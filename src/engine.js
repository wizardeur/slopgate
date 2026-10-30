// Core evaluation engine (v1.1, hardened).
//
// Design notes:
//  - hygiene and slop-marker checks run on ADDED lines only, so pre-existing
//    context text can never block a PR;
//  - findings carry new-file line numbers; multi-line rules scan joined
//    hunk blocks and the whole-file diff text;
//  - severity gating via minBlockSeverity: findings below the bar are
//    advisory and do not block;
//  - inline `slopgate-ignore` suppressions and config-driven rule/path
//    exclusion;
//  - lockfiles, minified bundles and vendored code are never scanned;
//  - lines are NFKC-normalized and zero-width/format characters stripped
//    before matching, so unicode tricks cannot hide a pattern; raw lines are
//    checked separately for hidden characters (SG-SEC-010);
//  - reachability considers hunk context too: a PR that touches code between
//    an existing public endpoint and an existing sink is reported as such.

const { parseDiff, isTestFile, GENERATED_FILE } = require('./parse');
const { classifyLayer } = require('./layers');
const { checkHygiene, findSlopMarkers } = require('./hygiene');
const { shields, ENTRYPOINT_PATTERN, SINK_PATTERN } = require('./shields');
const { SEVERITY_RANK, DEFAULTS } = require('./config');
const { runAnalyzers, collectChangedFiles } = require('./analyzers');
const { buildImportGraph, analyzeReachability } = require('./analyzers/import-graph');

const LINE_CAP = 1000; // chars per scanned line (bounds regex backtracking)
const BLOCK_CAP = 20000; // chars per scanned hunk/file block
const STRIP_FOR_MATCH = /[\u200B-\u200F\u2060-\u2064\uFEFF\u00AD]/g;
const INLINE_IGNORE = /(?:#|\/\/|\/\*|<!--)\s*slopgate-ignore\b/;

const TEST_DELETION_THRESHOLD = 25;

const WORKFLOW_PATH = /\.github\/workflows\//i;
/** The YAML keys this analysis acts on; everything else stays null. */
const NAMED_BLOCKS = new Set(['env', 'run', 'with']);
const YAML_KEY = /^(\s*)([A-Za-z0-9_.-]+)\s*:(?:\s|$)/;

function normalize(raw) {
  return raw.normalize('NFKC').replace(STRIP_FOR_MATCH, '').slice(0, LINE_CAP);
}

/**
 * YAML block context for a set of lines, keyed by new-file line number.
 *
 * A shield matcher receives one normalized line. For a workflow that is not
 * enough to tell a defect from its own remediation: `BODY: ${{ github.event.x }}`
 * under `env:` is the FIX for the injection that `run: echo "${{ github.event.x }}"`
 * is. Both are a single line; only the block they sit in separates them.
 *
 * So we carry the structure: for each line, which key owns it. The owner is the
 * nearest preceding line at LOWER indentation that has the shape `key:`. We then
 * report the FIRST segment of that key's path (the YAML walk down from the
 * document root), mapped to a named block when it is one we act on.
 *
 * Deliberately conservative:
 *  - only `env`, `run` and `with` are named; anything else is null, so a rule
 *    that switches on the value keeps its current behaviour everywhere else;
 *  - `run:` needs a value on the key's own line (an unfolded `run: >` /
 *    `run: |` block scalar opens with the indicator, which we do not follow);
 *  - quotes and comments are not stripped, because getting that wrong would
 *    make the answer confidently false instead of null;
 *  - any failure returns {} for the file, and callers read a missing entry as
 *    null. The context is additive: it must never change a rule that ignores it.
 *
 * @param {Array<{code: string, line: number|null}>} entries added lines
 * @returns {Map<number, ('env'|'run'|'with'|null)>}
 */
function yamlBlockMap(entries) {
  try {
    const stack = []; // [{ indent, key }] - open YAML keys, outermost first
    const byLine = new Map();
    for (const { code, line } of entries) {
      const text = normalize(code);
      const at = text.search(/\S/);
      if (at === -1) {
        byLine.set(line, currentBlock(stack));
        continue;
      }
      const indent = at;
      while (stack.length > 0 && stack[stack.length - 1].indent >= indent) stack.pop();
      // A NAMED KEY IS ITS OWN BLOCK. `run: echo "$BODY"` carries its value on the
      // key's own line, so it never has children to ask the stack about - asking
      // the stack BEFORE the push answered null for every single-line `run:`, which
      // is the shape a workflow uses most. `env:` and `with:` escaped this only
      // because their values always sit on following lines. (Measured: a map over
      // a 13-line step produced env and with but null for the `run:` line.)
      const key = text.match(YAML_KEY);
      const named = key && NAMED_BLOCKS.has(key[2]) ? key[2] : null;
      byLine.set(line, named || currentBlock(stack));
      if (key) stack.push({ indent, key: key[2] });
    }
    return byLine;
  } catch {
    return new Map();
  }
}

// The block a line belongs to: the outermost named key on its path.
// `    with:` nested under a step is `with`; the step's `name:` under `with:`
// is still `with`. `jobs:` at the root never shadows, because `jobs` is not named.
function currentBlock(stack) {
  for (const frame of stack) {
    if (frame.key === 'env') return 'env';
    if (frame.key === 'run') return 'run';
    if (frame.key === 'with') return 'with';
  }
  return null;
}

function evaluate(diffText, options = {}) {
  const config = options.config || { ...DEFAULTS, ignorePaths: [], source: null };
  const minRank = SEVERITY_RANK[config.minBlockSeverity] || SEVERITY_RANK.MEDIUM;
  const disabled = new Set(config.disable || []);

  const files = parseDiff(diffText);
  // Files exempt from scanning (lockfiles, vendored code, config-ignored) are
  // excluded from hygiene/marker text too: a 500KB minified vendor bundle
  // must not trip the control-character check.
  const isSkippedFile = (p) =>
    GENERATED_FILE.test(p) || (config.ignorePaths || []).some((rx) => rx && rx.test(p));
  // Inline-ignored lines are excluded from hygiene/marker scanning as well:
  // the comment means "do not scan this line", not merely "no shields".
  const addedTextJoined = files
    .filter((f) => !isSkippedFile(f.path))
    .flatMap((f) => f.addedLines)
    .filter((l) => !INLINE_IGNORE.test(l.slice(0, LINE_CAP)))
    .map((l) => l.slice(0, LINE_CAP))
    .join('\n');

  const hygieneIssues = checkHygiene(addedTextJoined);
  const slopMarkers = findSlopMarkers(addedTextJoined);

  const securityFindings = [];
  let suppressedCount = 0;

  let entrypointAdded = false;
  let sinkAdded = false;
  let entrypointInContext = false;
  let sinkInContext = false;
  let hasUnboundIdentity = false;

  const layerFiles = new Map();
  const ignoredLines = new Map(); // file -> Set(line): inline slopgate-ignore targets
  const addFileToLayer = (filePath) => {
    const layer = classifyLayer(filePath);
    if (!layerFiles.has(layer)) layerFiles.set(layer, new Set());
    layerFiles.get(layer).add(filePath);
  };

  let testDeletions = 0;
  let testAdditions = 0;

  const record = (shield, filePath, line, variant, approx = false) => {
    const key = `${shield.id}:${filePath}`;
    if (securityFindings.some((f) => f.ruleId === shield.id && f.file === filePath)) return;
    securityFindings.push({
      ruleId: shield.id,
      cwe: (variant && variant.cwe) || shield.cwe,
      severity: shield.severity,
      title: (variant && variant.title) || shield.title,
      file: filePath,
      line,
      ...(approx ? { approx } : {}),
      ...(variant && variant.variant ? { variant: variant.variant } : {}),
      remediation: shield.remediation,
    });
  };

  for (const file of files) {
    const testFile = isTestFile(file.path);
    addFileToLayer(file.path);

    if (testFile) {
      testDeletions += file.removedLines.length;
      testAdditions += file.addedLines.length;
    }

    // Generated/vendored/config-ignored files: counted in metrics, not scanned.
    const skipped = isSkippedFile(file.path);

    const ctx = { filePath: file.path, isTestFile: testFile, config };

    // Structural YAML context, workflow files only. For every other path it is
    // null and costs one regex test per file. Computed once per file; a missing
    // entry in the map reads as null, so a shield that wants the block gets a
    // definite answer rather than undefined.
    const blockOf = WORKFLOW_PATH.test(file.path)
      // THE MAP IS BUILT FROM THE HUNK'S CONTEXT AS WELL AS ITS ADDED LINES.
      // Added-only was the bug: a new key under an `env:` that the diff did not
      // touch is an orphan, and every such line read as "unknown block", which a
      // rule must treat as "fire as before" - so the rule kept firing on the very
      // shape it had just been taught to allow. Context lines carry the parent
      // keys and their indent, which is the entire question.
      ? yamlBlockMap(file.addedLines.length > 0
          ? file.hunks.length > 0
            ? file.hunks.flatMap((h) => [...(h.context || []), ...h.added])
                .sort((a, b) => (a.line ?? 0) - (b.line ?? 0))
            : file.addedLines.map((code) => ({ code, line: null }))
          : [])
      : null;
    const yamlBlockAt = (line) => (blockOf && blockOf.has(line) ? blockOf.get(line) : null);

    if (!skipped) {
      // ---- per-line pass (exact line numbers) ------------------------------
      // Headerless diffs (no @@ hunk) still get scanned: synthesize entries
      // without line numbers rather than passing them silently.
      const addedEntries =
        file.hunks.length > 0
          ? file.hunks.flatMap((h) => h.added)
          : file.addedLines.map((code) => ({ code, line: null }));
      for (const { code, line: newLine } of addedEntries) {
        const raw = code.slice(0, LINE_CAP);
        if (INLINE_IGNORE.test(raw)) {
          suppressedCount++;
          if (!ignoredLines.has(file.path)) ignoredLines.set(file.path, new Set());
          ignoredLines.get(file.path).add(newLine);
          continue;
        }
        const norm = normalize(raw);

        if (ENTRYPOINT_PATTERN.test(norm)) entrypointAdded = true;
        if (SINK_PATTERN.test(norm)) sinkAdded = true;
        if (
          /def\s+(?:get_|update_|delete_|create_|list_|process_|chat|upload|export)\w*\s*\(\s*(?:username|user_id|owner_id|account_id)\s*:\s*(?:str|int)\b(?!.*(?:Depends|current_user|auth|session|token))/i.test(
            norm
          )
        ) {
          hasUnboundIdentity = true;
        }

        for (const shield of shields) {
          if (disabled.has(shield.id)) continue;
          if (shield.appliesTo === 'non-test' && testFile) continue;
          const variant = shield.match(norm, { ...ctx, rawLine: raw, yamlBlock: yamlBlockAt(newLine) });
          if (variant) record(shield, file.path, newLine, variant);
        }
      }

      // ---- per-hunk block pass (multi-line statements) ---------------------
      // Inline-ignored lines are excluded from block text, otherwise the block
      // pass would resurrect findings the author suppressed per line.
      const blockSource = (entries) =>
        entries.filter((e) => !INLINE_IGNORE.test(e.code.slice(0, LINE_CAP))).map((e) => e.code);
      const blocks =
        file.hunks.length > 0
          ? file.hunks
              .map((h) => ({ newStart: h.newStart, lines: blockSource(h.added) }))
              .filter((h) => h.lines.length > 0)
          : [{ newStart: null, lines: blockSource(file.addedLines.map((code) => ({ code }))) }];
      for (const hunk of blocks) {
        const block = hunk.lines
          .join('\n')
          .normalize('NFKC')
          .replace(STRIP_FOR_MATCH, '')
          .slice(0, BLOCK_CAP);
        for (const shield of shields) {
          if (disabled.has(shield.id) || !shield.blockMatch || shield.appliesTo === 'non-test' && testFile) continue;
          const variant = shield.blockMatch(block, ctx);
          if (variant) record(shield, file.path, hunk.newStart, variant, true);
        }
      }

      // ---- whole-file pass (rules needing file-wide state, e.g. S9) --------
      const fileHunkText = file.hunks
        .map((h) => h.hunkText)
        .join('\n')
        .normalize('NFKC')
        .replace(STRIP_FOR_MATCH, '')
        .slice(0, BLOCK_CAP);
      for (const shield of shields) {
        if (disabled.has(shield.id) || !shield.fileMatch) continue;
        if (shield.appliesTo === 'non-test' && testFile) continue;
        const variant = shield.fileMatch(fileHunkText, ctx);
        if (variant) record(shield, file.path, file.hunks[0]?.newStart ?? null, variant, true);
      }

      // Context reachability flags (hunk text includes context lines).
      if (ENTRYPOINT_PATTERN.test(fileHunkText)) entrypointInContext = true;
      if (SINK_PATTERN.test(fileHunkText)) sinkInContext = true;
    }
  }

  // ---- analyzer modules (AST / external) -------------------------------------
  // Optional: when a file provider is available (action workspace, CLI in a
  // repo, tests passing files directly), analyzers inspect FULL changed-file
  // contents. Without one the gate stays regex-only and says so.
  const changedPaths = files.filter((f) => !GENERATED_FILE.test(f.path)).map((f) => f.path);
  let analyzerFindings = [];
  let analyzerRan = [];
  let filesAnalyzed = 0;
  let filesMissing = 0;
  if (options.readFile || options.files) {
    const collected = options.files
      ? { files: options.files, missing: options.filesMissing || 0 }
      : collectChangedFiles(changedPaths, options.readFile);
    filesAnalyzed = collected.files.length;
    filesMissing = collected.missing;
    // External analyzers are repo-wide checks and run even when no changed
    // file content is readable; the python-ast filter simply finds no .py.
    const res = runAnalyzers(collected.files, config);
    analyzerFindings = res.findings;
    analyzerRan = res.ran;
  }

  // Markers on pre-existing lines must suppress too: the AST passes read
  // whole changed files, so an ignore comment anywhere in a changed file,
  // not just on diff-added lines, has to register its line number.
  // (Surfaced by dogfood: touching import-graph.js flagged best-effort
  // catches that had been sitting quietly in the same file for versions.)
  const wholeSources = options.files?.length
    ? options.files
    : options.readFile
      ? files.filter((f) => !isSkippedFile(f.path)).map((f) => ({ path: f.path, content: options.readFile(f.path) }))
      : [];
  for (const src of wholeSources) {
    if (!src || !src.content || isSkippedFile(src.path)) continue;
    String(src.content)
      .split('\n')
      .forEach((l, i) => {
        if (INLINE_IGNORE.test(l.slice(0, LINE_CAP))) {
          if (!ignoredLines.has(src.path)) ignoredLines.set(src.path, new Set());
          ignoredLines.get(src.path).add(i + 1);
        }
      });
  }

  // Merge policy (documented in README):
  //  - AST findings are ADDED (union): they catch shapes the regexes miss;
  //  - on files the python-ast analyzer processed, regex `while-true`
  //    findings are dropped (AST break-analysis is authoritative);
  //  - regex `approx` findings are dropped when the AST has a precise one
  //    for the same rule+file.
  const astRanFiles = new Set(
    analyzerRan.filter((r) => r.available && r.analyzed).flatMap((r) => r.analyzed)
  );
  const astPairs = new Set(analyzerFindings.map((f) => `${f.ruleId}:${f.file}`));
  // ---- import graph: built early so its taint findings join the gate --------
  let graphObj = null;
  if ((options.readFile || options.files) && !((config.analyzers || {}).importGraph === false)) {
    try {
      graphObj = buildImportGraph(options.repoRoot || process.cwd(), config, {
        contentOverrides: options.files ? new Map(options.files.map((f) => [f.path, f.content])) : null,
      });
    } catch (err) {
      graphObj = { error: err.message };
    }
  }
  const graphFindings = (graphObj && graphObj.findings) || [];

  const mergedFindings = securityFindings.filter((f) => {
    if (!astRanFiles.has(f.file)) return true;
    if (f.ruleId === 'SG-SEC-012' && f.variant === 'while-true') return false;
    if (f.approx && astPairs.has(`${f.ruleId}:${f.file}`)) return false;
    return true;
  });
  // Inline ignores suppress findings at that line in EVERY layer - but the
  // marker sits on a line of the CHECKED-OUT FILE, and a finding can anchor
  // on a line the diff never shows. Field cases 2026-10-15/16: a tracker PR
  // whose diff is only the workflow file, with the sink marker at a PHP line
  // far from any hunk (suppression structurally dead for graph findings);
  // and whole-file AST findings on pre-existing lines of changed files, where
  // the patch text never contains the marker line. For every finding's file,
  // read the whole file and collect its markers, so lineIgnored below sees
  // what the author actually wrote. Diff-file markers were already collected
  // above; re-scanning those files whole is idempotent.
  const markerScanFiles = new Set();
  for (const f of [...mergedFindings, ...analyzerFindings, ...graphFindings]) {
    if (f.line != null && !ignoredLines.has(f.file)) markerScanFiles.add(f.file);
  }
  if (options.readFile) {
    for (const mf of markerScanFiles) {
      const markerContent = options.readFile(mf);
      if (!markerContent) continue;
      String(markerContent)
        .split('\n')
        .forEach((l, i) => {
          if (INLINE_IGNORE.test(l.slice(0, LINE_CAP))) {
            if (!ignoredLines.has(mf)) ignoredLines.set(mf, new Set());
            ignoredLines.get(mf).add(i + 1);
          }
        });
    }
  }

  // Inline ignores suppress AST/graph findings at that line too: the comment
  // means "do not report here", whatever layer is looking.
  const lineIgnored = (f) => f.line != null && (ignoredLines.get(f.file)?.has(f.line) || false);
  // Dedupe identical rule+file+line hits across layers (regex first, then AST
  // analyzers, then graph findings) so a catch both layers see reports once.
  const seenFindingKeys = new Set();
  const allFindings = mergedFindings
    .concat(analyzerFindings)
    .concat(graphFindings)
    .filter((f) => {
      if (f.via && lineIgnored(f)) return false;
      const k = `${f.ruleId}:${f.file}:${f.line ?? ''}`;
      if (seenFindingKeys.has(k)) return false;
      seenFindingKeys.add(k);
      return true;
    });

  const hasTestDeletions = testDeletions > TEST_DELETION_THRESHOLD && testAdditions === 0;
  const hasSlopMarkers = slopMarkers.length > 0;
  const hasHygieneDefect = hygieneIssues.length > 0;

  // ---- severity gating: blocking vs advisory --------------------------------
  const withAdvisoryFlag = allFindings.map((f) => ({
    ...f,
    advisory: SEVERITY_RANK[f.severity] < minRank,
  }));
  const blockingFindings = withAdvisoryFlag.filter((f) => !f.advisory);
  const hasSecurityDefect = blockingFindings.length > 0;

  // ---- import-graph reachability (chains from the pre-built graph) ----------
  // Real chains (entrypoint -> changed file -> sink) replace the path-name
  // heuristic when the graph applies; any failure degrades to the heuristic.
  let realReach = { available: false, applicable: false, chains: [], stats: null };
  if (graphObj && !graphObj.error) {
    const res = analyzeReachability(graphObj, changedPaths, blockingFindings);
    realReach = { available: true, applicable: res.applicable, chains: res.chains, stats: graphObj.stats };
  } else if (graphObj && graphObj.error) {
    realReach.error = graphObj.error;
  }

  // ---- Blast radius ----------------------------------------------------------
  const impactedLayers = [];
  let totalFilesChanged = 0;
  for (const [layer, filesSet] of layerFiles.entries()) {
    const fileArr = Array.from(filesSet);
    totalFilesChanged += fileArr.length;
    const layerFindings = blockingFindings.filter((f) => filesSet.has(f.file));
    const hasCrit = layerFindings.some((f) => f.severity === 'CRITICAL' || f.severity === 'HIGH');
    impactedLayers.push({
      layer,
      files: fileArr,
      riskLevel: hasCrit ? 'CRITICAL' : layerFindings.length > 0 ? 'ELEVATED' : 'CLEAN',
    });
  }

  const entrypointPresent = entrypointAdded || entrypointInContext;
  const sinkPresent = sinkAdded || sinkInContext;
  const chainFound = realReach.applicable && realReach.chains.length > 0;
  const crossLayerReachability = chainFound || (entrypointPresent && sinkPresent && hasSecurityDefect);
  const reachabilityMethod = chainFound ? 'import-graph' : 'heuristic';

  let reachabilitySummary = 'No cross-layer exploit chain detected.';
  if (hasSecurityDefect) {
    if (chainFound) {
      const c = realReach.chains[0];
      const more = realReach.chains.length > 1 ? ` (+${realReach.chains.length - 1} more chained file(s))` : '';
      if (c.symbolPath) {
        reachabilitySummary =
          `CRITICAL REACHABILITY (call graph): ${c.symbolPath.join(' -> ')} ` +
          `-> sink ${c.sink}${more}.`;
      } else {
        reachabilitySummary =
          `CRITICAL REACHABILITY (import graph): ${c.entrypoint} (entrypoint) -> ` +
          `${c.file} (${c.findings.join(', ')}) -> ${c.sink} (sink, ` +
          `${c.entrypointHops}+${c.sinkHops} hops)${more}.`;
      }
    } else if (crossLayerReachability) {
      const idorPart = hasUnboundIdentity ? 'Unbound Caller Identity (IDOR) -> ' : '';
      const provenance =
        entrypointAdded && sinkAdded
          ? ''
          : entrypointAdded
          ? ' (sink is pre-existing code reached by the diff)'
          : sinkAdded
          ? ' (endpoint is pre-existing code reached by the diff)'
          : ' (both endpoint and sink are pre-existing code touched by the diff)';
      reachabilitySummary =
        `CRITICAL REACHABILITY: Public API Entrypoint -> ${idorPart}Persistence / Vector Sink ` +
        `(${blockingFindings.length} blocking CWE finding${blockingFindings.length === 1 ? '' : 's'} across ` +
        `${impactedLayers.length} architectural layer${impactedLayers.length === 1 ? '' : 's'})${provenance}.`;
    } else {
      const graphNote =
        realReach.applicable && realReach.available
          ? ' (import graph verified: no entrypoint-to-finding-to-sink chain)'
          : '';
      reachabilitySummary =
        `Exploit surface confined to ${impactedLayers.length} layer(s) ` +
        `(${blockingFindings.map((f) => f.cwe).join(', ')}). Immediate remediation required before merge.${graphNote}`;
    }
  }

  const blastRadius = {
    totalFilesChanged,
    impactedLayers,
    crossLayerReachability,
    reachabilityMethod,
    ...(realReach.chains.length > 0 ? { chains: realReach.chains } : {}),
    reachabilitySummary,
  };

  // ---- Score (blocking defect classes only, same ladder as before) -----------
  const hasCritical = blockingFindings.some((f) => f.severity === 'CRITICAL');
  const isGreen = !hasSlopMarkers && !hasTestDeletions && !hasHygieneDefect && !hasSecurityDefect;
  let slopScore = 0;
  if (!isGreen) {
    if (hasSecurityDefect) slopScore = hasCritical ? 90 : 70;
    else if (hasSlopMarkers) slopScore = 85;
    else if (hasTestDeletions) slopScore = 75;
    else if (hasHygieneDefect) slopScore = 40;
  }

  // Computed diff-reduction share (removals over the changed total).
  const totalAdded = files.reduce((n, f) => n + f.addedLines.length, 0);
  const totalRemoved = files.reduce((n, f) => n + f.removedLines.length, 0);
  const linesReduced =
    totalAdded + totalRemoved === 0 ? '0%' : `${Math.round((100 * totalRemoved) / (totalAdded + totalRemoved))}%`;

  const rulesTriggered = new Set(blockingFindings.map((f) => f.ruleId)).size;
  const invariantsVerified = `${Math.round(((shields.length - rulesTriggered) / shields.length) * 100)}%`;

  const analyzersAvailable = analyzerRan.filter((r) => r.available).map((r) => r.id);
  const analysis = {
    depth: analyzersAvailable.length > 0 ? `regex+${analyzersAvailable.join('+')}` : 'regex',
    ran: analyzerRan,
    filesAnalyzed,
    filesMissing,
    importGraph: realReach.available
      ? { method: reachabilityMethod, applicable: realReach.applicable, chains: realReach.chains.length, stats: realReach.stats }
      : { method: 'unavailable' },
  };

  let message;
  if (isGreen) {
    message = 'Gate passed: no hygiene issues, no security findings, no test regressions.';
  } else if (hasSecurityDefect) {
    message =
      `Security & reachability violations (${blockingFindings.map((f) => f.cwe).join(', ')}): ` +
      `${blockingFindings[0].title} in ${blockingFindings[0].file}` +
      (blockingFindings[0].line ? `:${blockingFindings[0].line}` : '') +
      '.';
  } else if (hasSlopMarkers) {
    message = `Explicit do-not-merge slop markers detected: ${slopMarkers.join(', ')}`;
  } else if (hasTestDeletions) {
    message = `Mass test deletions detected (${testDeletions} deleted test lines, 0 replacements).`;
  } else {
    message = `Markdown/Text hygiene defects detected: ${hygieneIssues.join('; ')}`;
  }

  return {
    isGreen,
    slopScore,
    engineeringScore: 100 - slopScore,
    linesReduced,
    invariantsVerified,
    hygieneIssues,
    slopMarkers,
    testDeletions,
    testAdditions,
    hasTestDeletions,
    securityFindings: withAdvisoryFlag,
    blockingFindings,
    suppressedCount,
    configSource: config.source || null,
    minBlockSeverity: config.minBlockSeverity || 'MEDIUM',
    analysis,
    blastRadius,
    diffStats: { filesChanged: files.length, addedLines: totalAdded, removedLines: totalRemoved },
    message,
  };
}

// Test-facing entry point for the structural context: same cheap path as the
// engine (null for non-workflow paths, {} on any failure), so a unit check
// exercises the code the gate actually runs rather than a copy of it.
function yamlBlockFor(filePath, entries) {
  const rows = entries || [];
  // NON-WORKFLOW PATHS ARE ALL-NULL, ONE ENTRY PER LINE. `new Map([[null, null]])`
  // was an empty answer wearing a shape: a caller reading .get(line) for any line
  // got undefined, not null, and "the block is unknown" has to read the same way
  // everywhere or a rule switching on it sees three states instead of two.
  if (!WORKFLOW_PATH.test(String(filePath))) {
    return new Map(rows.map((e, i) => [e?.line ?? i + 1, null]));
  }
  const map = yamlBlockMap(rows);
  // A bad input returns an empty map; normalise that to "every line unknown" too.
  if (map.size === 0) return new Map(rows.map((e, i) => [e?.line ?? i + 1, null]));
  return map;
}

module.exports = { evaluate, yamlBlockFor };
