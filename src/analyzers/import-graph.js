// Import-graph module: builds a repo-wide local import graph and uses it
// for real reachability ("this changed file is imported by an entrypoint
// and transitively imports a persistence sink", not path-name heuristics).
// Falls back gracefully: unavailable, empty or foreign-repo graphs leave
// the heuristic in charge; the verdict reports the analysis depth either way.
//
// Sources: .py via stdlib-AST (py-imports.js), .js/.ts/.jsx/.tsx/.mjs/.cjs via
// a local-only import/require scanner, .php via
// require/include path literals (__DIR__, plugin_dir_path(__FILE__)) plus
// composer.json psr-4 `use` resolution. Entry/sink roles per language.
const fs = require('fs');
const path = require('path');
const { extractPythonImports } = require('./py-imports');
const { GENERATED_FILE } = require('../parse');
const { ENTRYPOINT_PATTERN, SINK_PATTERN } = require('../shields');
const { available: jsAstAvailable, loadParser: jsLoadParser, extractJsSymbols, extractJsModule, parse: jsParse } = require('./js-ast');

const MAX_FILES = 2000;
const PY_EXT = /\.py$/i;
const JS_EXT = /\.(m?js|cjs|[jt]sx?)$/i;
const PHP_EXT = /\.php$/i;

const PY_ENTRYPOINT =
  /@\b(?:app|router)\.(?:get|post|put|delete|patch)\b|@\b(?:get|post|put|delete|patch)\s*\(|@\bapp\.route\b|if\s+__name__\s*==\s*['"]__main__['"]|\buvicorn\.run\(|\bgunicorn\b/i;
const JS_ENTRYPOINT =
  /\bapp\.listen\s*\(|\bcreateServer\s*\(|\bregisterBlockType\s*\(|\bregisterPlugin\s*\(|export\s+async\s+function\s+(?:GET|POST|PUT|DELETE|PATCH)\b/i;

function listSourceFiles(repoRoot, config) {
  const out = [];
  let truncated = false;
  const walk = (dir, depth) => {
    if (depth > 12 || out.length >= MAX_FILES) return;
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      if (out.length >= MAX_FILES) {
        truncated = true;
        break;
      }
      const rel = path.relative(repoRoot, path.join(dir, e.name));
      if (e.isDirectory()) {
        if (/^(node_modules|\.git|\.venv|venv|__pycache__|dist|build|vendor|third_party)$/i.test(e.name)) continue;
        walk(path.join(dir, e.name), depth + 1);
      } else if (e.isFile()) {
        if (GENERATED_FILE.test(rel)) continue;
        if ((config.ignorePaths || []).some((rx) => rx.test(rel))) continue;
        if (PY_EXT.test(rel) || JS_EXT.test(rel) || PHP_EXT.test(rel)) out.push(rel);
      }
    }
  };
  walk(repoRoot, 0);
  return { files: out, truncated: out.length >= MAX_FILES };
}

// Resolve a JS import specifier relative to the importing file. Returns the
// existing local file, or null.
function resolveJsSpec(repoRoot, fromRel, spec) {
  if (!spec || !spec.startsWith('.')) return null; // external / alias: not a local edge
  const base = path.resolve(path.dirname(path.join(repoRoot, fromRel)), spec);
  const candidates = [
    base,
    `${base}.js`,
    `${base}.ts`,
    `${base}.jsx`,
    `${base}.tsx`,
    `${base}.mjs`,
    `${base}.cjs`,
    path.join(base, 'index.js'),
    path.join(base, 'index.ts'),
  ];
  for (const c of candidates) {
    try {
      if (fs.statSync(c).isFile()) return path.relative(repoRoot, c);
    } catch { // slopgate-ignore: optional candidate extension
      /* best-effort: candidate extension doesn't exist, try the next one */
    }
  }
  return null;
}

function scanJsImports(repoRoot, rel) {
  let content;
  try {
    content = fs.readFileSync(path.join(repoRoot, rel), 'utf-8');
  } catch {
    return [];
  }
  const specs = [];
  const push = (s) => {
    if (s) specs.push(s);
  };
  content.replace(/import\s+(?:[\s\S]*?\s+from\s+)?['"]([^'"\n]+)['"]/g, (_, s) => {
    push(s);
    return _;
  });
  content.replace(/require\s*\(\s*['"]([^'"\n]+)['"]\s*\)/g, (_, s) => {
    push(s);
    return _;
  });
  content.replace(/import\s*\(\s*['"]([^'"\n]+)['"]\s*\)/g, (_, s) => {
    push(s);
    return _;
  });

  const resolved = new Set();
  for (const spec of specs) {
    const r = resolveJsSpec(repoRoot, rel, spec);
    if (r) resolved.add(r);
  }
  return Array.from(resolved);
}

// PHP: require/include with path literals (__DIR__, plugin_dir_path(__FILE__)),
// plus psr-4 `use` statements resolved through composer.json autoload maps.
// Unresolvable bases (get_template_directory(), variables) are skipped, never guessed.
function loadPsr4Map(repoRoot) {
  try {
    const composer = JSON.parse(fs.readFileSync(path.join(repoRoot, 'composer.json'), 'utf-8'));
    return Object.entries(composer.autoload?.['psr-4'] || {}).map(([prefix, dir]) => ({
      prefix: prefix.replace(/\\+$/, ''),
      dir: String(dir).replace(/\/+$/, ''),
    }));
  } catch {
    return [];
  }
}

const PHP_SKIP_BASE = /get_template_directory|get_stylesheet_directory|WP_PLUGIN_DIR|WP_CONTENT_DIR|\\\$_/i;

function scanPhpImports(repoRoot, rel, psr4) {
  let content;
  try {
    content = fs.readFileSync(path.join(repoRoot, rel), 'utf-8');
  } catch {
    return [];
  }
  const edges = new Set();
  const baseDir = path.dirname(path.join(repoRoot, rel));

  for (const m of content.matchAll(/(?:require|include)(?:_once)?\b[^;\n]*;/g)) {
    const expr = m[0];
    if (PHP_SKIP_BASE.test(expr)) continue;
    const segs = Array.from(expr.matchAll(/'([^']*)'/g)).map((s) => s[1]);
    if (segs.length === 0) continue;
    const joined = segs.join('');
    if (!/\.php$/i.test(joined) || path.isAbsolute(joined)) continue;
    const cleaned = joined.replace(/^\.\//, '');
    for (const candidate of [path.resolve(baseDir, cleaned), path.resolve(repoRoot, cleaned)]) {
      try {
        if (fs.statSync(candidate).isFile()) {
          edges.add(path.relative(repoRoot, candidate));
          break;
        }
      } catch { // slopgate-ignore: optional include path
        /* best-effort: candidate path doesn't exist, try the next one */
      }
    }
  }

  for (const m of content.matchAll(/(?:^|\n)\s*use\s+(?:\\)?([A-Za-z0-9_\\]+)\s*;/g)) {
    const fqcn = m[1];
    const match = psr4
      .filter((p) => p.prefix === '' || fqcn === p.prefix || fqcn.startsWith(p.prefix + '\\'))
      .sort((a, b) => b.prefix.length - a.prefix.length)[0];
    if (!match) continue;
    const remainder = match.prefix === '' ? fqcn : fqcn.slice(match.prefix.length + 1);
    const relPath = `${match.dir}/${remainder.replace(/\\/g, '/')}.php`;
    try {
      if (fs.statSync(path.join(repoRoot, relPath)).isFile()) edges.add(relPath);
    } catch { // slopgate-ignore: optional psr-4 resolution
      /* best-effort: psr-4 mapping didn't resolve to an existing file */
    }
  }

  return Array.from(edges);
}

const PHP_ENTRYPOINT = /(?:Plugin|Theme) Name:\s*\S/i;

// PHP symbols via regex spans (no zero-dep parser exists): functions/methods
// with brace-counted line ranges, typed call edges within the span, class
// property types, and add_action/add_filter callback registrations as
// entrypoint symbols (WordPress's route concept: both `[ $this, 'x' ]` and
// the array( $this, 'x' ) long syntax WP coding style mandates). Best-effort
// by design; documented.
const PHP_RESERVED = new Set([
  'if', 'foreach', 'for', 'while', 'switch', 'function', 'return', 'array', 'isset',
  'empty', 'unset', 'echo', 'print', 'die', 'exit', 'list', 'match', 'declare',
  'require', 'require_once', 'include', 'include_once',
]);

// Hook callback targets: [ $this, 'method' ], array( $this, 'method' ),
// or a plain 'function_name' string.
const PHP_HOOK =
  /add_(?:action|filter)\s*\([^,]+,\s*(?:(?:\[|array\s*\()\s*\$this\s*,\s*'(\w+)'\s*(?:\]|\))|'(\w+)')/i;

const PHP_TAINT_SINK_CWE = {
  query: 'CWE-89', get_row: 'CWE-89', get_results: 'CWE-89', get_var: 'CWE-89',
  insert: 'CWE-89', update: 'CWE-89', delete: 'CWE-89', replace: 'CWE-89',
  mysqli_query: 'CWE-89', pg_query: 'CWE-89',
  shell_exec: 'CWE-78', exec: 'CWE-78', system: 'CWE-78', passthru: 'CWE-78',
  proc_open: 'CWE-78', popen: 'CWE-78', eval: 'CWE-94', assert: 'CWE-94',
  unserialize: 'CWE-502', curl_exec: 'CWE-918',
  // v1.8: file-handling / LFI sinks (CWE-699 File Handling + Data Neutralization)
  include: 'CWE-98', include_once: 'CWE-98', require: 'CWE-98', require_once: 'CWE-98',
  file_get_contents: 'CWE-22', readfile: 'CWE-22', fopen: 'CWE-22', unlink: 'CWE-22',
  move_uploaded_file: 'CWE-434',
};

function phpSinkCwe(line) {
  const m =
    /\$wpdb\s*->\s*(\w+)|\b(mysqli_query|pg_query|shell_exec|exec|system|passthru|proc_open|popen|eval|assert|unserialize|curl_exec|file_get_contents|readfile|fopen|unlink|move_uploaded_file)\s*\(|\b(include|include_once|require|require_once)\b\(?\s*\$/i.exec(
      line
    );
  if (!m) return null;
  const sink = (m[1] || m[2] || m[3]).toLowerCase();
  if (sink === 'prepare') return null;
  return PHP_TAINT_SINK_CWE[sink] || 'CWE-20';
}

// Returns { functions, taintFindings, meta }: meta carries namespace, use
// aliases and class property types for cross-file symbol resolution.
function extractPhpSymbols(content) {
  const lines = content.split('\n');
  const out = [];
  const hookTargets = new Set();
  let className = null;
  let namespace = '';
  const uses = {};
  const classProps = {};

  // Hooks and file metadata first, over every line: hooks typically live
  // INSIDE a method's span, which the span-skipping scan below never revisits.
  for (const line of lines) {
    const hm = PHP_HOOK.exec(line);
    if (hm) hookTargets.add(hm[1] || hm[2]);
    const nm = /^\s*namespace\s+([\w\\]+)\s*;/.exec(line);
    if (nm) namespace = nm[1];
    const um = /^\s*use\s+\\?([\w\\]+)\s*(?:as\s+(\w+)\s*)?;/.exec(line);
    if (um) uses[um[2] || um[1].split('\\').pop()] = um[1];
  }

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const cm = /(?:^|\s)(?:abstract\s+|final\s+)?class\s+(\w+)/.exec(line);
    if (cm) className = cm[1];

    // Typed property declarations (visibility + type + $name + ;). Promoted
    // constructor parameters are handled separately below: they end the
    // parameter list, not with a semicolon.
    const pm = /(?:^|\s)(?:public|private|protected)\s+(?:static\s+)?(?:readonly\s+)?\??([\w\\]+)\s+\$(\w+)\s*;/.exec(line);
    if (pm && className) {
      classProps[className] = classProps[className] || {};
      classProps[className][pm[2]] = pm[1];
    }

    const fm = /(?:^|\s)((?:public|private|protected|static|final|abstract)\s+)*function\s+&?(\w+)\s*\(([^{]*)/.exec(line);
    if (!fm || /^\s*(?:require|include)/.test(line)) continue;
    const name = fm[2];

    // Promoted constructor properties: __construct( private Type $name, ... ).
    if (name === '__construct' && className) {
      for (const m of (fm[3] || '').matchAll(/(?:public|private|protected)\s+(?:readonly\s+)?\??([\w\\]+)\s+\$(\w+)/g)) {
        classProps[className] = classProps[className] || {};
        classProps[className][m[2]] = m[1];
      }
    }

    // Brace-counted span from the declaration line.
    let depth = 0;
    let started = false;
    let end = i;
    for (let j = i; j < lines.length; j++) {
      for (const ch of lines[j]) {
        if (ch === '{') {
          depth++;
          started = true;
        } else if (ch === '}') {
          depth--;
        }
      }
      if (started && depth <= 0) {
        end = j;
        break;
      }
    }

    const bodyText = lines.slice(i, end + 1).join('\n');
    const calls = [];
    for (const m of bodyText.matchAll(/\$this->(\w+)\s*\(/g)) calls.push({ k: 'this', m: m[1] });
    for (const m of bodyText.matchAll(/\$this->(\w+)->(\w+)\s*\(/g)) calls.push({ k: 'prop', p: m[1], m: m[2] });
    for (const m of bodyText.matchAll(/\$(\w+)\s*=\s*new\s+([\w\\]+)\s*[;(]/g)) calls.push({ k: 'new', v: m[1], c: m[2] });
    for (const m of bodyText.matchAll(/\$(\w+)->(\w+)\s*\(/g)) {
      if (m[1] !== 'this') calls.push({ k: 'var', v: m[1], m: m[2] });
    }
    for (const m of bodyText.matchAll(/\b([A-Z]\w+)::(\w+)\s*\(/g)) calls.push({ k: 'static', c: m[1], m: m[2] });
    for (const m of bodyText.matchAll(/(?<![\w>$\\])([a-z_]\w+)\s*\(/g)) {
      if (!PHP_RESERVED.has(m[1]) && m[1] !== name) calls.push({ k: 'fn', n: m[1] });
    }

    const varTypes = {};
    for (const m of bodyText.matchAll(/\$(\w+)\s*=\s*new\s+([\w\\]+)\s*[;(]/g)) varTypes[m[1]] = m[2];

    out.push({
      name,
      class: className,
      line: i + 1,
      end: end + 1,
      route: hookTargets.has(name),
      calls,
      varTypes,
    });
    i = end; // continue after the span (methods are siblings, not nested)
  }

  // ---- SG-TAINT-002: superglobal into a sink within one method ------------
  // One hop, span-local: `$x = $_GET[...]` then a sink line mentioning $x,
  // or a superglobal directly inside the sink call.
  const taintFindings = [];
  const taintScan = (entries, out) => {
    const tainted = new Set();
    for (const { n, text } of entries) {
      if (/\$(\w+)\s*=\s*[^;\n]*\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES)\b/.test(text)) {
        tainted.add(text.match(/\$(\w+)\s*=\s*[^;\n]*\$_/)[1]);
      }
      const cwe = phpSinkCwe(text);
      if (!cwe) continue;
      const direct = /\$_(?:GET|POST|REQUEST|COOKIE|FILES)\b/.test(text);
      const viaVar = Array.from(tainted).some((t) => new RegExp('\\$' + t + '\\b').test(text));
      if (direct || viaVar) {
        out.push({
          ruleId: 'SG-TAINT-002',
          cwe,
          severity: 'CRITICAL',
          title: 'PHP Superglobal Reaches Dangerous Sink (one hop)',
          line: n,
          remediation:
            'Sanitize and validate superglobal input (sanitize_key, absint, allowlists) before it reaches sinks; use parameterized queries.',
        });
      }
    }
  };
  for (const fn of out) {
    const entries = [];
    for (let j = fn.line - 1; j < fn.end; j++) entries.push({ n: j + 1, text: lines[j] });
    taintScan(entries, taintFindings);
  }

  // File-scope pass: WordPress plugins wire hooks and guard includes at
  // top level, where no function span exists: scan only the uncovered lines
  // so span findings never double-report.
  const inSpan = (n) => out.some((fn) => n >= fn.line && n <= fn.end);
  taintScan(
    lines.map((text, i) => ({ n: i + 1, text })).filter((e) => !inSpan(e.n)),
    taintFindings
  );

  return { functions: out, taintFindings, meta: { namespace, uses, classProps } };
}

function detectRole(rel, content) {
  const isPy = PY_EXT.test(rel);
  const entrypoint = isPy
    ? PY_ENTRYPOINT.test(content)
    : PHP_EXT.test(rel)
    ? PHP_ENTRYPOINT.test(content)
    : JS_ENTRYPOINT.test(content);
  const sink = SINK_PATTERN.test(content);
  return { entrypoint, sink };
}

// Returns { nodes, edges, reverse, entrypoints, sinks, symbols, findings, stats }
// or null if nothing usable. contentOverrides (path -> content) lets changed
// files be analyzed in their post-PR state when the checkout is not merged yet.
function buildImportGraph(repoRoot, config, options = {}) {
  const contentOverrides = options.contentOverrides || null;
  const { files, truncated } = listSourceFiles(repoRoot, config);
  const nodes = new Set(files);
  if (files.length === 0) return null;

  const edges = new Map(files.map((f) => [f, []]));

  const pyFiles = files.filter((f) => PY_EXT.test(f));
  let pyEdges = null;
  if (pyFiles.length > 0) {
    pyEdges = extractPythonImports(repoRoot, pyFiles);
    if (pyEdges) {
      for (const [from, data] of Object.entries(pyEdges)) {
        if (!edges.has(from)) continue;
        edges.set(
          from,
          (data.imports || []).filter((t) => nodes.has(t))
        );
      }
    }
  }
  for (const rel of files.filter((f) => JS_EXT.test(f))) {
    edges.set(
      rel,
      scanJsImports(repoRoot, rel).filter((t) => nodes.has(t))
    );
  }
  const phpTaint = [];
  const psr4 = loadPsr4Map(repoRoot);
  for (const rel of files.filter((f) => PHP_EXT.test(f))) {
    edges.set(
      rel,
      scanPhpImports(repoRoot, rel, psr4).filter((t) => nodes.has(t))
    );
  }

  const entrypoints = new Set();
  const sinks = new Set();
  const configEntrypoints = (config.analyzers && config.analyzers.entrypoints) || [];
  const contents = new Map(); // rel -> content, shared by role detection and symbol extraction
  const contentOf = (rel) => {
    if (contentOverrides && contentOverrides.has(rel)) return contentOverrides.get(rel);
    if (contents.has(rel)) return contents.get(rel);
    try {
      const c = fs.readFileSync(path.join(repoRoot, rel), 'utf-8');
      contents.set(rel, c);
      return c;
    } catch {
      return null;
    }
  };
  for (const rel of files) {
    const content = contentOf(rel);
    if (content == null) continue;
    const role = detectRole(rel, content);
    if (role.entrypoint) entrypoints.add(rel);
    if (role.sink) sinks.add(rel);
    if (configEntrypoints.some((rx) => rx.test(rel))) entrypoints.add(rel);
  }

  const reverse = new Map(files.map((f) => [f, []]));
  for (const [from, tos] of edges) {
    for (const to of tos) {
      if (!reverse.has(to)) reverse.set(to, []);
      reverse.get(to).push(from);
    }
  }

  // Symbol layer: python functions (AST) + php methods (regex spans, WP hook
  // entrypoints) + js/ts functions (babel AST when the parser is vendored or
  // present), merged into one index so chains work across all of them.
  const fileData = new Map();
  if (pyEdges) {
    for (const [file, data] of Object.entries(pyEdges)) {
      if (nodes.has(file)) fileData.set(file, data);
    }
  }
  for (const rel of files.filter((f) => PHP_EXT.test(f))) {
    const content = contentOf(rel);
    if (!content) continue;
    const r = extractPhpSymbols(content);
    if (r.functions.length > 0) {
      fileData.set(rel, {
        imports: [],
        namedImports: {},
        moduleImports: {},
        functions: r.functions,
        php: r.meta,
      });
    }
    for (const t of r.taintFindings) {
      phpTaint.push({ ...t, file: rel, via: 'ast' });
    }
  }
  const jsAstReady = jsAstAvailable(repoRoot);
  if (jsAstReady) {
    for (const rel of files.filter((f) => JS_EXT.test(f))) {
      const content = contentOf(rel);
      if (!content) continue;
      try {
        const ast = jsParse(content);
        const functions = extractJsSymbols(ast);
        if (functions.length === 0) continue;
        const importNames = {};
        const importsResolved = [];
        for (const imp of extractJsModule(ast)) {
          const target = resolveJsSpec(repoRoot, rel, imp.source);
          if (!target || !nodes.has(target)) continue;
          importsResolved.push(target);
          for (const n of imp.names) importNames[n] = target;
        }
        fileData.set(rel, {
          imports: importsResolved,
          namedImports: importNames,
          moduleImports: {},
          functions,
          js: { importNames },
        });
      } catch { // slopgate-ignore: regex scanner still provides edges
        // unparseable per the AST: SG-AST-002 (changed files) reports it;
        // the regex import scanner still provides edges below.
      }
    }
  }
  const symbols = buildSymbolLayer(fileData, nodes, psr4);

  return {
    nodes,
    edges,
    reverse,
    entrypoints,
    sinks,
    symbols,
    findings: phpTaint,
    stats: { files: files.length, truncated, entrypoints: entrypoints.size, sinks: sinks.size },
  };
}

// ---- symbol layer ----------------------------------------------------------

function shortName(qualified) {
  const i = qualified.lastIndexOf('.');
  return i === -1 ? qualified : qualified.slice(i + 1);
}

function buildSymbolLayer(fileData, nodes, psr4) {
  if (!fileData || fileData.size === 0) return null;
  const index = new Map(); // `file::name` -> fn
  const byFile = new Map();

  for (const [file, data] of fileData) {
    if (!nodes.has(file)) continue;
    const fns = (data.functions || []).map((fn) => ({ ...fn, file }));
    byFile.set(file, fns);
    for (const fn of fns) index.set(`${file}::${fn.name}`, fn);
  }

  const resolve = (callerFile, call, callerName) => {
    const data = fileData.get(callerFile);
    const named = data?.namedImports?.[call];
    if (named && index.has(`${named}::${call}`)) return `${named}::${call}`;
    if (call.includes('.')) {
      const last = call.split('.').pop();
      const dotted = call.slice(0, call.lastIndexOf('.'));
      const modFile = data?.moduleImports?.[dotted];
      if (modFile && index.has(`${modFile}::${last}`)) return `${modFile}::${last}`;
    }
    // Same-file fallback by short name; exclude the caller itself (a direct
    // self-reference would be recursion, not a call edge worth charting).
    const local = (byFile.get(callerFile) || []).find((f) => shortName(f.name) === call && f.name !== callerName);
    return local ? `${callerFile}::${local.name}` : null;
  };

  const symEdges = new Map(Array.from(index.keys()).map((k) => [k, []]));
  for (const [key, fn] of index) {
    for (const call of fn.calls || []) {
      // Python calls are plain strings; PHP calls are {k, ...} objects.
      if (typeof call === 'string') {
        const target = resolve(fn.file, call, fn.name);
        if (target && target !== key && symEdges.has(target)) symEdges.get(key).push(target);
      }
    }
  }

  // ---- Typed-receiver pass: php (psr-4 classes) and js (import bindings) ----
  for (const [file, data] of fileData) {
    if (!data.php && !data.js) continue;
    const typeToFile = (typeName) => {
      if (!typeName) return null;
      if (data.js) return data.js.importNames[typeName] || null; // binding -> file
      const t = typeName.replace(/^\\/, '');
      const candidates = new Set();
      if (data.php.uses[t]) candidates.add(data.php.uses[t]);
      if (data.php.namespace) candidates.add(data.php.namespace + '\\' + t);
      for (const p of psr4) {
        if (p.prefix && !t.includes('\\')) candidates.add(p.prefix + '\\' + t);
      }
      candidates.add(t);
      for (const fq of candidates) {
        for (const p of psr4) {
          if (p.prefix && (fq === p.prefix || fq.startsWith(p.prefix + '\\'))) {
            const rel = `${p.dir}/${fq.slice(p.prefix.length + 1).replace(/\\/g, '/')}.php`.replace(/^\.\//, '');
            if (nodes.has(rel)) return rel;
          }
        }
      }
      return null;
    };

    for (const fn of byFile.get(file) || []) {
      const callerKey = `${file}::${fn.name}`;
      if (!symEdges.has(callerKey)) continue;
      for (const c of fn.calls || []) {
        if (typeof c === 'string') continue;
        let target = null;
        if (c.k === 'this') {
          const local = (byFile.get(file) || []).find((f) => shortName(f.name) === c.m && f.name !== fn.name);
          target = local ? `${file}::${local.name}` : null;
        } else if (c.k === 'fn') {
          const local = (byFile.get(file) || []).find((f) => shortName(f.name) === c.n && f.name !== fn.name);
          target = local ? `${file}::${local.name}` : null;
        } else if (c.k === 'prop') {
          const type = data.php.classProps?.[fn.class]?.[c.p];
          const tFile = typeToFile(type);
          if (tFile && index.has(`${tFile}::${c.m}`)) target = `${tFile}::${c.m}`;
        } else if (c.k === 'var' || c.k === 'new') {
          const type = c.k === 'new' ? c.c : fn.varTypes?.[c.v];
          const tFile = typeToFile(type);
          const m = c.k === 'var' ? c.m : '__construct';
          if (tFile && index.has(`${tFile}::${m}`)) target = `${tFile}::${m}`;
          else if (tFile && m === '__construct') {
            // constructor-only instantiation: bind to the type's first symbol
            const tFns = byFile.get(tFile) || [];
            if (tFns.length > 0) target = `${tFile}::${tFns[0].name}`;
          }
        } else if (c.k === 'static') {
          const tFile = typeToFile(c.c);
          if (tFile && index.has(`${tFile}::${c.m}`)) target = `${tFile}::${c.m}`;
        }
        if (target && target !== callerKey && symEdges.has(target)) symEdges.get(callerKey).push(target);
      }
    }
  }

  // Callee -> callers, for walking from a finding UP to a route function.
  const symReverse = new Map(Array.from(index.keys()).map((k) => [k, []]));
  for (const [caller, targets] of symEdges) {
    for (const t of targets) symReverse.get(t).push(caller);
  }

  return { index, byFile, edges: symEdges, reverse: symReverse };
}

// Innermost function whose [line, end] range contains the finding line.
function findSymbolAt(graph, file, line) {
  if (!graph.symbols) return null;
  const fns = (graph.symbols.byFile.get(file) || [])
    .filter((f) => line >= f.line && line <= f.end)
    .sort((a, b) => a.end - a.line - (b.end - b.line));
  return fns[0] || null;
}

// Reverse BFS from the finding's symbol to a route function; returns the
// forward path of labels (route first), or null.
function symbolChainToRoute(graph, file, line) {
  const start = findSymbolAt(graph, file, line);
  if (!start) return null;
  const startKey = `${start.file}::${start.name}`;
  const parent = new Map([[startKey, null]]);
  const queue = [startKey];
  while (queue.length) {
    const cur = queue.shift();
    const fn = graph.symbols.index.get(cur);
    if (fn && fn.route) {
      // reconstruct forward path route -> ... -> start
      const path = [];
      for (let k = cur; k; k = parent.get(k)) {
        const f = graph.symbols.index.get(k);
        path.push(`${shortName(f.name)}() ${f.file}:${f.line}`);
      }
      return path;
    }
    for (const importer of graph.symbols.reverse.get(cur) || []) {
      if (!parent.has(importer)) {
        parent.set(importer, cur);
        queue.push(importer);
      }
    }
  }
  return null;
}

// BFS helpers with hop counts.
function reach(start, edgeMap) {
  const seen = new Map([[start, 0]]);
  const queue = [start];
  while (queue.length) {
    const cur = queue.shift();
    for (const next of edgeMap.get(cur) || []) {
      if (!seen.has(next)) {
        seen.set(next, seen.get(cur) + 1);
        queue.push(next);
      }
    }
  }
  return seen; // node -> hops (includes start at 0)
}

function analyzeReachability(graph, changedFiles, blockingFindings) {
  const chains = [];
  const findingFiles = [...new Set(blockingFindings.map((f) => f.file))].filter((f) => graph.nodes.has(f));
  for (const file of findingFiles) {
    const fromEntry = reach(file, graph.reverse); // who imports this, transitively
    const toSink = reach(file, graph.edges); // what this imports, transitively (self = 0)
    const entrypointHops = [...fromEntry.entries()].filter(([n]) => graph.entrypoints.has(n)).sort((a, b) => a[1] - b[1]);
    const sinkHops = [...toSink.entries()].filter(([n]) => graph.sinks.has(n)).sort((a, b) => a[1] - b[1]);

    // Symbol-level chain: route function -> ... -> function holding the finding.
    let symPath = null;
    for (const f of blockingFindings.filter((x) => x.file === file)) {
      if (!f.line) continue;
      const p = symbolChainToRoute(graph, file, f.line);
      if (p) {
        symPath = p;
        break;
      }
    }
    const routeFile = symPath ? (symPath[0].match(/ ([^:]+):\d+$/) || [])[1] : null;

    if (entrypointHops.length > 0 && sinkHops.length > 0) {
      chains.push({
        file,
        entrypoint: entrypointHops[0][0],
        entrypointHops: entrypointHops[0][1],
        sink: sinkHops[0][0],
        sinkHops: sinkHops[0][1],
        findings: blockingFindings
          .filter((f) => f.file === file)
          .map((f) => `${f.ruleId}${f.line ? ':' + f.line : ''}`),
        ...(symPath ? { symbolPath: symPath } : {}),
      });
    } else if (symPath && (graph.sinks.has(file) || sinkHops.length > 0)) {
      // Call-graph-only chain: hooks bypass file imports, so file-level reach
      // is empty while the call graph proves route -> finding. The sink side
      // still needs file-level evidence (the file is, or imports, a sink).
      chains.push({
        file,
        entrypoint: routeFile || file,
        sink: sinkHops.length > 0 ? sinkHops[0][0] : file,
        sinkHops: sinkHops.length > 0 ? sinkHops[0][1] : 0,
        findings: blockingFindings
          .filter((f) => f.file === file)
          .map((f) => `${f.ruleId}${f.line ? ':' + f.line : ''}`),
        symbolPath: symPath,
        viaSymbol: true,
      });
    }
  }
  const applicable = changedFiles.some((f) => graph.nodes.has(f));
  return { applicable, chains };
}

module.exports = { buildImportGraph, analyzeReachability, reach, symbolChainToRoute, extractPhpSymbols };
