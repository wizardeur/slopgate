// Renders the single self-updating PR verdict card: metrics table, CWE
// findings table, mermaid blast-radius graph, CI triage matrix.

const VERDICT_MARKER = '<!-- slopgate-verdict -->';

// Real-chain edges when the import/call graph proved a path.
// With a symbolPath, endpoints become route() and target() functions.
function chainMermaid(chains) {
  if (!chains || chains.length === 0) return [];
  const c = chains[0];
  const epLabel = c.symbolPath ? c.symbolPath[0] : `entrypoint: ${String(c.entrypoint).replace(/"/g, "'")}`;
  const cfLabel = c.symbolPath
    ? `${c.symbolPath[c.symbolPath.length - 1]} (${c.findings.join(', ')})`
    : `${String(c.file).replace(/"/g, "'")} (${c.findings.join(', ')})`;
  return [
    `  EP["${epLabel.replace(/"/g, "'")}"]`,
    `  CF["${cfLabel.replace(/"/g, "'")}"]`,
    `  SK["sink: ${String(c.sink).replace(/"/g, "'")}"]`,
    '  EP --> CF --> SK',
    '  style EP fill:#78350f,stroke:#f59e0b,color:#fffbeb',
    '  style CF fill:#7f1d1d,stroke:#ef4444,color:#fef2f2',
    '  style SK fill:#7f1d1d,stroke:#ef4444,color:#fef2f2',
  ];
}

function buildMermaidBlastRadius(blastRadius, securityFindings) {
  const layers = blastRadius?.impactedLayers || [];
  const chainLines = chainMermaid(blastRadius?.chains);
  if (layers.length === 0) {
    return [
      '```mermaid',
      'flowchart LR',
      ...chainLines,
      '  PR["Pull Request Diff"] --> CORE["Core Domain (0 Files)"]',
      '  style CORE fill:#064e3b,stroke:#10b981,color:#ecfdf5',
      '```',
    ].join('\n');
  }

  const lines = ['```mermaid', 'flowchart LR', ...chainLines, '  PR["Pull Request Diff"]'];
  layers.forEach((l, idx) => {
    const node = `L${idx}`;
    const name = String(l.layer).replace(/"/g, "'");
    const status =
      l.riskLevel === 'CRITICAL' ? 'CRITICAL CWE' : l.riskLevel === 'ELEVATED' ? 'ELEVATED' : 'CLEAN';
    lines.push(
      `  PR --> ${node}["${name} (${l.files.length} file${l.files.length === 1 ? '' : 's'} / ${status})"]`
    );
    if (l.riskLevel === 'CRITICAL') lines.push(`  style ${node} fill:#7f1d1d,stroke:#ef4444,color:#fef2f2`);
    else if (l.riskLevel === 'ELEVATED') lines.push(`  style ${node} fill:#78350f,stroke:#f59e0b,color:#fffbeb`);
    else lines.push(`  style ${node} fill:#064e3b,stroke:#10b981,color:#ecfdf5`);
  });

  if (securityFindings && securityFindings.length > 0) {
    const cwes = Array.from(new Set(securityFindings.map((f) => f.cwe))).join(', ');
    lines.push(`  GATE["Gate Verdict: BLOCKED (${cwes})"]`);
    lines.push('  style GATE fill:#7f1d1d,stroke:#ef4444,color:#fef2f2');
  } else {
    lines.push('  GATE["Gate Verdict: 100% GREEN"]');
    lines.push('  style GATE fill:#064e3b,stroke:#10b981,color:#ecfdf5');
  }
  for (let i = 0; i < layers.length; i++) lines.push(`  L${i} --> GATE`);
  lines.push('```');
  return lines.join('\n');
}

function renderVerdict(result, { repo, ciSummary = '' }) {
  const { isGreen, slopScore, engineeringScore, securityFindings, blockingFindings, blastRadius, linesReduced, invariantsVerified } =
    result;
  const criticalCount = blockingFindings.filter((f) => f.severity === 'CRITICAL').length;

  const layerRows =
    blastRadius.impactedLayers.length > 0
      ? blastRadius.impactedLayers
          .map((l) => {
            const badge =
              l.riskLevel === 'CRITICAL'
                ? ':red_circle: **CRITICAL**'
                : l.riskLevel === 'ELEVATED'
                ? ':warning: **ELEVATED**'
                : ':green_circle: **CLEAN**';
            const sample =
              l.files.slice(0, 3).map((f) => `\`${f}\``).join(', ') +
              (l.files.length > 3 ? ` *(+${l.files.length - 3} more)*` : '');
            return `| **${l.layer}** | \`${l.files.length}\` | ${badge} | ${sample} |`;
          })
          .join('\n')
      : '| **Core Domain** | `0` | :green_circle: **CLEAN** | *No changes* |';

  const cweTable =
    securityFindings.length > 0
      ? `\n#### Security findings (${securityFindings.length}, blocking: ${blockingFindings.length})\n\n` +
        '| Rule | CWE | Severity | Location | Vulnerability & Required Fix |\n| :--- | :--- | :---: | :--- | :--- |\n' +
        securityFindings
          .map((f) => {
            const sev =
              (f.severity === 'CRITICAL'
                ? ':red_circle: CRITICAL'
                : f.severity === 'HIGH'
                ? ':orange_circle: HIGH'
                : ':yellow_circle: MEDIUM') + (f.advisory ? ' *(advisory)*' : '');
            const loc = `\`${f.file}${f.line ? ':' + f.line : ''}\`${f.approx ? ' *(approx)*' : ''}`;
            return `| \`${f.ruleId}\` | **\`${f.cwe}\`** | ${sev} | ${loc} | **${f.title}**: *${f.remediation}* |`;
          })
          .join('\n') +
        '\n'
      : '';

  return `${VERDICT_MARKER}
## :shield: SlopGate Security Audit · ${isGreen ? 'PASSED (Green)' : 'BLOCKED: ACTION REQUIRED'}

> Deterministic PR gatekeeper: Hygiene checks, 22 CWE-mapped security shields, reachability analysis. No LLM involved.
${analysisSection(result)}

| Metric | Measured | Standard | Status |
| :--- | :--- | :--- | :--- |
| **Engineering Score** | \`${engineeringScore} / 100\` | \`>= 60 / 100\` | ${isGreen ? ':white_check_mark: Approved' : ':x: Action Required'} |
| **AI Slop Score** | \`${slopScore}%\` | \`0%\` | ${isGreen ? ':white_check_mark: Clean' : ':x: Action Required'} |
| **12-Shield CWE Security** | \`${blockingFindings.length} blocking finding(s)\` | \`0\` | ${blockingFindings.length === 0 ? ':white_check_mark: 12/12 Passed' : `:x: ${blockingFindings.length} Blocked`} |
| **Blast Radius** | \`${blastRadius.impactedLayers.length} layer(s) / ${blastRadius.totalFilesChanged} file(s)\` | \`Contained\` | ${blastRadius.crossLayerReachability ? ':x: Cross-Layer Sink' : ':white_check_mark: Isolated'} |
| **Shields Passed** | \`${invariantsVerified}\` | \`100%\` | :white_check_mark: |
| **Diff Minimization (real)** | \`${linesReduced}\` | \`informational\` | :white_check_mark: |

### Architectural blast radius
> **Exploit reachability**: ${blastRadius.reachabilitySummary}

${buildMermaidBlastRadius(blastRadius, blockingFindings)}

| Architectural Layer | Files Touched | Security Posture | Impacted Surface |
| :--- | :---: | :---: | :--- |
${layerRows}
${cweTable}
${ciSummary}
---
*${repo ? `Repo: \`${repo}\` · ` : ''}Deterministic evaluation, no diff leaves the runner · Critical findings: ${criticalCount}.*
`;
}

function renderCiSummary({ classification, passCount, gatedCount, flakeCount, defectCount }) {
  return `
### CI triage matrix · ${classification}

| Category | Checks | Contributor Impact | Root Cause |
| :--- | :---: | :--- | :--- |
| :green_circle: **Passed** | \`${passCount}\` | Clean | Tests, types, linters, compilers green. |
| :lock: **Maintainer Triage Gates** | \`${gatedCount}\` | Unaffected | Requires maintainer authorization label. |
| :warning: **Upstream Infra Flakes** | \`${flakeCount}\` | Unaffected | Runner lost communication, timeout, network drop. |
| :red_circle: **Code Defect Failures** | \`${defectCount}\` | ${defectCount === 0 ? 'None' : 'Action Required'} | ${defectCount === 0 ? 'Zero contributor errors.' : 'Investigate failing test/build.'} |
`;
}

// Analysis-depth section: shown whenever any analyzer module ran. Explicitly
// says "regex" when no analyzer was available: never silently degrades.
function analysisSection(result) {
  const a = result.analysis;
  if (!a) return '';
  const rows = a.ran
    .map((r) => {
      const status = r.available ? ':white_check_mark: ran' : `:grey_question: unavailable${r.error ? `: ${r.error}` : ''}`;
      return `| \`${r.id}\` | ${status} | ${r.findings} |`;
    })
    .join('\n');
  if (!rows) {
    const reason =
      a.filesAnalyzed > 0
        ? 'no analyzer module applies to the changed file types'
        : 'no analyzer modules available or no readable changed files';
    return `\n> Analysis depth: **regex** (${reason}).\n`;
  }
  const note = a.filesMissing > 0 ? `\n> ${a.filesMissing} changed file(s) were not readable for deep analysis.` : '';
  return `\n### Analysis depth: **${a.depth}**\n\n| Analyzer | Status | Findings |\n| :--- | :--- | :---: |\n${rows}\n${note}`;
}

module.exports = { VERDICT_MARKER, buildMermaidBlastRadius, renderVerdict, renderCiSummary, analysisSection };
