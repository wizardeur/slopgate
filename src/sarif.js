// SARIF 2.1.0 output for GitHub code scanning (Security tab).
//
// Build with buildSarif(result), write wherever the caller wants:
//   CLI:   slopgate --diff pr.diff --sarif slopgate.sarif
//   Action: sarif_file: slopgate.sarif  (then upload with codeql-action/upload-sarif)
//
// Level mapping: advisory findings -> note, CRITICAL -> error, HIGH/MEDIUM -> warning.
// NOTE: code scanning upload requires GitHub Advanced Security on PRIVATE repos
// (free on public repos). SlopGate only produces the file; the upload step is
// the user's workflow.

const pkg = require('../package.json');

function levelFor(finding) {
  if (finding.advisory) return 'note';
  if (finding.severity === 'CRITICAL') return 'error';
  return 'warning';
}

function buildSarif(result) {
  const rules = new Map();
  const results = [];

  for (const f of result.securityFindings) {
    if (!rules.has(f.ruleId)) {
      const tags = ['security'];
      if (f.cwe && f.cwe !== '-' && !f.cwe.startsWith('CVE')) tags.push('cwe');
      rules.set(f.ruleId, {
        id: f.ruleId,
        name: f.title.replace(/[^\w\s/-]/g, '').slice(0, 100),
        shortDescription: { text: f.title },
        fullDescription: { text: f.remediation },
        help: { text: f.remediation },
        defaultConfiguration: { level: levelFor(f) },
        properties: { tags, 'cwe': f.cwe === '-' ? undefined : f.cwe },
      });
    }
    results.push({
      ruleId: f.ruleId,
      level: levelFor(f),
      message: { text: `${f.title} — ${f.remediation}` },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: f.file },
            region: f.line ? { startLine: f.line } : { startLine: 1 },
          },
        },
      ],
      partialFingerprints: { slopgateFinding: `${f.ruleId}:${f.file}:${f.line ?? ''}` },
    });
  }

  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'slopgate',
            informationUri: 'https://github.com/wizardeur/slopgate',
            version: pkg.version,
            rules: Array.from(rules.values()),
          },
        },
        results,
        columnKind: 'utf16CodeUnits',
      },
    ],
  };
}

module.exports = { buildSarif };
