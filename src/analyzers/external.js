// External analyzer modules: wrap any repo-relative check tool that signals
// problems via exit code (tsc --noEmit, php -l, a custom gate script, ...).
//
// Config (in .slopgate.json):
//   "analyzers": {
//     "external": [
//       { "id": "php-lint",
//         "cmd": "php -l {file}",
//         "when": "package.json",      // optional gate: only run if this file exists
//         "severity": "HIGH",          // default HIGH
//         "timeoutMs": 60000 }
//     ]
//   }
//
// Exit 0 -> no finding. Non-zero -> one SG-EXT finding carrying a sanitized
// output excerpt. Missing binary / timeout -> analyzer marked unavailable,
// never fatal: the gate must not break because an optional tool is absent.

const { spawnSync } = require('child_process');
const fs = require('fs');

function gateFileExists(repoRoot, rel) {
  try {
    fs.accessSync(`${repoRoot}/${rel}`);
    return true;
  } catch {
    return false;
  }
}

function runExternalAnalyzers(ext, { repoRoot = process.cwd() } = {}) {
  const { id, cmd, when, severity = 'HIGH', timeoutMs = 60000 } = ext;
  if (!id || !cmd) return { available: false, error: 'external analyzer needs id and cmd' };
  if (when && !gateFileExists(repoRoot, when)) {
    return { available: false, skipped: true, error: `gate file ${when} not present` };
  }

  const res = spawnSync('sh', ['-c', cmd], {
    cwd: repoRoot,
    encoding: 'utf-8',
    timeout: timeoutMs,
    maxBuffer: 4 * 1024 * 1024,
  });

  if (res.error) {
    // ETIMEDOUT / ENOENT mean the optional tool is unavailable; degrade, don't fail.
    return { available: false, error: res.error.message };
  }
  if (res.status === 0) return { available: true, findings: [] };

  const excerpt = `${res.stderr || ''}\n${res.stdout || ''}`
    .replace(/\x1b\[[0-9;]*m/g, '') // ANSI codes
    .trim()
    .split('\n')
    .slice(0, 12)
    .join('\n')
    .slice(0, 800);

  return {
    available: true,
    findings: [
      {
        ruleId: `SG-EXT-${id.toUpperCase().replace(/[^A-Z0-9]/g, '')}`,
        cwe: '-',
        severity,
        title: `External analyzer reported issues: ${id}`,
        file: cmd,
        line: null,
        remediation: `Fix the issues reported by \`${cmd}\` (excerpt below).`,
        excerpt,
        via: 'external',
      },
    ],
  };
}

module.exports = { runExternalAnalyzers };
