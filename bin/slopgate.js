#!/usr/bin/env node
// slopgate CLI. Local twin of the GitHub Action: identical engine, identical
// exit-code contract (0 = green, 1 = blocked), so it can gate commits/hooks.
//
//   slopgate --diff <file>       evaluate a unified diff from a file
//   slopgate --base main         diff HEAD against origin/main (default: stdin)
//   slopgate --json              machine-readable output
//   cat foo.diff | slopgate
//
// --base is fail-closed, exactly like the Action: only a merge-base diff
// (origin/main...HEAD) is a complete view of the change. If it cannot be
// computed, the CLI exits 1 with setup instructions instead of scanning a
// partial range (defect 3: a shallow clone used to fall back to HEAD~1).

const fs = require('fs');
const { evaluate } = require('../src/engine');
const { renderVerdict } = require('../src/verdict');
const { loadConfig } = require('../src/config');

function has(flag) {
  return process.argv.includes(flag);
}

function arg(name, fallback = null) {
  const i = process.argv.indexOf(name);
  const next = i !== -1 ? process.argv[i + 1] : undefined;
  return next && !next.startsWith('--') ? next : fallback;
}

function readDiff() {
  const file = arg('--diff');
  if (file) return fs.readFileSync(file, 'utf-8');
  const base = arg('--base');
  if (has('--base') && base) {
    // Same fail-closed guard as the Action: a diff that cannot be computed
    // against the merge base must stop the gate, not silently shrink its range.
    const { resolveDiff, diffFailureMessage } = require('../src/diff');
    const diff = resolveDiff(base);
    if (diff === null) {
      console.error(diffFailureMessage(base));
      process.exit(1);
    }
    return diff;
  }
  if (!process.stdin.isTTY) return fs.readFileSync(0, 'utf-8');
  console.error('Usage: slopgate (--diff <file> | --base <branch> | diff on stdin) [--config <path>] [--json]');
  process.exit(2);
}

const diff = readDiff();
const config = loadConfig(process.cwd(), arg('--config'));
const result = evaluate(diff, {
  config,
  readFile: (p) => {
    try {
      return fs.readFileSync(p, 'utf-8');
    } catch {
      return null;
    }
  },
});

if (has('--json')) {
  console.log(JSON.stringify(result, null, 2));
} else {
  console.log(renderVerdict(result, { repo: null }));
  console.log(`slop score: ${result.slopScore}/100 · findings: ${result.securityFindings.length} · ${result.message}`);
}

const sarifPath = arg('--sarif');
if (sarifPath) {
  const { buildSarif } = require('../src/sarif');
  fs.writeFileSync(sarifPath, JSON.stringify(buildSarif(result), null, 2));
  console.error(`[slopgate] SARIF written to ${sarifPath}`);
}

process.exit(result.isGreen ? 0 : 1);
