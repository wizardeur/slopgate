// Diff acquisition shared by the GitHub Action and the CLI.
//
// Fail-closed semantics: only `git diff origin/<base>...HEAD` (three dots,
// i.e. relative to the merge base) is a complete view of a pull request. Every
// other way of producing a diff is a partial range wearing a full-range label,
// so there is deliberately no fallback: an uncomputable diff returns null and
// the caller stops the gate.
//
// History (defect 3): a `git diff HEAD~1` fallback used to catch the failure
// case. On a depth>=2 checkout whose merge base lies outside the clone it did
// not fail, it succeeded over the LAST COMMIT ONLY, so a two-commit PR with two
// defects was reported as a clean-looking verdict over one. A depth=1 checkout
// happened to fail closed because HEAD~1 did not exist yet, which is why the
// hole was invisible in shallow-depth-1 testing.

const { execSync } = require('child_process');

// A DIFF IS NOT SMALL, AND execSync's DEFAULT BUFFER IS 1 MiB. Without maxBuffer here, any pull
// request over roughly a megabyte of diff throws ENOBUFS - and `attempt` below catches it and
// returns null, so the gate reports "cannot compute a diff ... an empty range is not treated as a
// pass" for a pull request whose diff is perfectly computable. Measured on a real 1,080,625-byte
// diff: ENOBUFS, and the workaround took five wrong diagnoses because the message names the
// checkout, not the buffer.
//
// The ceiling matches the analyzers in this same package (py-imports.js, external.js,
// python-ast.js all set maxBuffer explicitly); diff.js was the one call that forgot.
const MAX_DIFF_BYTES = 64 * 1024 * 1024;

function sh(cmd) {
  return execSync(cmd, { encoding: 'utf-8', stdio: ['pipe', 'pipe', 'ignore'], maxBuffer: MAX_DIFF_BYTES });
}

function diffFailureMessage(baseBranch) {
  const base = baseBranch || 'main';
  return (
    `[slopgate] FATAL: cannot compute a diff against the base branch "${base}". ` +
    `The gate got no diff from "git diff origin/${base}...HEAD" (the command failed, or it ` +
    'succeeded with an empty range because the head equals the base). Only a merge-base diff is a ' +
    'complete view of the pull request, and an empty range is not treated as a pass. ' +
    'On a shallow checkout the usual cause is that the merge base lies outside the clone. ' +
    'Fix it with actions/checkout and fetch-depth: 0, or create the remote-tracking ref the gate ' +
    `diffs against: "git fetch origin ${base}:refs/remotes/origin/${base}". ` +
    'Failing closed: a partial diff must never pass as a full scan.'
  );
}

function resolveDiff(baseBranch, run = sh) {
  const attempt = (cmd) => {
    try {
      const out = run(cmd);
      return typeof out === 'string' && out.trim().length > 0 ? out : null;
    } catch {
      return null;
    }
  };
  const range = `git diff origin/${baseBranch}...HEAD`;
  let diff = attempt(range);
  if (!diff) {
    // Shallow clone without the base ref: fetch just enough to diff.
    try {
      run(`git fetch origin ${baseBranch} --depth=200`);
    } catch { // slopgate-ignore: best-effort: the retry below fails closed
    }
    diff = attempt(range);
  }
  return diff;
}

module.exports = { resolveDiff, diffFailureMessage, MAX_DIFF_BYTES };
