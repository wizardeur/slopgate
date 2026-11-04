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
//
// History (v1.10.7, dsh-org PR #632, measured 2026-11-04): `sh` used execSync
// with NO maxBuffer, so every read inherited Node's default ceiling of 1 MiB -
// and a merge-base diff over that throws ENOBUFS, which `attempt` catches and
// turns into null, the same null a missing merge base produces. A too-big diff
// therefore wore the message "cannot compute a diff against the base branch",
// and the consumer spent five checkout-side fixes (fetch-depth 0, an explicit
// base ref, --unshallow, moving HEAD) on a problem that was never the checkout:
// measured on that PR, whose diff is 1,080,625 bytes, execSync threw ENOBUFS
// while the same command piped through the shell printed the diff fine. Two
// changes, and the second does not weaken the first:
//
//   1. THE CEILING IS RAISED, explicitly and on the record: 64 MiB, which
//      covers every pull request this gate has graded with two orders of
//      magnitude of margin.
//   2. THE READ SPLITS as a backstop, not a replacement: if the whole-range
//      read still fails, the SAME three-dot range is re-read in batches of the
//      changed paths and the chunks are concatenated. A merge-base diff is
//      computed once for the range and its per-file hunks do not interact, so
//      the concatenation is byte-identical to the whole read (pinned by test).
//      Fail-closed semantics survive intact, and each property is load-bearing:
//        - the batches use the SAME merge-base range, so a missing merge base
//          fails every batch exactly as it fails the whole read;
//        - an empty changed-path list (head == base) yields no batches and
//          still returns null - an empty range is not treated as a pass;
//        - ANY failed batch returns null - a read that cannot be completed is
//          a read that must not pass, never a partial scan wearing a full one.
//      The one honest limit left: a SINGLE path whose diff exceeds the ceiling
//      cannot be batched below it, and that PR still fails closed by design.

const { execSync } = require('child_process');

const DIFF_MAX_BUFFER = 64 * 1024 * 1024;

function sh(cmd) {
  return execSync(cmd, { encoding: 'utf-8', maxBuffer: DIFF_MAX_BUFFER, stdio: ['pipe', 'pipe', 'ignore'] });
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

// THE BATCHED READ (v1.10.7). Names come back NUL-delimited (`-z`) so paths
// with spaces, quotes or newlines survive the round trip; each path is
// single-quoted for the shell `execSync` runs the command through, with the
// one embedded-quote escape POSIX requires. Batches of 200 paths keep every
// command's argv and output far under the ceiling while staying at a handful
// of invocations for any real pull request.
const SPLIT_BATCH = 200;

function shellQuote(p) {
  return `'${String(p).replace(/'/g, `'\\''`)}'`;
}

function resolveDiffSplit(baseBranch, run = sh) {
  const base = baseBranch || 'main';
  const spec = `origin/${base}...HEAD`;
  let names;
  try {
    names = run(`git diff --name-only -z ${spec}`);
  } catch {
    return null; // no merge base / no ref: every batch would fail the same way
  }
  const paths = names.split('\0').filter(Boolean);
  if (paths.length === 0) return null; // empty range is not treated as a pass
  const chunks = [];
  for (let i = 0; i < paths.length; i += SPLIT_BATCH) {
    const batch = paths.slice(i, i + SPLIT_BATCH).map(shellQuote).join(' ');
    try {
      chunks.push(run(`git diff ${spec} -- ${batch}`));
    } catch {
      return null; // a read that cannot be completed must not pass as a full scan
    }
  }
  const diff = chunks.join('');
  return diff.trim().length > 0 ? diff : null;
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
  if (!diff) diff = resolveDiffSplit(baseBranch, run);
  if (!diff) {
    // Shallow clone without the base ref: fetch just enough to diff.
    try {
      run(`git fetch origin ${baseBranch} --depth=200`);
    } catch { // slopgate-ignore: best-effort: the retry below fails closed
    }
    diff = attempt(range);
    if (!diff) diff = resolveDiffSplit(baseBranch, run);
  }
  return diff;
}

module.exports = { resolveDiff, resolveDiffSplit, diffFailureMessage };
