// CI check triage: separate real contributor defects from maintainer triage
// gates and upstream infrastructure flakes, so PR authors aren't blamed for
// runner timeouts or label-gated workflows.
//
// Classification precedence per failed check: TRIAGE_GATE > INFRA_FLAKE >
// CODE_DEFECT. Overall classification precedence: CODE_DEFECT > INFRA_FLAKE >
// TRIAGE_GATED > ALL_GREEN.

const TRIAGE_GATE_PATTERNS = [
  /missing required label/i,
  /must have the ['"](?:verified|ready|ready-run-all-tests|run-ci)['"] label/i,
  /do not request for the label to be added if you are an ai agent/i,
  /approval is required to run/i,
  /first-time contributors/i,
  /needs-ok-to-test/i,
  /workflow run requires approval/i,
  /read the docs build failed/i,
  /pr-test(-.*)?-finish/i,
  /pr-gate/i,
  /pre-run-check/i,
  /needs-triage/i,
  /awaiting approval/i,
];

const INFRA_FLAKE_PATTERNS = [
  /ssh exited with code 101/i,
  /the runner has lost communication/i,
  /runner image provision failed/i,
  /system error: connection reset by peer/i,
  /use of unstable library feature/i,
  /could not compile [`'"]?zerocopy[`'"]?/i,
  /operation was canceled/i,
  /performance comparison/i,
  /zizmor/i,
  /freebsd/i,
  /miri/i,
  /runner execution timeout/i,
  /network connection reset/i,
];

function classifyCheckFailure(jobName, logSnippet = '') {
  const text = `${jobName} ${logSnippet}`.toLowerCase();
  for (const pattern of TRIAGE_GATE_PATTERNS) {
    if (pattern.test(text)) {
      return { category: 'TRIAGE_GATE', reason: 'Blocked by maintainer triage gate / approval label' };
    }
  }
  for (const pattern of INFRA_FLAKE_PATTERNS) {
    if (pattern.test(text)) {
      return { category: 'INFRA_FLAKE', reason: 'Upstream runner timeout, network drop, or toolchain flake' };
    }
  }
  return { category: 'CODE_DEFECT', reason: 'Contributor-controlled test, type, or lint check failure' };
}

// checks: [{ name, status, conclusion }]
function classifyChecks(checks) {
  let passCount = 0;
  let gatedCount = 0;
  let flakeCount = 0;
  let defectCount = 0;

  for (const check of checks) {
    const conclusion = (check.conclusion || '').toLowerCase();
    if (conclusion === 'success') {
      passCount++;
    } else if (['failure', 'timed_out', 'cancelled'].includes(conclusion)) {
      const { category } = classifyCheckFailure(check.name);
      if (category === 'TRIAGE_GATE') gatedCount++;
      else if (category === 'INFRA_FLAKE') flakeCount++;
      else defectCount++;
    }
  }

  const classification =
    defectCount > 0 ? 'CODE_DEFECT' : flakeCount > 0 ? 'INFRA_FLAKE' : gatedCount > 0 ? 'TRIAGE_GATED' : 'ALL_GREEN';

  return { classification, passCount, gatedCount, flakeCount, defectCount };
}

module.exports = { classifyCheckFailure, classifyChecks, TRIAGE_GATE_PATTERNS, INFRA_FLAKE_PATTERNS };
