// GitHub Action entrypoint (runs.using: node20). Reads action inputs, acquires
// the PR diff (fail-closed: a diff that cannot be computed blocks the gate
// instead of silently passing everything), runs the deterministic engine,
// writes outputs + step summary + the single self-updating verdict comment,
// optionally auto-closes, and gates the workflow exit code.

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const { evaluate } = require('./engine');
const { classifyChecks } = require('./ci');
const { renderVerdict, renderCiSummary } = require('./verdict');
const { loadConfig } = require('./config');
const { resolveDiff, diffFailureMessage } = require('./diff');
const gh = require('./github');

// Auto-polish: run the repository's own linters when config is present. Purely
// advisory: failures are logged, never gate the verdict.
function autoPolish(enabled) {
  if (!enabled) return;
  try {
    if (fs.existsSync('package.json')) {
      const pkg = JSON.parse(fs.readFileSync('package.json', 'utf-8'));
      if (pkg.scripts?.lint) execSync('npm run lint --if-present', { stdio: 'inherit' });
    }
    if (fs.existsSync('Cargo.toml')) execSync('cargo clippy --quiet -- -D warnings', { stdio: 'inherit' });
    if (fs.existsSync('pyproject.toml') || fs.existsSync('ruff.toml')) {
      execSync('ruff check --quiet .', { stdio: 'inherit' });
    }
  } catch (err) {
    console.log(`[slopgate] Linter status: ${err.message}`);
  }
}

async function run() {
  const baseBranch = gh.setInput('base_branch', 'main');
  const failOnSlop = gh.setInput('fail_on_slop', 'true') === 'true';
  const ciDiagnostics = gh.setInput('ci_diagnostics', 'false') === 'true';
  const githubToken = gh.setInput('github_token') || process.env.GITHUB_TOKEN;
  const postComment = gh.setInput('post_pr_comment', 'true') !== 'false';
  const autoClose = gh.setInput('auto_close_slop', 'false') === 'true';
  const configPath = gh.setInput('config_path', '') || null;
  const minSeverityInput = gh.setInput('min_block_severity', '');
  const sarifFile = gh.setInput('sarif_file', '');

  console.log('[slopgate] Deterministic PR gate: hygiene checks, 22-shield CWE rules, reachability analysis.');

  const diff = resolveDiff(baseBranch);
  if (!diff) {
    const msg = diffFailureMessage(baseBranch);
    console.error(msg);
    gh.writeSummary(`## :shield: SlopGate: gate failed closed\n\n${msg}`);
    process.exit(1);
  }

  const config = loadConfig(process.cwd(), configPath);
  if (minSeverityInput) config.minBlockSeverity = minSeverityInput;

  // The workspace is checked out at the PR head, so changed files are read
  // from disk for the analyzer modules (AST / external tools).
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

  autoPolish(gh.setInput('auto_polish', 'true') === 'true');

  const repo = process.env.GITHUB_REPOSITORY || 'unknown/repo';
  let prNumber = null;
  try {
    const event = JSON.parse(fs.readFileSync(process.env.GITHUB_EVENT_PATH, 'utf-8'));
    prNumber = event.pull_request?.number || event.number || null;
  } catch { // slopgate-ignore: best-effort: outside a pull_request event there is no PR to comment on
  }

  // Action outputs.
  gh.setOutput('slop_score', String(result.slopScore));
  gh.setOutput('lines_reduced', result.linesReduced);
  gh.setOutput('invariants_verified', result.invariantsVerified);
  gh.setOutput('security_findings_count', String(result.securityFindings.length));
  gh.setOutput(
    'critical_cwe_count',
    String(result.securityFindings.filter((f) => f.severity === 'CRITICAL').length)
  );
  gh.setOutput('blast_radius_layers', String(result.blastRadius.impactedLayers.length));
  gh.setOutput('suppressed_count', String(result.suppressedCount));

  // Optional CI triage.
  let ciSummary = '';
  if (ciDiagnostics) {
    const sha = process.env.GITHUB_SHA || '';
    const checks = await gh.fetchCheckRuns(repo, sha, githubToken);
    if (checks.length > 0) {
      const ci = classifyChecks(checks);
      gh.setOutput('ci_classification', ci.classification);
      gh.setOutput('flaky_jobs_count', String(ci.flakeCount));
      gh.setOutput('gated_jobs_count', String(ci.gatedCount));
      ciSummary = renderCiSummary(ci);
    } else {
      gh.setOutput('ci_classification', 'ALL_GREEN');
      gh.setOutput('flaky_jobs_count', '0');
      gh.setOutput('gated_jobs_count', '0');
    }
  } else {
    gh.setOutput('ci_classification', 'ALL_GREEN');
    gh.setOutput('flaky_jobs_count', '0');
    gh.setOutput('gated_jobs_count', '0');
  }

  const verdict = renderVerdict(result, { repo, ciSummary });
  gh.writeSummary(verdict);
  if (postComment && prNumber) {
    await gh.upsertVerdictComment(repo, prNumber, githubToken, verdict);
  }

  // Optional SARIF for GitHub code scanning (needs security-events: write and
  // a codeql-action/upload-sarif step in the caller's workflow; GHAS required
  // on private repos).
  if (sarifFile) {
    const { buildSarif } = require('./sarif');
    const target = path.isAbsolute(sarifFile) ? sarifFile : `${process.env.GITHUB_WORKSPACE || process.cwd()}/${sarifFile}`;
    fs.writeFileSync(target, JSON.stringify(buildSarif(result), null, 2));
    console.log(`[slopgate] SARIF written to ${target}`);
  }

  const criticalCount = result.blockingFindings.filter((f) => f.severity === 'CRITICAL').length;
  if (!result.isGreen && autoClose && prNumber && (result.slopScore >= 60 || criticalCount > 0)) {
    await gh.autoClosePullRequest(repo, prNumber, githubToken, result.message);
  }

  if (!result.isGreen) {
    console.error(`[slopgate] BLOCKED: ${result.message}`);
    if (failOnSlop) process.exit(1);
  } else {
    console.log('[slopgate] Green. Zero slop, zero blocking CWE findings.');
  }
}

module.exports = { run, resolveDiff };

if (require.main === module) {
  run().catch((err) => {
    console.error(`[slopgate] ${err.message}`);
    process.exit(1);
  });
}
