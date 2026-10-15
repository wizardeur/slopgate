// GitHub API helpers for action mode (uses global fetch, Node >= 20).

const VERDICT_MARKER = '<!-- slopgate-verdict -->';

function ghHeaders(token) {
  return {
    'User-Agent': 'slopgate-action',
    Authorization: `Bearer ${token}`,
    Accept: 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28',
    'Content-Type': 'application/json',
  };
}

async function gh(method, apiPath, token, payload = null) {
  if (!token) return { ok: false, status: 0, data: null };
  try {
    const res = await fetch(`https://api.github.com${apiPath}`, {
      method,
      headers: ghHeaders(token),
      body: payload ? JSON.stringify(payload) : undefined,
      signal: AbortSignal.timeout(10000),
    });
    let data = null;
    try {
      data = await res.json();
    } catch {
      /* best-effort: 2xx responses may have empty bodies; ok/status carry the verdict */
    }
    return { ok: res.ok, status: res.status, data };
  } catch {
    return { ok: false, status: 0, data: null };
  }
}

// Post or update THE single verdict comment, identified by an HTML marker.
// Deletes any duplicates left by races or older runs.
async function upsertVerdictComment(repo, prNumber, token, markdownBody) {
  if (!token || !repo || !prNumber) return;
  const bodyWithMarker = markdownBody.trimStart().startsWith(VERDICT_MARKER)
    ? markdownBody
    : `${VERDICT_MARKER}\n${markdownBody}`;
  const list = await gh('GET', `/repos/${repo}/issues/${prNumber}/comments?per_page=100`, token);
  if (list.ok && Array.isArray(list.data)) {
    const existing = list.data.filter((c) => typeof c.body === 'string' && c.body.includes(VERDICT_MARKER));
    if (existing.length > 0) {
      await gh('PATCH', `/repos/${repo}/issues/comments/${existing[0].id}`, token, { body: bodyWithMarker });
      for (let i = 1; i < existing.length; i++) {
        await gh('DELETE', `/repos/${repo}/issues/comments/${existing[i].id}`, token);
      }
      return;
    }
  }
  await gh('POST', `/repos/${repo}/issues/${prNumber}/comments`, token, { body: bodyWithMarker });
}

async function autoClosePullRequest(repo, prNumber, token, reason) {
  if (!token || !repo || !prNumber) return;
  const res = await gh('PATCH', `/repos/${repo}/pulls/${prNumber}`, token, { state: 'closed' });
  if (res.ok) console.log(`[slopgate] Auto-closed PR #${prNumber}: ${reason}`);
}

// Fetch check runs for a SHA; prefers `gh` CLI when available (it handles auth),
// falls back to the REST API with the provided token.
async function fetchCheckRuns(repo, sha, token) {
  try {
    const { execSync } = require('child_process');
    const out = execSync(
      `gh api repos/${repo}/commits/${sha}/check-runs --jq ".check_runs[] | {name: .name, status: .status, conclusion: .conclusion}"`,
      { encoding: 'utf-8', stdio: ['pipe', 'pipe', 'ignore'] }
    );
    if (out.trim()) {
      return out
        .trim()
        .split('\n')
        .map((l) => {
          try {
            return JSON.parse(l);
          } catch {
            return null;
          }
        })
        .filter(Boolean);
    }
  } catch {
    // fall through to REST
  }
  if (!token || !sha || sha === 'unknown') return [];
  const res = await gh('GET', `/repos/${repo}/commits/${sha}/check-runs?per_page=100`, token);
  if (res.ok && res.data?.check_runs) {
    return res.data.check_runs.map((c) => ({ name: c.name, status: c.status, conclusion: c.conclusion }));
  }
  return [];
}

function setInput(name, fallback = '') {
  const env = process.env[`INPUT_${name.toUpperCase().replace(/ /g, '_')}`];
  return env === undefined || env === '' ? fallback : env;
}

function setOutput(name, value) {
  if (process.env.GITHUB_OUTPUT) {
    require('fs').appendFileSync(process.env.GITHUB_OUTPUT, `${name}=${value}\n`);
  }
}

function writeSummary(markdown) {
  if (process.env.GITHUB_STEP_SUMMARY) {
    require('fs').appendFileSync(process.env.GITHUB_STEP_SUMMARY, `${markdown}\n`);
  }
}

module.exports = { gh, upsertVerdictComment, autoClosePullRequest, fetchCheckRuns, setInput, setOutput, writeSummary };
