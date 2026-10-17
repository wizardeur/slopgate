// Fixture + unit tests. Run: node test/run.js
const assert = require('assert');
const { spawnSync } = require('child_process');
const path = require('path');

const { evaluate } = require('../src/engine');
const { classifyCheckFailure, classifyChecks } = require('../src/ci');
const { checkHygiene } = require('../src/hygiene');

const ROOT = path.join(__dirname, '..');
const read = (f) => require('fs').readFileSync(path.join(__dirname, 'fixtures', f), 'utf-8');

let passed = 0;
function check(name, fn) {
  try {
    fn();
    passed++;
    console.log(`  ok  ${name}`);
  } catch (err) {
    console.error(`FAIL  ${name}\n      ${err.message}`);
    process.exitCode = 1;
  }
}

// ---- vulnerable.diff: should trip all 12 shields -------------------------
const vuln = evaluate(read('vulnerable.diff'));

check('vulnerable: blocked with score 90', () => {
  assert.strictEqual(vuln.isGreen, false);
  assert.strictEqual(vuln.slopScore, 90);
  assert.strictEqual(vuln.engineeringScore, 10);
});

check('vulnerable: all 12 shields triggered', () => {
  const rules = new Set(vuln.securityFindings.map((f) => f.ruleId));
  assert.strictEqual(rules.size, 12);
  for (let i = 1; i <= 12; i++) {
    assert.ok(rules.has(`SG-SEC-${String(i).padStart(3, '0')}`), `missing SG-SEC-${i}`);
  }
});

check('vulnerable: 8 CRITICAL findings', () => {
  const crit = vuln.securityFindings.filter((f) => f.severity === 'CRITICAL');
  assert.strictEqual(crit.length, 8);
});

check('vulnerable: cross-layer reachability detected', () => {
  assert.strictEqual(vuln.blastRadius.crossLayerReachability, true);
  assert.ok(vuln.blastRadius.reachabilitySummary.includes('CRITICAL REACHABILITY'));
});

check('vulnerable: blast radius spans expected layers', () => {
  const layers = vuln.blastRadius.impactedLayers.map((l) => l.layer);
  assert.ok(layers.includes('Persistence & Vector / Data Store'));
  assert.ok(layers.includes('API Contracts & Entrypoints'));
  assert.ok(layers.includes('CI/CD & Infrastructure'));
  assert.ok(layers.includes('Frontend Client & UI Surface'));
  assert.strictEqual(vuln.blastRadius.impactedLayers.length, 6);
});

check('vulnerable: variant CWEs resolved (94, 295-family, 693)', () => {
  const evalFinding = vuln.securityFindings.find((f) => f.ruleId === 'SG-SEC-004' && f.file === 'ingest.py');
  assert.strictEqual(evalFinding.cwe, 'CWE-94');
  const promptFinding = vuln.securityFindings.find((f) => f.ruleId === 'SG-SEC-010');
  assert.strictEqual(promptFinding.cwe, 'CWE-693');
});

check('vulnerable: real lines_reduced (not a hardcoded 94%)', () => {
  assert.ok(/^\d+%$/.test(vuln.linesReduced));
});

check('vulnerable: mass test deletion flagged', () => {
  assert.strictEqual(vuln.hasTestDeletions, true);
});

// ---- clean.diff ----------------------------------------------------------
const clean = evaluate(read('clean.diff'));

check('clean: green, score 0, no findings', () => {
  assert.strictEqual(clean.isGreen, true);
  assert.strictEqual(clean.slopScore, 0);
  assert.strictEqual(clean.securityFindings.length, 0);
  assert.strictEqual(clean.invariantsVerified, '100%');
});

check('clean: real diff minimization computed (1 removed / 4 added -> 20%)', () => {
  assert.strictEqual(clean.linesReduced, '20%');
});

// ---- hygiene-only.diff ---------------------------------------------------
const hygiene = evaluate(read('hygiene-only.diff'));

check('hygiene-only: blocked at score 40, no security findings', () => {
  assert.strictEqual(hygiene.isGreen, false);
  assert.strictEqual(hygiene.slopScore, 40);
  assert.strictEqual(hygiene.securityFindings.length, 0);
  assert.strictEqual(hygiene.hygieneIssues.length, 1); // slop phrase; the escaped-backtick check was removed after external dogfooding
});

// ---- unit: trojan source bidi --------------------------------------------
check('unit: bidi unicode triggers SG-SEC-010 even in test files', () => {
  const diff =
    'diff --git a/tests/x.js b/tests/x.js\n--- a/tests/x.js\n+++ b/tests/x.js\n' +
    '+const s = "a\u202Eb";\n';
  const res = evaluate(diff);
  const f = res.securityFindings.find((x) => x.ruleId === 'SG-SEC-010');
  assert.ok(f, 'expected SG-SEC-010');
  assert.ok(f.title.includes('Trojan Source'));
});

// ---- unit: CI classifier --------------------------------------------------
check('ci: triage gate / infra flake / defect classification', () => {
  assert.strictEqual(classifyCheckFailure('workflow run requires approval').category, 'TRIAGE_GATE');
  assert.strictEqual(classifyCheckFailure('ci / build', 'the runner has lost communication').category, 'INFRA_FLAKE');
  assert.strictEqual(classifyCheckFailure('npm test').category, 'CODE_DEFECT');
});

check('ci: overall precedence defect > flake > gate > green', () => {
  const ok = { name: 'lint', conclusion: 'success' };
  assert.strictEqual(classifyChecks([ok]).classification, 'ALL_GREEN');
  assert.strictEqual(
    classifyChecks([ok, { name: 'needs-triage', conclusion: 'failure' }, { name: 'runner execution timeout', conclusion: 'timed_out' }])
      .classification,
    'INFRA_FLAKE'
  );
  assert.strictEqual(
    classifyChecks([ok, { name: 'needs-triage', conclusion: 'failure' }, { name: 'npm test', conclusion: 'failure' }])
      .classification,
    'CODE_DEFECT'
  );
  assert.strictEqual(classifyChecks([{ name: 'needs-ok-to-test', conclusion: 'failure' }]).classification, 'TRIAGE_GATED');
});

// ---- unit: hygiene scanner ------------------------------------------------
check('hygiene: control characters detected', () => {
  assert.ok(checkHygiene('x\x01y').includes('Found raw non-printable control characters'));
});

check('hygiene: multi-char shell escapes flagged, regex/escape sequences exempt', () => {
  assert.ok(checkHygiene('make\\install').some((i) => i.includes('shell escaping'))); // slopgate-ignore: intentional artifact fixture
  assert.ok(checkHygiene('app\\continue').some((i) => i.includes('shell escaping'))); // slopgate-ignore: intentional artifact fixture
  assert.strictEqual(checkHygiene("WHERE option_name LIKE '\\_transient\\_wsu\\_cf\\_rate\\_%'").length, 0);
  assert.strictEqual(checkHygiene('const re = /\\b(?:foo|bar)\\s+/;').length, 0);
  assert.strictEqual(checkHygiene('const s = "line one\\nline two";').length, 0);
  assert.strictEqual(checkHygiene('use MyPlugin\\Admin\\Settings;').length, 0); // PHP namespaces
});

check('hygiene: real-world legit shapes exempt (SQL LIKE, gettext EOT, escaped backtick)', () => {
  assert.strictEqual(
    checkHygiene("WHERE option_name LIKE '\\_transient\\_wsu\\_cf\\_rate\\_%'").length, 0
  );
  assert.strictEqual(checkHygiene('msgctxt = "\x04plural";').length, 0);
  assert.strictEqual(checkHygiene('docs say to write \\`code\\` escaped').length, 0); // check removed: cannot tell intent
});

// ---- verdict rendering ----------------------------------------------------
check('verdict: mermaid graph + marker rendered', () => {
  const { renderVerdict, VERDICT_MARKER } = require('../src/verdict');
  const md = renderVerdict(vuln, { repo: 'acme/api' });
  assert.ok(md.includes(VERDICT_MARKER));
  assert.ok(md.includes('```mermaid'));
  assert.ok(md.includes('BLOCKED'));
  assert.ok(md.includes('SG-SEC-001'));
});

// ---- CLI contract ----------------------------------------------------------
check('cli: vulnerable diff exits 1, clean exits 0, --json parses', () => {
  const bin = path.join(ROOT, 'bin', 'slopgate.js');
  const blocked = spawnSync('node', [bin, '--diff', path.join(__dirname, 'fixtures/vulnerable.diff')]);
  assert.strictEqual(blocked.status, 1);
  const green = spawnSync('node', [bin, '--diff', path.join(__dirname, 'fixtures/clean.diff')]);
  assert.strictEqual(green.status, 0);
  const jsonRun = spawnSync('node', [bin, '--json', '--diff', path.join(__dirname, 'fixtures/vulnerable.diff')]);
  assert.strictEqual(jsonRun.status, 1);
  const json = JSON.parse(jsonRun.stdout.toString());
  assert.strictEqual(json.slopScore, 90);
});

// ========================== v1.1 hardening checks ==========================

const { resolveDiff } = require('../src/action');
const { globToRegex } = require('../src/config');

const hard = evaluate(read('hardened.diff'));

check('hardened: multi-line SQL / shell=True / except-pass caught via block scan', () => {
  const ids = hard.securityFindings.map((f) => `${f.ruleId}@${f.file}`);
  assert.ok(ids.includes('SG-SEC-001@worker/pipeline.py'), ids.join(', '));
  assert.ok(ids.includes('SG-SEC-004@worker/pipeline.py'));
  assert.ok(ids.includes('SG-SEC-005@worker/pipeline.py'));
});

check('hardened: block-scan findings are attributed to the hunk start (approx)', () => {
  for (const rule of ['SG-SEC-001', 'SG-SEC-004', 'SG-SEC-005']) {
    const f = hard.securityFindings.find((x) => x.ruleId === rule);
    assert.strictEqual(f.approx, true, rule);
    assert.strictEqual(f.line, 10, rule);
  }
});

check('hardened: exact line numbers on per-line findings', () => {
  assert.strictEqual(hard.securityFindings.find((f) => f.ruleId === 'SG-SEC-012').line, 1);
  assert.strictEqual(hard.securityFindings.find((f) => f.ruleId === 'SG-SEC-008').line, 4);
  assert.strictEqual(hard.securityFindings.find((f) => f.ruleId === 'SG-SEC-002').line, 1);
  assert.strictEqual(hard.securityFindings.find((f) => f.ruleId === 'SG-SEC-007').line, 3);
});

check('hardened: while-true / metadata SSRF / AKIA key / torch.load all detected', () => {
  assert.ok(hard.securityFindings.find((f) => f.ruleId === 'SG-SEC-012').title.includes('Busy Loop'));
  assert.ok(hard.securityFindings.find((f) => f.ruleId === 'SG-SEC-008').title.includes('SSRF'));
  assert.ok(hard.securityFindings.find((f) => f.ruleId === 'SG-SEC-002').title.includes('Credential Literal'));
  assert.strictEqual(hard.isGreen, false);
  assert.strictEqual(hard.slopScore, 90);
});

check('vulnerable: findings carry line numbers (db.py SQL at line 5)', () => {
  const f = vuln.securityFindings.find((x) => x.ruleId === 'SG-SEC-001');
  assert.strictEqual(f.line, 5);
});

// ---- context-trap: pre-existing slop must NOT block -----------------------
const trap = evaluate(read('context-trap.diff'));

check('context-trap: context-line slop/markers ignored (old version blocked this)', () => {
  assert.strictEqual(trap.isGreen, true);
  assert.strictEqual(trap.slopScore, 0);
  assert.strictEqual(trap.hygieneIssues.length, 0);
  assert.strictEqual(trap.slopMarkers.length, 0);
});

// ---- test-file bypass regression -------------------------------------------
const bypass = evaluate(read('test-file-bypass.diff'));

check('bypass: src/latest.js and attestation.ts are NOT exempted as test files', () => {
  const ids = bypass.securityFindings.map((f) => `${f.ruleId}@${f.file}`);
  assert.ok(ids.includes('SG-SEC-008@src/latest.js'), ids.join(', '));
  assert.ok(ids.includes('SG-SEC-006@src/attestation.ts'));
  assert.strictEqual(bypass.isGreen, false);
});

// ---- pwn request_target with untrusted checkout in CONTEXT ------------------
const pwn = evaluate(read('pwn-target.diff'));

check('pwn-target: privileged pull_request_target + context head-ref checkout flagged', () => {
  const f = pwn.securityFindings.find((x) => x.ruleId === 'SG-SEC-009');
  assert.ok(f, 'expected SG-SEC-009');
  assert.ok(f.title.includes('pull_request_target'));
  assert.strictEqual(f.line, 1); // per-line pass cannot see the context checkout
  assert.strictEqual(pwn.isGreen, false);
});

// ---- inline suppression ------------------------------------------------------
check('suppression: slopgate-ignore skips the line for shields AND hygiene', () => {
  const diff =
    'diff --git a/app/db.py b/app/db.py\n--- a/app/db.py\n+++ b/app/db.py\n' +
    '+cursor.execute(f"SELECT * FROM u WHERE id = {uid}")  # slopgate-ignore\n' +
    '+eval(req.body.expr)\n' +
    '+make\\_install  # slopgate-ignore\n';
  const res = evaluate(diff);
  assert.strictEqual(res.securityFindings.some((f) => f.ruleId === 'SG-SEC-001'), false);
  assert.strictEqual(res.securityFindings.some((f) => f.ruleId === 'SG-SEC-004'), true);
  assert.strictEqual(res.suppressedCount, 2);
  assert.strictEqual(res.hygieneIssues.length, 0);
});

// ---- config: disable rules, severity bar, ignore paths ----------------------
check('config: minBlockSeverity=HIGH makes MEDIUM findings advisory', () => {
  const diff =
    'diff --git a/timers.js b/timers.js\n--- a/timers.js\n+++ b/timers.js\n' +
    '+setInterval(poll, 1);\n' +
    '+try { x() } catch (e) { return null; }\n';
  const blocked = evaluate(diff);
  assert.strictEqual(blocked.isGreen, false);
  assert.strictEqual(blocked.blockingFindings.length, 2);

  const lenient = evaluate(diff, {
    config: { disable: [], ignorePaths: [], minBlockSeverity: 'HIGH' },
  });
  assert.strictEqual(lenient.securityFindings.length, 2);
  assert.ok(lenient.securityFindings.every((f) => f.advisory));
  assert.strictEqual(lenient.isGreen, true);
  assert.strictEqual(lenient.slopScore, 0);
});

check('config: disable list removes a rule entirely', () => {
  const diff =
    'diff --git a/timers.js b/timers.js\n--- a/timers.js\n+++ b/timers.js\n' + '+setInterval(poll, 1);\n';
  const res = evaluate(diff, { config: { disable: ['SG-SEC-012'], ignorePaths: [], minBlockSeverity: 'MEDIUM' } });
  assert.strictEqual(res.securityFindings.length, 0);
  assert.strictEqual(res.isGreen, true);
});

check('config: ignorePaths globs skip files from scanning', () => {
  const res = evaluate(read('hardened.diff'), {
    config: { disable: [], ignorePaths: [globToRegex('worker/**')], minBlockSeverity: 'MEDIUM' },
  });
  const files = res.securityFindings.map((f) => f.file);
  assert.ok(!files.includes('worker/pipeline.py'), files.join(', '));
  assert.ok(files.includes('jobs/sync.py'));
  assert.strictEqual(res.securityFindings.length, 4);
});

// ---- generated/lockfile skip --------------------------------------------------
check('lockfiles and minified bundles are never scanned', () => {
  const diff =
    'diff --git a/package-lock.json b/package-lock.json\n--- a/package-lock.json\n+++ b/package-lock.json\n' +
    '+    "db_password": "supersecretlongvalue1234567890",\n';
  const res = evaluate(diff);
  assert.strictEqual(res.securityFindings.length, 0);
  assert.strictEqual(res.isGreen, true);
});

// ---- fail-closed diff resolution ---------------------------------------------
check('resolveDiff: returns diff when base ref exists', () => {
  const run = (cmd) => (cmd.includes('diff origin/main...HEAD') ? 'DIFFTEXT' : '');
  assert.strictEqual(resolveDiff('main', run), 'DIFFTEXT');
});

check('resolveDiff: falls back to HEAD~1 when base is missing', () => {
  const run = (cmd) => (cmd.includes('HEAD~1') ? 'DIFF1' : '');
  assert.strictEqual(resolveDiff('main', run), 'DIFF1');
});

check('resolveDiff: returns null (fail closed) when no diff can be computed', () => {
  assert.strictEqual(resolveDiff('main', () => ''), null);
});

// ======================= v1.2 analyzer module checks =======================

const { analyzePythonFiles } = require('../src/analyzers/python-ast');
const { runAnalyzers } = require('../src/analyzers');

check('python-ast: syntax error blocks with exact line', () => {
  const r = analyzePythonFiles([
    { path: 'm.py', content: 'def ok():\n    pass\n\ndef broken(:\n    pass\n', is_test: false },
  ]);
  assert.ok(r.available, r.error);
  const f = r.findings.find((x) => x.ruleId === 'SG-AST-001');
  assert.ok(f, JSON.stringify(r.findings));
  assert.strictEqual(f.line, 4);
});

check('python-ast: while True with nested break is NOT flagged (regex FP cleared)', () => {
  const r = analyzePythonFiles([
    { path: 'm.py', content: 'def poll(x):\n    while True:\n        if x:\n            break\n', is_test: false },
  ]);
  assert.strictEqual(r.findings.filter((f) => f.ruleId === 'SG-SEC-012').length, 0);
});

check('python-ast: while True without break flagged at exact line', () => {
  const r = analyzePythonFiles([
    { path: 'm.py', content: 'def drain():\n    while True:\n        drain_queue()\n', is_test: false },
  ]);
  const f = r.findings.find((x) => x.ruleId === 'SG-SEC-012');
  assert.ok(f, JSON.stringify(r.findings));
  assert.strictEqual(f.line, 2);
});

check('python-ast: multi-line except-pass caught at exact line', () => {
  const r = analyzePythonFiles([
    {
      path: 'h.py',
      content: 'def h(fn):\n    try:\n        fn()\n    except Exception as e:\n        pass\n    return None\n',
      is_test: false,
    },
  ]);
  const f = r.findings.find((x) => x.ruleId === 'SG-SEC-005');
  assert.ok(f, JSON.stringify(r.findings));
  assert.strictEqual(f.line, 4);
  assert.strictEqual(f.via, 'ast');
});

check('python-ast: SG-SEC-005 documented swallow (comment in handler) is LOW', () => {
  const r = analyzePythonFiles([
    {
      path: 'd.py',
      content: 'def h(fn):\n    try:\n        fn()\n    except Exception as e:\n        # already dead; nothing left to report to\n        pass\n    return None\n',
      is_test: false,
    },
  ]);
  const f = r.findings.find((x) => x.ruleId === 'SG-SEC-005');
  assert.ok(f, JSON.stringify(r.findings));
  assert.strictEqual(f.severity, 'LOW');
});

check('python-ast: SG-SEC-005 undocumented except-pass stays MEDIUM', () => {
  const r = analyzePythonFiles([
    {
      path: 'u.py',
      content: 'def h(fn):\n    try:\n        fn()\n    except Exception as e:\n        pass\n    return None\n',
      is_test: false,
    },
  ]);
  const f = r.findings.find((x) => x.ruleId === 'SG-SEC-005');
  assert.ok(f, JSON.stringify(r.findings));
  assert.strictEqual(f.severity, 'MEDIUM');
});

check('python-ast: eval on variable, multi-line shell=True, yaml.load, aliased f-string SQL', () => {
  const r = analyzePythonFiles(
    [
      { path: 'a.py', content: 'def run(u):\n    return eval(u)\n', is_test: false },
      {
        path: 'b.py',
        content: 'import subprocess\ndef sh(cmd):\n    subprocess.run(\n        cmd,\n        shell=True,\n    )\n',
        is_test: false,
      },
      { path: 'c.py', content: 'import yaml\ndef c(s):\n    return yaml.load(s)\n', is_test: false },
      {
        path: 'd.py',
        content: 'def q(conn, uid):\n    sql = f"SELECT * FROM accounts WHERE id = {uid}"\n    return conn.execute(sql)\n',
        is_test: false,
      },
    ].map((f) => f)
  );
  const ids = (rule) => r.findings.filter((f) => f.ruleId === rule);
  assert.strictEqual(ids('SG-SEC-004').filter((f) => f.cwe === 'CWE-94').length, 1);
  assert.strictEqual(ids('SG-SEC-004').filter((f) => f.cwe === 'CWE-78').length, 1);
  assert.strictEqual(ids('SG-SEC-007').length, 1);
  const s1 = ids('SG-SEC-001');
  assert.strictEqual(s1.length, 1);
  assert.strictEqual(s1[0].variant, 'aliased');
  assert.strictEqual(s1[0].line, 3);
});

check('python-ast: secret literal assignment flagged; test files keep shields but not syntax gate', () => {
  const r = analyzePythonFiles([
    { path: 'cfg.py', content: 'AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMIpK7MDENGbPxRfiCYEMulator"\n', is_test: false },
    { path: 'tests/t.py', content: 'def t(u):\n    return eval(u)\n', is_test: true },
  ]);
  assert.strictEqual(r.findings.filter((f) => f.ruleId === 'SG-SEC-002').length, 1);
  assert.strictEqual(r.findings.filter((f) => f.file === 'tests/t.py').length, 0);
});

// ---- engine merge policy ----------------------------------------------------
const whileFpDiff =
  'diff --git a/m.py b/m.py\n--- a/m.py\n+++ b/m.py\n@@ -1,2 +1,4 @@\n def poll(x):\n+    while True:\n+        if x:\n+            break\n';

check('engine: AST merge clears the while-true regex FP, reports depth', () => {
  const res = evaluate(whileFpDiff, {
    files: [{ path: 'm.py', content: 'def poll(x):\n    while True:\n        if x:\n            break\n' }],
  });
  assert.strictEqual(res.securityFindings.filter((f) => f.ruleId === 'SG-SEC-012').length, 0);
  assert.ok(res.analysis.depth.includes('python-ast'), res.analysis.depth);
  assert.strictEqual(res.isGreen, true);
});

check('engine: AST except-pass replaces the regex approx finding (exact line kept)', () => {
  const diff =
    'diff --git a/h.py b/h.py\n--- a/h.py\n+++ b/h.py\n@@ -1,2 +1,6 @@\n def h(fn):\n+    try:\n+        fn()\n+    except Exception as e:\n+        pass\n+    return None\n';
  const res = evaluate(diff, {
    files: [{ path: 'h.py', content: 'def h(fn):\n    try:\n        fn()\n    except Exception as e:\n        pass\n    return None\n' }],
  });
  const s5 = res.securityFindings.filter((f) => f.ruleId === 'SG-SEC-005');
  assert.strictEqual(s5.length, 1, JSON.stringify(s5));
  assert.strictEqual(s5[0].via, 'ast');
  assert.strictEqual(s5[0].line, 4);
});

check('engine: a documented swallow is advisory and does not block the gate', () => {
  const content = 'def h(fn):\n    try:\n        fn()\n    except Exception as e:\n        # already dead; nothing left to report to\n        pass\n    return None\n';
  const diff =
    'diff --git a/d.py b/d.py\n--- a/d.py\n+++ b/d.py\n@@ -1,2 +1,7 @@\n def h(fn):\n+    try:\n+        fn()\n+    except Exception as e:\n+        # already dead; nothing left to report to\n+        pass\n+    return None\n';
  const res = evaluate(diff, {
    files: [{ path: 'd.py', content }],
  });
  const s5 = res.securityFindings.find((f) => f.ruleId === 'SG-SEC-005');
  assert.ok(s5, JSON.stringify(res.securityFindings));
  assert.strictEqual(s5.severity, 'LOW');
  assert.strictEqual(s5.advisory, true);
  assert.strictEqual(res.blockingFindings.length, 0);
  assert.strictEqual(res.isGreen, true);
});

check('engine: eval(user_input) found only via AST; regex-only mode stays silent on it', () => {
  const diff =
    'diff --git a/r.py b/r.py\n--- a/r.py\n+++ b/r.py\n@@ -1,1 +1,2 @@\n def run(u):\n+    return eval(u)\n';
  const withAst = evaluate(diff, { files: [{ path: 'r.py', content: 'def run(u):\n    return eval(u)\n' }] });
  assert.ok(withAst.securityFindings.some((f) => f.ruleId === 'SG-SEC-004' && f.via === 'ast'));
  assert.strictEqual(withAst.isGreen, false);

  const regexOnly = evaluate(diff);
  assert.strictEqual(regexOnly.analysis.depth, 'regex');
  assert.strictEqual(regexOnly.securityFindings.length, 0);
});

check('engine: syntax error in a changed file blocks the gate', () => {
  const diff =
    'diff --git a/bad.py b/bad.py\n--- a/bad.py\n+++ b/bad.py\n@@ -0,0 +1,2 @@\n+def broken(:\n+    pass\n';
  const res = evaluate(diff, { files: [{ path: 'bad.py', content: 'def broken(:\n    pass\n' }] });
  assert.ok(res.securityFindings.some((f) => f.ruleId === 'SG-AST-001'));
  assert.strictEqual(res.isGreen, false);
  assert.strictEqual(res.slopScore, 90);
});

// ---- external analyzer modules ----------------------------------------------
const extConfig = (cmd, extra = {}) => ({
  disable: [],
  ignorePaths: [],
  minBlockSeverity: 'MEDIUM',
  analyzers: { pythonAst: false, external: [{ id: 'probe', cmd, ...extra }] },
});

check('external: failing command emits a finding, passing command does not', () => {
  const diff =
    'diff --git a/x.py b/x.py\n--- a/x.py\n+++ b/x.py\n@@ -0,0 +1,1 @@\n+x = 1\n';
  const bad = evaluate(diff, { files: [{ path: 'x.py', content: 'x = 1\n' }], config: extConfig('exit 1') });
  const f = bad.securityFindings.find((r) => r.ruleId === 'SG-EXT-PROBE');
  assert.ok(f, JSON.stringify(bad.analysis.ran));
  assert.strictEqual(f.severity, 'HIGH');
  assert.ok(bad.analysis.depth.includes('external:probe'));

  const good = evaluate(diff, { files: [{ path: 'x.py', content: 'x = 1\n' }], config: extConfig('exit 0') });
  assert.strictEqual(good.securityFindings.length, 0);
  assert.ok(good.analysis.ran[0].available);
});

check('external: "when" gate skips the tool when its repo file is absent', () => {
  const diff =
    'diff --git a/x.py b/x.py\n--- a/x.py\n+++ b/x.py\n@@ -0,0 +1,1 @@\n+x = 1\n';
  const res = evaluate(diff, {
    files: [{ path: 'x.py', content: 'x = 1\n' }],
    config: extConfig('exit 1', { when: 'definitely-not-here.lock' }),
  });
  assert.strictEqual(res.securityFindings.length, 0);
  assert.strictEqual(res.analysis.ran[0].available, false);
  assert.strictEqual(res.analysis.ran[0].skipped, true);
});

check('runAnalyzers: pythonAst=false disables the AST module', () => {
  const res = runAnalyzers([{ path: 'm.py', content: 'def broken(:\n', is_test: false }], {
    analyzers: { pythonAst: false, external: [] },
  });
  assert.strictEqual(res.findings.length, 0);
  assert.strictEqual(res.ran.length, 0);
});

// ======================= v1.3 import-graph reachability =====================

const os = require('os');
const fs = require('fs');
const { buildImportGraph, analyzeReachability, extractPhpSymbols } = require('../src/analyzers/import-graph');

const graphRepo = fs.mkdtempSync(path.join(os.tmpdir(), 'sg-graph-'));
fs.mkdirSync(path.join(graphRepo, 'app'), { recursive: true });
fs.mkdirSync(path.join(graphRepo, 'scripts'), { recursive: true });
fs.mkdirSync(path.join(graphRepo, 'web'), { recursive: true });
fs.writeFileSync(
  path.join(graphRepo, 'app/main.py'),
  'from app.db import fetch_user\nfrom app.vector import upsert\n\n@app.post("/chat")\ndef chat():\n    return fetch_user(1)\n'
);
fs.writeFileSync(
  path.join(graphRepo, 'app/db.py'),
  'def fetch_user(uid):\n    cursor.execute(f"SELECT * FROM users WHERE id = %s", [uid])\n'
);
fs.writeFileSync(path.join(graphRepo, 'app/vector.py'), 'from qdrant_client import QdrantClient\n\ndef upsert(v):\n    pass\n');
fs.writeFileSync(path.join(graphRepo, 'app/util.py'), 'def helper():\n    return 42\n');
fs.writeFileSync(
  path.join(graphRepo, 'scripts/tool.py'),
  'from app.util import helper\n\nif __name__ == "__main__":\n    helper()\n'
);
fs.writeFileSync(
  path.join(graphRepo, 'web/server.js'),
  "import { getUser } from './store.js';\n\napp.listen(3000);\n"
);
fs.writeFileSync(path.join(graphRepo, 'web/store.js'), 'export function getUser(id) {\n  return collection.find({ id });\n}\n');

check('graph: nodes, edges, entrypoints and sinks detected', () => {
  const g = buildImportGraph(graphRepo, { analyzers: {}, ignorePaths: [] });
  assert.strictEqual(g.nodes.size, 7);
  assert.deepStrictEqual(g.edges.get('app/main.py').sort(), ['app/db.py', 'app/vector.py']);
  assert.deepStrictEqual(g.edges.get('scripts/tool.py'), ['app/util.py']);
  assert.deepStrictEqual(g.edges.get('web/server.js'), ['web/store.js']);
  assert.deepStrictEqual([...g.entrypoints].sort(), ['app/main.py', 'scripts/tool.py', 'web/server.js']);
  assert.deepStrictEqual([...g.sinks].sort(), ['app/db.py', 'app/vector.py', 'web/store.js']);
});

check('graph: finding in db.py chains to main.py entrypoint (real hops)', () => {
  const g = buildImportGraph(graphRepo, { analyzers: {}, ignorePaths: [] });
  const res = analyzeReachability(
    g,
    ['app/db.py'],
    [{ ruleId: 'SG-SEC-001', file: 'app/db.py', line: 2 }]
  );
  assert.strictEqual(res.applicable, true);
  assert.strictEqual(res.chains.length, 1);
  assert.strictEqual(res.chains[0].entrypoint, 'app/main.py');
  assert.strictEqual(res.chains[0].entrypointHops, 1);
  assert.strictEqual(res.chains[0].sink, 'app/db.py');
  assert.strictEqual(res.chains[0].sinkHops, 0);
  // symbol-level upgrade: route function -> finding function
  assert.deepStrictEqual(res.chains[0].symbolPath, ['chat() app/main.py:5', 'fetch_user() app/db.py:1']);
});

check('graph: reachable-but-no-sink file produces no chain (util.py orphan chain)', () => {
  const g = buildImportGraph(graphRepo, { analyzers: {}, ignorePaths: [] });
  const res = analyzeReachability(
    g,
    ['app/util.py'],
    [{ ruleId: 'SG-SEC-005', file: 'app/util.py', line: 1 }]
  );
  assert.strictEqual(res.applicable, true);
  assert.strictEqual(res.chains.length, 0);
});

check('engine: import graph proves entrypoint->finding->sink chain, upgrades blast radius', () => {
  const diff =
    'diff --git a/app/db.py b/app/db.py\n--- a/app/db.py\n+++ b/app/db.py\n@@ -1,2 +1,3 @@\n def fetch_user(uid):\n+    cursor.execute(f"SELECT * FROM users WHERE id = {uid}")\n';
  const res = evaluate(diff, {
    repoRoot: graphRepo,
    files: [{ path: 'app/db.py', content: fs.readFileSync(path.join(graphRepo, 'app/db.py'), 'utf-8') }],
  });
  assert.strictEqual(res.blastRadius.reachabilityMethod, 'import-graph');
  assert.strictEqual(res.blastRadius.crossLayerReachability, true);
  assert.ok(res.blastRadius.chains[0].entrypoint.startsWith('app/main.py'));
  assert.ok(res.blastRadius.reachabilitySummary.includes('call graph'));
  assert.ok(res.blastRadius.reachabilitySummary.includes('chat()'));

  const { renderVerdict } = require('../src/verdict');
  const md = renderVerdict(res, { repo: 'acme/api' });
  assert.ok(md.includes('chat() app/main.py:5'), 'chain nodes missing from mermaid');
  assert.ok(md.includes('sink: app/db.py'));
});

check('engine: graph-applicable but chainless finding stays confined (authoritative downgrade note)', () => {
  const diff =
    'diff --git a/app/util.py b/app/util.py\n--- a/app/util.py\n+++ b/app/util.py\n@@ -1,1 +1,2 @@\n def helper():\n+    try:\n+        pass\n+    except Exception: pass\n';
  const res = evaluate(diff, { repoRoot: graphRepo, files: [{ path: 'app/util.py', content: 'def helper():\n    try:\n        pass\n    except Exception: pass\n' }] });
  assert.strictEqual(res.securityFindings.some((f) => f.ruleId === 'SG-SEC-005'), true);
  assert.strictEqual(res.blastRadius.crossLayerReachability, false);
  assert.strictEqual(res.blastRadius.reachabilityMethod, 'heuristic');
  assert.ok(res.blastRadius.reachabilitySummary.includes('import graph verified'));
});

check('engine: foreign repoRoot -> graph not applicable, heuristic untouched', () => {
  const empty = fs.mkdtempSync(path.join(os.tmpdir(), 'sg-empty-'));
  const diff =
    'diff --git a/app/db.py b/app/db.py\n--- a/app/db.py\n+++ b/app/db.py\n@@ -1,2 +1,3 @@\n def fetch_user(uid):\n+    cursor.execute(f"SELECT * FROM users WHERE id = {uid}")\n';
  const res = evaluate(diff, { repoRoot: empty, files: [{ path: 'app/db.py', content: 'x\n' }] });
  assert.strictEqual(res.blastRadius.reachabilityMethod, 'heuristic');
  assert.strictEqual(res.blastRadius.crossLayerReachability, false);
  fs.rmSync(empty, { recursive: true, force: true });
});

check('engine: importGraph=false disables the module entirely', () => {
  const diff =
    'diff --git a/app/db.py b/app/db.py\n--- a/app/db.py\n+++ b/app/db.py\n@@ -1,2 +1,3 @@\n def fetch_user(uid):\n+    cursor.execute(f"SELECT * FROM users WHERE id = {uid}")\n';
  const res = evaluate(diff, {
    repoRoot: graphRepo,
    files: [{ path: 'app/db.py', content: fs.readFileSync(path.join(graphRepo, 'app/db.py'), 'utf-8') }],
    config: { disable: [], ignorePaths: [], minBlockSeverity: 'MEDIUM', analyzers: { importGraph: false } },
  });
  assert.strictEqual(res.analysis.importGraph.method, 'unavailable');
  assert.strictEqual(res.blastRadius.reachabilityMethod, 'heuristic');
});

fs.rmSync(graphRepo, { recursive: true, force: true });

// ============================= v1.4 checks ==================================

const { buildSarif } = require('../src/sarif');

check('sarif: valid 2.1.0 structure, rules deduped, levels mapped, lines present', () => {
  const sarif = buildSarif(vuln);
  assert.strictEqual(sarif.version, '2.1.0');
  const run = sarif.runs[0];
  assert.strictEqual(run.tool.driver.name, 'slopgate');
  assert.strictEqual(run.results.length, vuln.securityFindings.length);
  assert.strictEqual(run.tool.driver.rules.length, 12); // one per shield
  const sql = run.results.find((r) => r.ruleId === 'SG-SEC-001');
  assert.strictEqual(sql.level, 'error');
  assert.strictEqual(sql.locations[0].physicalLocation.artifactLocation.uri, 'app/db.py');
  assert.strictEqual(sql.locations[0].physicalLocation.region.startLine, 5);
  assert.ok(sql.partialFingerprints.slopgateFinding.length > 0);
});

check('sarif: advisory findings become note level', () => {
  const diff =
    'diff --git a/timers.js b/timers.js\n--- a/timers.js\n+++ b/timers.js\n' + '+setInterval(poll, 1);\n';
  const lenient = evaluate(diff, { config: { disable: [], ignorePaths: [], minBlockSeverity: 'HIGH' } });
  const sarif = buildSarif(lenient);
  assert.strictEqual(sarif.runs[0].results[0].level, 'note');
});

check('python-ast: one-hop taint flagged with sink-specific CWEs', () => {
  const r = analyzePythonFiles([
    { path: 't1.py', content: 'def run(req):\n    cmd = req.args.get("c")\n    os.system(cmd)\n', is_test: false },
    {
      path: 't2.py',
      content: 'def q(request):\n    uid = request.args.get("id")\n    cursor.execute("SELECT * FROM t WHERE id = " + uid)\n',
      is_test: false,
    },
    { path: 't3.py', content: 'def safe(x):\n    cmd = "ls " + x\n    os.system(cmd)\n', is_test: false },
  ]);
  const t = r.findings.filter((f) => f.ruleId === 'SG-TAINT-001');
  assert.strictEqual(t.length, 2, JSON.stringify(r.findings));
  assert.ok(t.some((f) => f.cwe === 'CWE-78' && f.line === 3));
  assert.ok(t.some((f) => f.cwe === 'CWE-89'));
});

const phpRepo = fs.mkdtempSync(path.join(os.tmpdir(), 'sg-php-'));
fs.mkdirSync(path.join(phpRepo, 'includes'), { recursive: true });
fs.mkdirSync(path.join(phpRepo, 'src/Admin'), { recursive: true });
fs.writeFileSync(phpRepo + '/composer.json', JSON.stringify({ autoload: { 'psr-4': { 'MyPlugin\\': 'src/' } } }));
fs.writeFileSync(
  path.join(phpRepo, 'my-plugin.php'),
  "<?php\n/**\n * Plugin Name: My Plugin\n */\nrequire_once plugin_dir_path( __FILE__ ) . 'includes/class-db.php';\nuse MyPlugin\\Admin\\Settings;\nnew Settings();\n"
);
fs.writeFileSync(
  path.join(phpRepo, 'includes/class-db.php'),
  "<?php\nclass DB {\n  public function all() {\n    global $wpdb;\n    return $wpdb->get_results( 'SELECT 1' );\n  }\n}\n"
);
fs.writeFileSync(
  path.join(phpRepo, 'src/Admin/Settings.php'),
  "<?php\nnamespace MyPlugin\\Admin;\nclass Settings {\n  public function __construct() {\n    add_action( 'init', [ $this, 'boot' ] );\n  }\n  public function boot() {\n    $this->render_report( 'x' );\n  }\n  public function render_report( $x ) {\n    global $wpdb;\n    return $wpdb->get_results( 'SELECT 1' );\n  }\n}\n"
);

check('php graph: psr-4 use + require literal edges, WP entrypoint, wpdb sink, theme-include skipped', () => {
  const g = buildImportGraph(phpRepo, { analyzers: {}, ignorePaths: [] });
  assert.ok(g.nodes.has('my-plugin.php'));
  assert.deepStrictEqual(g.edges.get('my-plugin.php').sort(), ['includes/class-db.php', 'src/Admin/Settings.php']);
  assert.deepStrictEqual(g.edges.get('src/Admin/Settings.php'), []);
  assert.deepStrictEqual([...g.entrypoints], ['my-plugin.php']);
  assert.deepStrictEqual([...g.sinks].sort(), ['includes/class-db.php', 'src/Admin/Settings.php']);

  const res = analyzeReachability(g, ['includes/class-db.php'], [
    { ruleId: 'SG-SEC-001', file: 'includes/class-db.php', line: 5 },
  ]);
  assert.strictEqual(res.chains.length, 1);
  assert.strictEqual(res.chains[0].entrypoint, 'my-plugin.php');
});

check('php symbols: add_action hook is the entrypoint; boot -> render_report call chain', () => {
  const g = buildImportGraph(phpRepo, { analyzers: {}, ignorePaths: [] });
  const res = analyzeReachability(g, ['src/Admin/Settings.php'], [
    { ruleId: 'SG-SEC-001', file: 'src/Admin/Settings.php', line: 12 },
  ]);
  assert.strictEqual(res.chains.length, 1, JSON.stringify(res.chains));
  const sp = res.chains[0].symbolPath;
  assert.ok(Array.isArray(sp), 'missing symbolPath');
  assert.ok(sp[0].startsWith('boot() '), sp.join(' -> '));
  assert.ok(sp[1].startsWith('render_report() '), sp.join(' -> '));
});

check('sarif: structural validation (schema, levels, rule refs, regions)', () => {
  const sarif = buildSarif(vuln);
  const levels = new Set(['error', 'warning', 'note', 'none']);
  const ruleIds = new Set(sarif.runs[0].tool.driver.rules.map((r) => r.id));
  assert.strictEqual(sarif.$schema, 'https://json.schemastore.org/sarif-2.1.0.json');
  for (const r of sarif.runs[0].results) {
    assert.ok(levels.has(r.level), `bad level ${r.level}`);
    assert.ok(ruleIds.has(r.ruleId), `unknown rule ${r.ruleId}`);
    const loc = r.locations[0].physicalLocation;
    assert.ok(loc.artifactLocation.uri.length > 0);
    assert.ok(Number.isInteger(loc.region.startLine));
    assert.ok(r.message.text.length > 0);
    assert.ok(r.partialFingerprints.slopgateFinding.length > 0);
  }
});

fs.rmSync(phpRepo, { recursive: true, force: true });

// ============================= v1.6 checks ==================================

check('shields: PHP superglobal SQL and shell shapes', () => {
  const diff =
    'diff --git a/includes/api.php b/includes/api.php\n--- a/includes/api.php\n+++ b/includes/api.php\n' +
    "@@ -0,0 +1,2 @@\n" +
    "+$wpdb->query( \"SELECT * FROM wp_t WHERE x = '{$_GET['q']}'\" );\n" +
    "+shell_exec( 'ping ' . $_GET['h'] );\n";
  const r = evaluate(diff);
  const ids = r.securityFindings.map((f) => `${f.ruleId}@${f.file}:${f.line}`);
  assert.ok(ids.includes('SG-SEC-001@includes/api.php:1'), ids.join(', '));
  assert.ok(ids.includes('SG-SEC-004@includes/api.php:2'), ids.join(', '));
  assert.strictEqual(r.securityFindings.find((f) => f.ruleId === 'SG-SEC-004').cwe, 'CWE-78');
});

const php16 = fs.mkdtempSync(path.join(os.tmpdir(), 'sg-php16-'));
fs.writeFileSync(php16 + '/composer.json', JSON.stringify({ autoload: { 'psr-4': { 'P\\': './' } } }));
fs.writeFileSync(
  path.join(php16, 'Handler.php'),
  "<?php\nnamespace P;\nclass Handler {\n  public function init() {\n    add_action( 'init', array( $this, 'handle' ) );\n  }\n  public function handle() {\n    $repo = new Repo();\n    $repo->save( 'x' );\n  }\n}\n"
);
fs.writeFileSync(
  path.join(php16, 'Repo.php'),
  "<?php\nnamespace P;\nclass Repo {\n  public function save( $x ) {\n    global $wpdb;\n    $wpdb->query( \"INSERT INTO t VALUES ('$x')\" );\n  }\n}\n"
);

check('php v1.6: hook entrypoint -> new -> cross-file method chain', () => {
  const g = buildImportGraph(php16, { analyzers: {}, ignorePaths: [] });
  const res = analyzeReachability(g, ['Repo.php'], [{ ruleId: 'SG-SEC-001', file: 'Repo.php', line: 5 }]);
  assert.strictEqual(res.chains.length, 1, JSON.stringify(res.chains));
  const sp = res.chains[0].symbolPath;
  assert.ok(sp, 'missing symbolPath');
  assert.ok(sp[0].startsWith('handle() Handler.php:'), sp.join(' -> '));
  assert.ok(sp[1].startsWith('save() Repo.php:'), sp.join(' -> '));
  assert.strictEqual(res.chains[0].viaSymbol, true);
});

check('php v1.6: cross-line superglobal taint within a method (SG-TAINT-002)', () => {
  fs.writeFileSync(
    path.join(php16, 'Legacy.php'),
    "<?php\nnamespace P;\nclass Legacy {\n  public function listing() {\n    $id = $_GET['id'];\n    global $wpdb;\n    return $wpdb->get_results( \"SELECT * FROM t WHERE id = $id\" );\n  }\n}\n"
  );
  const g = buildImportGraph(php16, { analyzers: {}, ignorePaths: [] });
  assert.strictEqual(g.findings.length, 1, JSON.stringify(g.findings));
  assert.strictEqual(g.findings[0].ruleId, 'SG-TAINT-002');
  assert.strictEqual(g.findings[0].cwe, 'CWE-89');
  assert.strictEqual(g.findings[0].line, 7);

  // and it blocks through the engine
  const diff =
    'diff --git a/Legacy.php b/Legacy.php\n--- a/Legacy.php\n+++ b/Legacy.php\n@@ -3,2 +3,4 @@\n class Legacy {\n+  public function listing() {\n+    $id = $_GET[\'id\'];\n';
  const res = evaluate(diff, {
    repoRoot: php16,
    files: [{ path: 'Legacy.php', content: fs.readFileSync(path.join(php16, 'Legacy.php'), 'utf-8') }],
  });
  assert.ok(res.securityFindings.some((f) => f.ruleId === 'SG-TAINT-002' && f.via === 'ast'));
  assert.strictEqual(res.isGreen, false);
});

fs.rmSync(php16, { recursive: true, force: true });

// ============================= v1.7 checks ==================================

const { analyzeJsFiles, available: jsAstAvailable } = require('../src/analyzers/js-ast');

check('js-ast: parser available from vendor/, TS syntax parses', () => {
  assert.ok(jsAstAvailable(), 'vendored @babel/parser not loadable');
  const r = analyzeJsFiles([{ path: 'x.ts', content: 'const n: number = 1;\nexport const f = (a: string): string => a;\n', is_test: false }]);
  assert.ok(r.available);
  assert.strictEqual(r.findings.length, 0);
});

check('js-ast: syntax error blocks with exact line (SG-AST-002)', () => {
  const r = analyzeJsFiles([{ path: 'broken.js', content: 'const ok = 1;\nfunction broken(: {}\n', is_test: false }]);
  const f = r.findings.find((x) => x.ruleId === 'SG-AST-002');
  assert.ok(f, JSON.stringify(r.findings));
  assert.strictEqual(f.line, 2);
});

check('js-ast: while(true) with nested-break cleared; empty catch and eval caught', () => {
  const content =
    'function poll(x) {\n  while (true) {\n    if (x) break;\n  }\n}\n' +
    'function handler() {\n  try { risky(); } catch (e) {}\n  eval(userInput);\n}\n';
  const r = analyzeJsFiles([{ path: 'm.js', content, is_test: false }]);
  assert.strictEqual(r.findings.filter((f) => f.ruleId === 'SG-SEC-012').length, 0);
  const s5 = r.findings.filter((f) => f.ruleId === 'SG-SEC-005');
  assert.strictEqual(s5.length, 1);
  assert.strictEqual(s5[0].line, 7);
  const s4 = r.findings.filter((f) => f.ruleId === 'SG-SEC-004');
  assert.strictEqual(s4.length, 1);
  assert.strictEqual(s4[0].line, 8);
});

check('js-ast: SG-SEC-005 catch with an explanatory comment is documented (LOW)', () => {
  const r = analyzeJsFiles([
    { path: 'b.js', content: 'function f() {\n  try { g(); } catch { /* already dead */ }\n}\n', is_test: false },
  ]);
  const x = r.findings.find((q) => q.ruleId === 'SG-SEC-005');
  assert.ok(x, JSON.stringify(r.findings));
  assert.strictEqual(x.severity, 'LOW');
});

check('js-ast: SG-SEC-005 bare empty catch stays MEDIUM', () => {
  const r = analyzeJsFiles([{ path: 'a.js', content: 'function f() { try { g(); } catch {} }\n', is_test: false }]);
  const x = r.findings.find((q) => q.ruleId === 'SG-SEC-005');
  assert.ok(x, JSON.stringify(r.findings));
  assert.strictEqual(x.severity, 'MEDIUM');
});

check('js-ast: test files keep syntax gate, skip shields', () => {
  const r = analyzeJsFiles([{ path: 'tests/x.test.js', content: 'eval(input);\n', is_test: true }]);
  assert.strictEqual(r.findings.length, 0);
});

const jsRepo = fs.mkdtempSync(path.join(os.tmpdir(), 'sg-js-'));
fs.writeFileSync(
  path.join(jsRepo, 'api.js'),
  "import { MessageRepository } from './repo.js';\n\nexport function GET() {\n  const repo = new MessageRepository();\n  return repo.create({ ok: 1 });\n}\n"
);
fs.writeFileSync(
  path.join(jsRepo, 'repo.js'),
  "export class MessageRepository {\n  create(data) {\n    return db.execute('INSERT', data);\n  }\n}\n"
);

check('js graph: import + new + call chain across files', () => {
  const g = buildImportGraph(jsRepo, { analyzers: {}, ignorePaths: [] });
  const res = analyzeReachability(g, ['repo.js'], [{ ruleId: 'SG-SEC-001', file: 'repo.js', line: 3 }]);
  assert.strictEqual(res.chains.length, 1, JSON.stringify(res.chains));
  const sp = res.chains[0].symbolPath;
  assert.ok(sp, 'missing symbolPath');
  assert.ok(sp[0].startsWith('GET() api.js:'), sp.join(' -> '));
  assert.ok(sp[1].startsWith('create() repo.js:'), sp.join(' -> '));
});

check('engine: regex + AST see the same empty catch exactly once', () => {
  const diff =
    'diff --git a/h.js b/h.js\n--- a/h.js\n+++ b/h.js\n@@ -1,1 +1,3 @@\n function h() {\n+  try { risky(); } catch (e) {}\n }\n';
  const res = evaluate(diff, {
    repoRoot: jsRepo,
    files: [{ path: 'h.js', content: 'function h() {\n  try { risky(); } catch (e) {}\n}\n' }],
  });
  const s5 = res.securityFindings.filter((f) => f.ruleId === 'SG-SEC-005');
  assert.strictEqual(s5.length, 1, JSON.stringify(s5));
  assert.strictEqual(s5[0].line, 2);
  assert.ok(res.analysis.depth.includes('js-ast'), res.analysis.depth);
});

check('analyzers: ignorePaths exempts files from AST analysis (vendored-gate pattern)', () => {
  const files = [{ path: 'tools/slopgate/src/action.js', content: 'function h() {\n  try { r(); } catch (e) {}\n}\n' }];
  const raw = runAnalyzers(files, { analyzers: {}, ignorePaths: [] });
  assert.strictEqual(raw.findings.length, 1);
  const exempt = runAnalyzers(files, { analyzers: {}, ignorePaths: [globToRegex('tools/**')] });
  assert.strictEqual(exempt.findings.length, 0);
});

fs.rmSync(jsRepo, { recursive: true, force: true });

// ============================= v1.8 checks ==================================
// CWE-699 gap closure: SG-SEC-013..018 + PHP LFI/file taint sinks.

check('v1.8 fixture: all six new shields trip, blocked', () => {
  const r = evaluate(read('extended-cwe.diff'));
  assert.strictEqual(r.isGreen, false, JSON.stringify(r.securityFindings));
  const count = (id) => r.securityFindings.filter((f) => f.ruleId === id).length;
  assert.strictEqual(count('SG-SEC-013'), 3, JSON.stringify(r.securityFindings));
  assert.strictEqual(count('SG-SEC-014'), 1);
  assert.strictEqual(count('SG-SEC-015'), 1);
  assert.strictEqual(count('SG-SEC-016'), 1);
  assert.strictEqual(count('SG-SEC-017'), 1);
  assert.strictEqual(count('SG-SEC-018'), 1);
});

check('v1.8: zip-slip variant, LFI cwe, debug severity are attributed', () => {
  const r = evaluate(read('extended-cwe.diff'));
  const zip = r.securityFindings.find((f) => f.ruleId === 'SG-SEC-013' && f.variant === 'zip-slip');
  assert.ok(zip && zip.file === 'utils/export.py' && zip.line === 3, JSON.stringify(zip));
  const block = r.securityFindings.find((f) => f.ruleId === 'SG-SEC-013' && f.variant === 'traversal' && f.approx);
  assert.ok(block && block.file === 'routes/download.js', JSON.stringify(block));
  const debug = r.securityFindings.find((f) => f.ruleId === 'SG-SEC-018');
  assert.strictEqual(debug.severity, 'MEDIUM');
  assert.strictEqual(r.securityFindings.find((f) => f.ruleId === 'SG-SEC-014').cwe, 'CWE-327');
  assert.strictEqual(r.securityFindings.find((f) => f.ruleId === 'SG-SEC-015').cwe, 'CWE-338');
  assert.strictEqual(r.securityFindings.find((f) => f.ruleId === 'SG-SEC-016').cwe, 'CWE-601');
  assert.strictEqual(r.securityFindings.find((f) => f.ruleId === 'SG-SEC-017').cwe, 'CWE-347');
});

check('v1.8: checksum md5, Math.random ids, safe redirect, alg-pinned verify stay green', () => {
  const lines = [
    ['fp.py', '+etag = hashlib.md5(payload).hexdigest()'],
    ['fp.js', '+const id = Math.random().toString(36).slice(2);'],
    ['fp.php', '+wp_safe_redirect( $url );'],
    ['fp.js', "+jwt.verify(token, KEY, { algorithms: ['RS256'] })"],
    ['fp.js', '+fs.readFile(configPath, cb)'],
    ['fp.py', '+app.run(host, port)'],
    ['fp.php', "+require_once __DIR__ . '/vendor/autoload.php';"],
    ['fp.py', '+open(local_path)'],
    ['fp.php', '+header( "Location: $fallback" );'],
  ];
  for (const [file, line] of lines) {
    const diff =
      `diff --git a/${file} b/${file}\n--- a/${file}\n+++ b/${file}\n@@ -1,1 +1,2 @@\n` + line + '\n';
    const r = evaluate(diff);
    const hit = r.securityFindings.filter((f) => f.ruleId >= 'SG-SEC-013');
    assert.strictEqual(hit.length, 0, `${line} -> ${JSON.stringify(hit)}`);
  }
});

check('v1.8: multi-line jwt.verify without algorithms caught by block pass', () => {
  const diff =
    'diff --git a/mw/auth.js b/mw/auth.js\n--- a/mw/auth.js\n+++ b/mw/auth.js\n@@ -1,1 +1,5 @@\n function requireUser(req) {\n' +
    '+  const payload = jwt.verify(\n+    req.cookies.session,\n+    process.env.JWT_SECRET\n+  );\n';
  const r = evaluate(diff);
  const f = r.securityFindings.find((x) => x.ruleId === 'SG-SEC-017');
  assert.ok(f, JSON.stringify(r.securityFindings));
  assert.strictEqual(f.variant, 'no-alg');
});

check('v1.8: PHP superglobal include caught line-level and via taint (CWE-98)', () => {
  const diff =
    'diff --git a/inc/loader.php b/inc/loader.php\n--- a/inc/loader.php\n+++ b/inc/loader.php\n@@ -1,1 +1,2 @@\n <?php\n' +
    "+include $_GET['template'];\n";
  const r = evaluate(diff);
  const f = r.securityFindings.find((x) => x.ruleId === 'SG-SEC-013');
  assert.ok(f && f.cwe === 'CWE-98', JSON.stringify(r.securityFindings));

  const t = extractPhpSymbols(
    "<?php\nclass Loader {\n  public function render() {\n    $page = $_GET['template'];\n    include $page;\n  }\n}\n"
  );
  assert.strictEqual(t.taintFindings.length, 1, JSON.stringify(t.taintFindings));
  assert.strictEqual(t.taintFindings[0].cwe, 'CWE-98');
  assert.strictEqual(t.taintFindings[0].line, 5);
});

check('v1.8: PHP file sinks in taint map (upload, read, delete), benign requires untouched', () => {
  const t = extractPhpSymbols(
    "<?php\nclass Up {\n  public function store() { $name = $_FILES['f']['name']; move_uploaded_file( $_FILES['f']['tmp_name'], $name ); }\n  public function peek() { $p = $_GET['log']; echo file_get_contents( $p ); }\n  public function boot() { require_once plugin_dir_path( __FILE__ ) . 'inc/helpers.php'; }\n}\n"
  );
  const cwes = t.taintFindings.map((f) => f.cwe).sort();
  assert.ok(cwes.includes('CWE-434') && cwes.includes('CWE-22'), JSON.stringify(t.taintFindings));
  assert.strictEqual(t.taintFindings.length, 2);
});

const v18 = fs.mkdtempSync(path.join(os.tmpdir(), 'sg-v18-'));
fs.writeFileSync(v18 + '/composer.json', JSON.stringify({ autoload: { 'psr-4': { 'V\\': './' } } }));
fs.writeFileSync(
  path.join(v18, 'helpers.php'),
  "<?php\nclass V_Logger {\n  public static function write( $x ) {\n    global $wpdb;\n    $wpdb->query( \"INSERT INTO v_log VALUES ('$x')\" );\n  }\n}\n"
);
fs.writeFileSync(
  path.join(v18, 'Panel.php'),
  "<?php\nnamespace V;\nrequire_once __DIR__ . 'helpers.php';\nclass Panel {\n  public function view() {\n    add_action( 'template_redirect', array( $this, 'redirect_out' ) );\n  }\n  public function redirect_out() {\n    $this->render_template();\n  }\n  private function render_template() {\n    $tpl = $_GET['template'];\n    include $tpl;\n  }\n}\n"
);

check('v1.8: hook entrypoint reaches LFI sink via symbol chain', () => {
  const g = buildImportGraph(v18, { analyzers: {}, ignorePaths: [] });
  assert.ok(g.findings.some((f) => f.ruleId === 'SG-TAINT-002' && f.cwe === 'CWE-98'), JSON.stringify(g.findings));
  const res = analyzeReachability(g, ['Panel.php'], [{ ruleId: 'SG-TAINT-002', file: 'Panel.php', line: 13 }]);
  assert.strictEqual(res.chains.length, 1, JSON.stringify(res.chains));
  const sp = res.chains[0].symbolPath;
  assert.ok(sp, 'missing symbolPath');
  assert.ok(sp[0].startsWith('redirect_out() Panel.php:'), sp.join(' -> '));
  assert.ok(sp[1].startsWith('render_template() Panel.php:'), sp.join(' -> '));
  assert.ok(res.chains[0].findings.includes('SG-TAINT-002:13'), JSON.stringify(res.chains[0]));
});

check('v1.8: slopgate-ignore on a pre-existing line suppresses AST findings (whole-content registry)', () => {
  const marked = 'function a() {\n  try { r(); } catch (e) {} // slopgate-ignore: legacy swallow\n}\n\nfunction b() {\n  return 1;\n}\n';
  const unmarked = 'function a() {\n  try { r(); } catch (e) {}\n}\n\nfunction b() {\n  return 1;\n}\n';
  // The diff only adds a line inside b(); the catch is pre-existing context
  // the AST pass still reads because it scans whole changed files.
  const diff =
    'diff --git a/legacy.js b/legacy.js\n--- a/legacy.js\n+++ b/legacy.js\n@@ -2,2 +2,3 @@\n function a() {}\n function b() {\n+  return 1;\n';
  const withMark = evaluate(diff, { files: [{ path: 'legacy.js', content: marked }] });
  const noMark = evaluate(diff, { files: [{ path: 'legacy.js', content: unmarked }] });
  const s5 = (r) => r.securityFindings.filter((f) => f.ruleId === 'SG-SEC-005');
  assert.strictEqual(s5(withMark).length, 0, JSON.stringify(s5(withMark)));
  assert.strictEqual(s5(noMark).length, 1, JSON.stringify(s5(noMark)));
});

check('v1.8: top-level PHP taint outside any function span caught at exact line', () => {
  const t = extractPhpSymbols("<?php\n// plugin bootstrap\n$q = $_GET['tpl'];\ninclude $q;\n");
  assert.strictEqual(t.functions.length, 0);
  assert.strictEqual(t.taintFindings.length, 1, JSON.stringify(t.taintFindings));
  assert.strictEqual(t.taintFindings[0].cwe, 'CWE-98');
  assert.strictEqual(t.taintFindings[0].line, 4);
  // and span-local findings are not duplicated by the file-scope pass
  const inFn = extractPhpSymbols("<?php\nclass L {\n  public function r() {\n    $p = $_GET['p'];\n    require $p;\n  }\n}\n");
  assert.strictEqual(inFn.taintFindings.length, 1, JSON.stringify(inFn.taintFindings));
  assert.strictEqual(inFn.taintFindings[0].line, 5);
});

check('v1.9 fixture: all four tier-2 shields trip, blocked', () => {
  const r = evaluate(read('tier2-cwe.diff'));
  assert.strictEqual(r.isGreen, false, JSON.stringify(r.securityFindings));
  const count = (id) => r.securityFindings.filter((f) => f.ruleId === id).length;
  assert.strictEqual(count('SG-SEC-019'), 4, JSON.stringify(r.securityFindings));
  assert.strictEqual(count('SG-SEC-020'), 2);
  assert.strictEqual(count('SG-SEC-021'), 1);
  assert.strictEqual(count('SG-SEC-022'), 1);
  assert.ok(r.securityFindings.filter((f) => f.ruleId >= 'SG-SEC-019').every((f) => f.severity === 'MEDIUM'));
  assert.strictEqual(r.securityFindings.find((f) => f.ruleId === 'SG-SEC-019').cwe, 'CWE-611');
  assert.strictEqual(r.securityFindings.find((f) => f.ruleId === 'SG-SEC-021').cwe, 'CWE-434');
});

check('v1.9: reflection, star, reflect-all cors variants all caught line-level', () => {
  const lines = [
    ['r.js', '+res.header("Access-Control-Allow-Origin", req.headers.origin);'],
    ['r.js', "+app.use(cors({ origin: '*', credentials: true }));"],
    ['r.py', '+CORS_ALLOW_ALL_ORIGINS = True'],
    ['r.php', "+header( 'Access-Control-Allow-Origin: ' . $_SERVER['HTTP_ORIGIN'] );"],
  ];
  for (const [file, line] of lines) {
    const diff =
      `diff --git a/${file} b/${file}\n--- a/${file}\n+++ b/${file}\n@@ -1,1 +1,2 @@\n <?php\n` + line + '\n';
    const r = evaluate(diff);
    assert.ok(r.securityFindings.some((f) => f.ruleId === 'SG-SEC-020'), `${line} not caught`);
  }
});

check('v1.9: multi-line cors wildcard+credentials caught by block pass', () => {
  const diff =
    'diff --git a/app.js b/app.js\n--- a/app.js\n+++ b/app.js\n@@ -1,1 +1,6 @@\n const app = express();\n' +
    '+app.use(\n+  cors({\n+    origin: "*",\n+    credentials: true,\n+  })\n+);\n';
  const r = evaluate(diff);
  const f = r.securityFindings.find((x) => x.ruleId === 'SG-SEC-020');
  assert.ok(f, JSON.stringify(r.securityFindings));
  assert.strictEqual(f.approx, true);
});

check('v1.9 FP battery: allowlisted cors, filtered multer, trusted xml, pinned hosts stay green', () => {
  const lines = [
    ['u.js', '+const upload = multer({ dest: UP, fileFilter: pdfOnly });'],
    ['c.js', '+res.setHeader("Access-Control-Allow-Origin", "https://app.example.com");'],
    ['c.js', '+app.use(cors({ origin: allowlist }));'],
    ['c.js', "+app.use(cors({ origin: '*' }));"],
    ['x.php', '+$doc->loadXML( $schema );'],
    ['x.py', '+tree = ET.parse(local_config)'],
    ['h.py', '+ALLOWED_HOSTS = ["app.example.com", "api.example.com"]'],
  ];
  for (const [file, line] of lines) {
    const diff =
      `diff --git a/${file} b/${file}\n--- a/${file}\n+++ b/${file}\n@@ -1,1 +1,2 @@\n x\n` + line + '\n';
    const r = evaluate(diff);
    const hit = r.securityFindings.filter((f) => f.ruleId >= 'SG-SEC-019');
    assert.strictEqual(hit.length, 0, `${line} -> ${JSON.stringify(hit)}`);
  }
});

fs.rmSync(v18, { recursive: true, force: true });

console.log(`\n${passed} checks passed${process.exitCode ? ' (with failures)' : ''}`);
