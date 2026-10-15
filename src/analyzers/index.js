// Analyzer registry.
//
// An analyzer is an optional, selectable module that inspects the FULL content
// of changed files (not just diff lines) and emits findings in the standard
// schema. Two kinds ship:
//
//   python-ast:  bundled, in-process. Real Python AST via stdlib. Upgrades
//                shield precision (multi-line except:pass, while-True break
//                analysis, eval/shell=True call nodes, f-string SQL through
//                call arguments) and adds syntax-error gating (SG-AST-001).
//   external:    configurable repo tools. Runs a command; a nonzero exit
//                becomes a finding.
//
// Availability is probed, never assumed; everything degrades to regex-only.

const fs = require('fs');
const { spawnSync } = require('child_process');

const { analyzePythonFiles } = require('./python-ast');
const { analyzeJsFiles } = require('./js-ast');
const { runExternalAnalyzers } = require('./external');
const { isTestFile } = require('../parse');

// Run all configured analyzers over changed files.
//   files: full post-change file contents as [{ path, content }], when the provider can read them
//   config.analyzers: { pythonAst, jsAst, external: [...] }
// Returns { findings, ran: [{ id, available, analyzed?, findings, error? }] }
function runAnalyzers(files, config, { repoRoot = process.cwd() } = {}) {
  const analyzersCfg = config.analyzers || {};
  const ran = [];
  let findings = [];

  // ignorePaths means "never scan this path": for every layer, analyzers
  // included (a repo that vendors the linter must exempt the linter).
  const ignored = (p) => (config.ignorePaths || []).some((rx) => rx && rx.test(p));
  const scannable = files.filter((f) => !ignored(f.path));

  if (analyzersCfg.pythonAst !== false && scannable.length > 0) {
    const pyFiles = scannable.filter((f) => /\.py$/i.test(f.path));
    if (pyFiles.length > 0) {
      const res = analyzePythonFiles(
        pyFiles.map((f) => ({ ...f, is_test: isTestFile(f.path) }))
      );
      ran.push({
        id: 'python-ast',
        ...res,
        analyzed: res.available ? pyFiles.map((f) => f.path) : [],
        findings: res.findings?.length || 0,
      });
      if (res.available && res.findings) findings = findings.concat(res.findings);
    }
  }

  if (analyzersCfg.jsAst !== false && scannable.length > 0) {
    const jsFiles = scannable.filter((f) => /\.(m?js|cjs|[jt]sx?)$/i.test(f.path));
    if (jsFiles.length > 0) {
      const res = analyzeJsFiles(
        jsFiles.map((f) => ({ ...f, is_test: isTestFile(f.path) })),
        { repoRoot }
      );
      ran.push({
        id: 'js-ast',
        ...res,
        analyzed: res.available ? jsFiles.map((f) => f.path) : [],
        findings: res.findings?.length || 0,
      });
      if (res.available && res.findings) findings = findings.concat(res.findings);
    }
  }

  const external = analyzersCfg.external || [];
  for (const ext of external) {
    const res = runExternalAnalyzers(ext, { repoRoot });
    ran.push({ id: `external:${ext.id}`, ...res, findings: res.findings?.length || 0 });
    if (res.available && res.findings) findings = findings.concat(res.findings);
  }

  return { findings, ran };
}

// Changed source files a provider can supply. Used by action/CLI to build the
// `files` list for the current diff.
function collectChangedFiles(changedPaths, readFile) {
  const files = [];
  let missing = 0;
  for (const path of changedPaths) {
    const content = readFile(path);
    if (typeof content === 'string') files.push({ path, content });
    else missing++;
  }
  return { files, missing };
}

function fileExists(p) {
  try {
    fs.accessSync(p);
    return true;
  } catch {
    return false;
  }
}

module.exports = { runAnalyzers, collectChangedFiles, fileExists };
