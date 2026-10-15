// Bundled JS/TS AST analyzer — real syntax trees via the vendored
// @babel/parser (see vendor/README.md; falls back to the consumer repo's
// own copy when present). Mirrors python-ast.js:
//
//   SG-AST-002  JS/TS file does not parse — instant block, any file
//   SG-SEC-005  empty catch blocks — exact, via AST (supersedes regex)
//   SG-SEC-012  while(true) with no break reachable in THIS loop body
//   SG-SEC-004  eval(...) / new Function(...) on non-literal input
//
// Also extracts the JS symbol layer for the import graph: functions with
// ranges, typed calls (this / var-from-new / imported-object), and route
// names (GET/POST/PUT/DELETE/PATCH, next-style handlers).
//
// Test files keep the syntax gate; shields are exempt, same policy as Python.

const path = require('path');

const ROUTE_NAMES = new Set(['GET', 'POST', 'PUT', 'DELETE', 'PATCH']);

let cachedParser; // { key, parser }
function loadParser(repoRoot = process.cwd()) {
  const key = repoRoot;
  if (cachedParser && cachedParser.key === key) return cachedParser.parser;
  let parser = null;
  try {
    parser = require('../../vendor/@babel/parser');
  } catch {
    try {
      // Fall back to the target repo's own copy when present.
      const { createRequire } = require('module');
      parser = createRequire(path.join(repoRoot, 'package.json'))('@babel/parser');
    } catch {
      parser = null;
    }
  }
  cachedParser = { key, parser };
  return parser;
}

function available(repoRoot) {
  return !!loadParser(repoRoot);
}

function parse(source) {
  return loadParser().parse(source, {
    sourceType: 'unambiguous',
    plugins: ['typescript', 'jsx'],
    attachComment: false,
    errorRecovery: false,
  });
}

// Generic AST walker (babel nodes are plain JSON with .type and .loc).
const SKIP_KEYS = new Set(['loc', 'start', 'end', 'innerComments', 'leadingComments', 'trailingComments', 'extra', 'range']);
function walk(node, cb, parent = null) {
  if (!node || typeof node.type !== 'string') return;
  cb(node, parent);
  for (const key of Object.keys(node)) {
    if (SKIP_KEYS.has(key)) continue;
    const v = node[key];
    if (Array.isArray(v)) {
      for (const x of v) {
        if (x && typeof x === 'object' && typeof x.type === 'string') walk(x, cb, node);
      }
    } else if (v && typeof v === 'object' && typeof v.type === 'string') {
      walk(v, cb, node);
    }
  }
}

function functionName(node, parent) {
  if (node.id && node.id.name) return node.id.name;
  // ClassMethod/ObjectMethod carry their name on .key (their parent is ClassBody)
  if ((node.type === 'ClassMethod' || node.type === 'ObjectMethod') && node.key && node.key.name) {
    return node.key.name;
  }
  if (parent) {
    if (parent.type === 'VariableDeclarator' && parent.id.type === 'Identifier') return parent.id.name;
    if ((parent.type === 'Property' || parent.type === 'ObjectMethod' || parent.type === 'ClassMethod') && parent.key && parent.key.name) {
      return parent.key.name;
    }
    if (parent.type === 'AssignmentExpression' && parent.left.type === 'MemberExpression') {
      return parent.left.property.name;
    }
  }
  return null;
}

function calleeCalls(callee) {
  if (callee.type === 'Identifier') return [{ k: 'fn', n: callee.name }];
  if (callee.type === 'MemberExpression' && !callee.computed && callee.property.type === 'Identifier') {
    if (callee.object.type === 'ThisExpression') return [{ k: 'this', m: callee.property.name }];
    if (callee.object.type === 'Identifier') return [{ k: 'var', v: callee.object.name, m: callee.property.name }];
    return [{ k: 'fn', n: callee.property.name }];
  }
  return [];
}

// Extract functions with spans/calls/varTypes for the symbol layer.
function extractJsSymbols(ast) {
  const fns = [];
  walk(ast, (node, parent) => {
    const isFn =
      node.type === 'FunctionDeclaration' ||
      node.type === 'FunctionExpression' ||
      node.type === 'ArrowFunctionExpression' ||
      node.type === 'ClassMethod' ||
      node.type === 'ObjectMethod';
    if (!isFn) return;
    // Skip the machinery of anonymous inline callbacks: keep named units.
    const name = functionName(node, parent);
    if (!name) return;

    const calls = [];
    const varTypes = {};
    walk(node, (n) => {
      if (n !== node && (n.type === 'FunctionDeclaration' || n.type === 'FunctionExpression' || n.type === 'ArrowFunctionExpression' || n.type === 'ClassMethod')) {
        return; // nested named units get their own entry; their calls are theirs
      }
      if (n.type === 'CallExpression') calls.push(...calleeCalls(n.callee));
      if (n.type === 'VariableDeclarator' && n.id.type === 'Identifier' && n.init && n.init.type === 'NewExpression' && n.init.callee.type === 'Identifier') {
        varTypes[n.id.name] = n.init.callee.name;
      }
    });

    fns.push({
      name,
      line: node.loc ? node.loc.start.line : 1,
      end: node.loc ? node.loc.end.line : 1,
      route: ROUTE_NAMES.has(name),
      calls,
      varTypes,
    });
  });
  // calls walk skips nested function subtrees only via the guard above —
  // dedupe per kind while preserving order.
  return fns;
}

function ownBreak(loopNode) {
  let found = false;
  walk(loopNode.body, (n, parent) => {
    if (found) return;
    if (n.type === 'BreakStatement') {
      // break belongs to the nearest enclosing loop — stop at nested loops
      if (parent && (parent.type === 'WhileStatement' || parent.type === 'DoWhileStatement' || parent.type === 'ForStatement' || parent.type === 'ForOfStatement' || parent.type === 'ForInStatement') && parent !== loopNode) {
        return;
      }
      found = true;
    }
  });
  return found;
}

// files: [{ path, content, is_test }]
// Returns { available, findings, symbolsByFile: Map<path, functions> }
function analyzeJsFiles(files, { repoRoot } = {}) {
  const parser = loadParser(repoRoot);
  if (!parser) return { available: false, error: '@babel/parser not found (vendor/ or target node_modules)' };

  const findings = [];
  const symbolsByFile = new Map();

  for (const file of files) {
    let ast;
    try {
      ast = parse(file.content);
    } catch (err) {
      findings.push({
        ruleId: 'SG-AST-002',
        cwe: 'SYNTAX',
        severity: 'CRITICAL',
        title: 'JS/TS Syntax Error (file does not parse)',
        file: file.path,
        line: (err.loc && err.loc.line) || 1,
        remediation: 'Fix the syntax error; unparseable code must not merge.',
        via: 'ast',
      });
      continue;
    }

    symbolsByFile.set(file.path, extractJsSymbols(ast));
    if (file.is_test) continue; // shields exempt; syntax gate above still ran

    walk(ast, (node) => {
      // SG-SEC-005: empty catch
      if (node.type === 'CatchClause' && node.body && node.body.body.length === 0) {
        findings.push({
          ruleId: 'SG-SEC-005',
          cwe: 'CWE-390',
          severity: 'MEDIUM',
          title: 'Silent Exception Swallowing (Empty Catch)',
          file: file.path,
          line: node.loc.start.line,
          remediation: 'Log or propagate structured exceptions rather than silently masking failures.',
          via: 'ast',
        });
      }
      // SG-SEC-012: while(true) without a break in THIS loop's body
      if ((node.type === 'WhileStatement' || node.type === 'DoWhileStatement') && node.test && node.test.type === 'Literal' && (node.test.value === true || node.test.value === 1)) {
        if (!ownBreak(node)) {
          findings.push({
            ruleId: 'SG-SEC-012',
            cwe: 'CWE-400',
            severity: 'MEDIUM',
            title: 'Unbounded Busy Loop (while true without break)',
            file: file.path,
            line: node.loc.start.line,
            remediation: 'Give every busy loop a break/timeout guard.',
            via: 'ast',
          });
        }
      }
      // SG-SEC-004: eval / new Function on non-literals
      if (node.type === 'CallExpression' && node.callee.type === 'Identifier' && (node.callee.name === 'eval' || node.callee.name === 'Function')) {
        const nonLiteral = node.arguments.length > 0 && node.arguments[0].type !== 'StringLiteral';
        if (nonLiteral) {
          findings.push({
            ruleId: 'SG-SEC-004',
            cwe: 'CWE-94',
            severity: 'CRITICAL',
            title: 'Dynamic Code Execution (eval/Function) on Non-Literal Input',
            file: file.path,
            line: node.loc.start.line,
            remediation: 'Avoid eval() and new Function(); parse and validate structured input instead.',
            via: 'ast',
          });
        }
      }
    });
  }

  return { available: true, findings, symbolsByFile };
}

// Module imports for the symbol layer: ES imports and require() bindings.
// Returns [{ source, names: [localBinding] }].
function extractJsModule(ast) {
  const imports = [];
  walk(ast, (node, parent) => {
    if (node.type === 'ImportDeclaration' && node.source && typeof node.source.value === 'string') {
      imports.push({ source: node.source.value, names: node.specifiers.map((s) => s.local.name) });
    }
    if (
      node.type === 'CallExpression' &&
      node.callee.type === 'Identifier' &&
      node.callee.name === 'require' &&
      node.arguments[0] &&
      node.arguments[0].type === 'StringLiteral'
    ) {
      let name = null;
      if (parent && parent.type === 'VariableDeclarator' && parent.id.type === 'Identifier') name = parent.id.name;
      imports.push({ source: node.arguments[0].value, names: name ? [name] : [] });
    }
  });
  return imports;
}

module.exports = { analyzeJsFiles, available, loadParser, extractJsSymbols, extractJsModule, parse, ROUTE_NAMES };
