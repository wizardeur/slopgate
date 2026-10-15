// Bundled Python AST analyzer: the reference implementation of the module API.
//
// Spawns python3 (stdlib only) and sends
// changed-file contents as JSON on stdin; receives findings as JSON on stdout.
//
// What it detects that the regex shields cannot, or only approximately:
//   SG-AST-001  file does not parse (SyntaxError): instant block
//   SG-SEC-004  eval()/exec() on non-literals; subprocess/os.system shell
//               execution via CALL NODES (shell=True keyword, any line layout)
//   SG-SEC-005  exception handlers whose body is only pass/continue: exact,
//               any form incl. `except Exception as e:` and multi-line
//   SG-SEC-007  pickle/dill/marshal/shelve loads; yaml.load without a Loader kw
//   SG-SEC-012  `while True` with NO break reachable in THIS loop's body
//               (nested-loop breaks don't count: the regex same-line
//               heuristic both false-positives and false-negatives here)
//   SG-SEC-001  SQL verbs in f-strings passed to execute/query(...) through
//               call arguments, including one-hop `sql = f"..."` aliases
//   SG-SEC-002  assignments of string literals to secret-shaped names
//   SG-SEC-003  functions taking client-identity params with no auth binding
//
// Test files: shields skipped (same policy as regex), syntax check always runs.

const { spawnSync } = require('child_process');

const PY_SCRIPT = String.raw`
import ast, json, sys, re

SQL_VERB = re.compile(r"\b(?:SELECT\s.+\sFROM|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM|DROP\s+(?:TABLE|DATABASE)|ALTER\s+TABLE|TRUNCATE\s+TABLE)\b", re.S | re.I)
SECRET_NAME = re.compile(r"(?:API_?KEY|SECRET|PASSWORD|PASSWD|TOKEN|PRIVATE_?KEY|ACCESS_?KEY)", re.I)
PLACEHOLDER = re.compile(r"example|placeholder|mock|dummy|changeme|xxx|<|\$\{", re.I)
SECRET_VALUE = re.compile(r"sk-|ghp_|gho_|github_pat_|AKIA[0-9A-Z]{16}|eyJ|xox[baprs]-", re.I)
IDENTITY_PARAM = re.compile(r"^(?:username|user_id|owner_id|account_id)$", re.I)
AUTH_HINT = re.compile(r"Depends|current_user|auth|session|token|principal", re.I)
EXEC_SINKS = {"execute", "executescript", "executemany", "query", "raw", "rawquery", "raw_query"}
PICKLES = {"pickle", "cPickle", "dill", "marshal"}

findings = []

def add(rule, cwe, severity, title, path, line, remediation, variant=None):
    f = {"ruleId": rule, "cwe": cwe, "severity": severity, "title": title,
         "file": path, "line": line, "remediation": remediation, "via": "ast"}
    if variant: f["variant"] = variant
    findings.append(f)

def is_str_const(n):
    return isinstance(n, ast.Constant) and isinstance(n.value, str)

def string_value(n):
    # static text of a str constant or f-string ('{}' for each interpolation)
    if is_str_const(n):
        return n.value
    if isinstance(n, ast.JoinedStr):
        return "".join(v.value if isinstance(v, ast.Constant) else "{}" for v in n.values)
    return None

def has_sql(text):
    return bool(text and SQL_VERB.search(text))

def own_break(loop):
    # break belonging to THIS loop: nested loops keep their own
    stack = list(loop.body)
    while stack:
        x = stack.pop()
        if isinstance(x, ast.Break):
            return True
        if isinstance(x, (ast.For, ast.AsyncFor, ast.While)):
            continue
        stack.extend(ast.iter_child_nodes(x))
    return False

def func_name(call):
    f = call.func
    if isinstance(f, ast.Name):
        return f.id, None
    if isinstance(f, ast.Attribute):
        owner = f.value.id if isinstance(f.value, ast.Name) else None
        return f.attr, owner
    return None, None

def analyze(path, src, is_test):
    try:
        tree = ast.parse(src, filename=path)
    except (SyntaxError, ValueError) as e:
        line = getattr(e, "lineno", None) or 1
        add("SG-AST-001", "SYNTAX", "CRITICAL",
            "Python Syntax Error (file does not compile)", path, line,
            "Fix the syntax error; unparseable code must not merge.")
        return

    if is_test:
        return  # shields exempt in test files (same policy as regex); syntax above still ran

    # one-hop alias map: sql = f"..."; execute(sql)
    sql_aliases = {}
    for n in ast.walk(tree):
        if isinstance(n, (ast.Assign, ast.AnnAssign)):
            value = n.value
            if value is None:
                continue
            if has_sql(string_value(value)):
                targets = n.targets if isinstance(n, ast.Assign) else [n.target]
                for t in targets:
                    if isinstance(t, ast.Name):
                        sql_aliases[t.id] = n.lineno

    for n in ast.walk(tree):
        # ---- SG-SEC-005: silent exception swallowing (exact) --------------
        if isinstance(n, ast.Try):
            for h in n.handlers:
                if h.body and all(isinstance(s, (ast.Pass, ast.Continue)) for s in h.body):
                    add("SG-SEC-005", "CWE-390", "MEDIUM",
                        "Silent Exception Swallowing (Empty Catch / Except Pass)",
                        path, h.lineno,
                        "Log or propagate structured exceptions rather than silently masking failures.")
        if isinstance(n, ast.Call):
            fname, owner = func_name(n)
            if fname == "suppress" and owner == "contextlib":
                add("SG-SEC-005", "CWE-390", "MEDIUM",
                    "Silent Exception Swallowing (contextlib.suppress)",
                    path, n.lineno,
                    "Scope suppression narrowly and log suppressed errors.")

        # ---- SG-SEC-012: unbounded while-True (exact break analysis) ------
        if isinstance(n, (ast.While,)):
            test = n.test
            always = (isinstance(test, ast.Constant) and (test.value is True or test.value == 1))
            if always and not own_break(n):
                add("SG-SEC-012", "CWE-400", "MEDIUM",
                    "Unbounded Busy Loop (while True without break)",
                    path, n.lineno,
                    "Give every busy loop a break/timeout guard.")

        # ---- call-based shields -------------------------------------------
        if isinstance(n, ast.Call):
            fname, owner = func_name(n)

            # SG-SEC-004: eval/exec on non-literals
            if fname in ("eval", "exec", "__import__") and n.args:
                if not isinstance(n.args[0], ast.Constant):
                    add("SG-SEC-004", "CWE-94", "CRITICAL",
                        "Dynamic Code Execution (eval/exec) on Non-Literal Input",
                        path, n.lineno,
                        "Avoid eval()/exec(); parse and validate structured input instead.")

            # SG-SEC-004: shell execution through call nodes
            if owner == "os" and fname in ("system", "popen") and n.args:
                if not is_str_const(n.args[0]):
                    add("SG-SEC-004", "CWE-78", "CRITICAL",
                        "OS Shell Command Injection Vector (os.system/popen on non-literal)",
                        path, n.lineno,
                        "Use subprocess with an argument array and shell=False.")
            if owner == "subprocess" and fname in ("run", "Popen", "call", "check_output", "check_call"):
                shell_kw = any(k.arg == "shell" and getattr(k.value, "value", None) is True for k in n.keywords)
                nonliteral = n.args and not is_str_const(n.args[0])
                if shell_kw and nonliteral:
                    add("SG-SEC-004", "CWE-78", "CRITICAL",
                        "OS Shell Command Injection Vector (shell=True with non-literal command)",
                        path, n.lineno,
                        "Pass the command as an explicit argument array without shell=True.")

            # SG-SEC-007: unsafe deserialization
            if owner in PICKLES and fname in ("loads", "load", "open"):
                add("SG-SEC-007", "CWE-502", "CRITICAL",
                    "Unsafe Object Deserialization (pickle family)",
                    path, n.lineno,
                    "Use JSON or a schema-validated format instead of pickle deserialization.")
            if owner == "yaml" and fname in ("unsafe_load", "full_load"):
                add("SG-SEC-007", "CWE-502", "CRITICAL",
                    "Unsafe YAML Deserialization",
                    path, n.lineno,
                    "Use yaml.safe_load().")
            if owner == "yaml" and fname == "load" and not any(k.arg == "Loader" for k in n.keywords):
                add("SG-SEC-007", "CWE-502", "CRITICAL",
                    "Unsafe YAML Deserialization (yaml.load without Loader)",
                    path, n.lineno,
                    "Use yaml.safe_load() or pass Loader=SafeLoader explicitly.")
            if owner == "torch" and fname == "load" and not any(k.arg == "weights_only" for k in n.keywords):
                add("SG-SEC-007", "CWE-502", "CRITICAL",
                    "Unsafe Deserialization (torch.load without weights_only)",
                    path, n.lineno,
                    "Pass weights_only=True for checkpoints you do not fully control.")

            # SG-SEC-001: SQL through call arguments (incl. f-strings, aliases)
            if fname in EXEC_SINKS and n.args:
                arg0 = n.args[0]
                if has_sql(string_value(arg0)):
                    add("SG-SEC-001", "CWE-89", "CRITICAL",
                        "Unparameterized SQL Injection (f-string/interpolated query)",
                        path, n.lineno,
                        "Use parameterized queries (?, %s, :name) and query allowlists.")
                elif isinstance(arg0, ast.Name) and arg0.id in sql_aliases:
                    add("SG-SEC-001", "CWE-89", "CRITICAL",
                        "Unparameterized SQL Injection (interpolated query via variable)",
                        path, n.lineno,
                        "Use parameterized queries (?, %s, :name) and query allowlists.",
                        variant="aliased")

        # ---- SG-SEC-002: secret literals (exact) ---------------------------
        if isinstance(n, (ast.Assign, ast.AnnAssign)) and n.value is not None:
            if is_str_const(n.value) and len(n.value.value) >= 16 and not PLACEHOLDER.search(n.value.value):
                names = []
                if isinstance(n, ast.Assign):
                    names = [t for t in n.targets if isinstance(t, ast.Name)]
                elif isinstance(n.target, ast.Name):
                    names = [n.target]
                for t in names:
                    if SECRET_NAME.search(t.id):
                        secretish = bool(SECRET_VALUE.search(n.value.value)) or len(n.value.value) >= 24
                        if secretish:
                            add("SG-SEC-002", "CWE-798", "CRITICAL",
                                "Hardcoded API Key or Secret Credential in Source",
                                path, n.lineno,
                                "Load secrets from environment variables or a secret manager.")

        # ---- SG-SEC-003: handlers with unbound identity params -------------
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            decorated_auth = any(AUTH_HINT.search(ast.dump(d)) for d in n.decorator_list)
            defaults_auth = any(AUTH_HINT.search(ast.dump(d)) for d in (n.args.defaults + [d for d in n.args.kw_defaults if d]))
            if not decorated_auth and not defaults_auth:
                pos = [a.arg for a in n.args.posonlyargs + n.args.args if a.arg != "self"]
                if any(IDENTITY_PARAM.match(p) for p in pos):
                    add("SG-SEC-003", "CWE-639", "HIGH",
                        "Unbound Caller Identity / Authorization Bypass (IDOR)",
                        path, n.lineno,
                        "Bind operations to the authenticated session principal instead of trusting client-supplied identifiers.")

    # ---- SG-TAINT-001: one-hop user input -> dangerous sink ---------------
    # Deliberately shallow: a variable assigned from a request-ish expression
    # and later passed to a dangerous call, within one scope. Walk order is
    # not source order, so an assignment after the sink can also taint it:
    # intentional and documented.
    TAINT_SOURCE_HINTS = ("args", "form", "GET", "POST", "values", "cookies", "headers", "json", "body", "query_params", "argv")
    TAINT_SINK_CWE = {"execute": "CWE-89", "executescript": "CWE-89", "query": "CWE-89", "raw": "CWE-89",
                      "eval": "CWE-94", "exec": "CWE-94", "system": "CWE-78", "popen": "CWE-78",
                      "urlopen": "CWE-918", "fetch": "CWE-918"}

    def is_taint_source(node):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in ("input", "raw_input"):
            return True
        d = ast.dump(node)
        if not any(h in d for h in TAINT_SOURCE_HINTS):
            return False
        low = d.lower()
        return "request" in low or "req" in low or "argv" in low

    def mentions_taint(node, tainted):
        if not tainted:
            return False
        d = ast.dump(node)
        return any(("Name(id='%s')" % t) in d for t in tainted)

    def scan_taint(scope_nodes):
        tainted = set()
        for n in scope_nodes:
            if isinstance(n, ast.Assign) and is_taint_source(n.value):
                for t in n.targets:
                    if isinstance(t, ast.Name):
                        tainted.add(t.id)
            elif isinstance(n, ast.AugAssign) and isinstance(n.target, ast.Name) and is_taint_source(n.value):
                tainted.add(n.target.id)
            elif isinstance(n, ast.Call):
                fname, owner = func_name(n)
                cwe = TAINT_SINK_CWE.get(fname)
                if not cwe and owner in ("requests", "httpx", "axios") and fname in ("get", "post", "put", "delete", "request"):
                    cwe = "CWE-918"
                if cwe and any(mentions_taint(a, tainted) for a in list(n.args) + [k.value for k in n.keywords]):
                    add("SG-TAINT-001", cwe, "CRITICAL",
                        "User-Controlled Input Reaches Dangerous Sink (one hop)",
                        path, n.lineno,
                        "Validate and allowlist user input before it reaches sinks; use parameterized APIs.")

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            scan_taint(ast.walk(node))
    scan_taint(list(tree.body))  # module scope

payload = json.load(sys.stdin)
for entry in payload:
    analyze(entry["path"], entry["content"], entry.get("is_test", False))

json.dump({"findings": findings}, sys.stdout)
`;

let probeCache;
function available() {
  if (probeCache === undefined) {
    const res = spawnSync('python3', ['-c', 'import ast, json'], { encoding: 'utf-8', timeout: 10000 });
    probeCache = res.status === 0;
  }
  return probeCache;
}

// files: [{ path, content, is_test }]
function analyzePythonFiles(files) {
  if (!available()) return { available: false, error: 'python3 not available' };
  try {
    const res = spawnSync('python3', ['-c', PY_SCRIPT], {
      input: JSON.stringify(files),
      encoding: 'utf-8',
      timeout: 15000,
      maxBuffer: 16 * 1024 * 1024,
    });
    if (res.status !== 0 || !res.stdout) {
      return { available: false, error: (res.stderr || 'python3 analyzer failed').slice(0, 300) };
    }
    const parsed = JSON.parse(res.stdout);
    return { available: true, findings: parsed.findings || [] };
  } catch (err) {
    return { available: false, error: err.message };
  }
}

// Rules where the AST module supersedes the regex heuristic on files it
// analyzed: while-True (regex same-line heuristic false-positives on
// `while True: if x: break`) and any approx regex finding once the AST has a
// precise one for the same rule+file.
const SUPERSEDES = {
  whileTrue: 'SG-SEC-012',
};

module.exports = { analyzePythonFiles, available, SUPERSEDES };
