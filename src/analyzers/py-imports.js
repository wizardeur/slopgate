// Python import + function extraction for the import/call graph. One-shot
// python3 script (stdlib only): file list in, per-file edges and symbols out.
//
// Per file:
//   imports:       resolved local file imports (dotted-module map with
//                  src-layout prefixes: src/, backend/src/, lib/)
//   namedImports:  name -> file ("from app.db import fetch_user")
//   moduleImports: dotted module -> file ("import app.db", "from app import db")
//   functions:     [{ name (Class.method-qualified), line, end, route, calls }]
//                   route = decorated with a get/post/put/delete/patch/route-ish
//                   decorator; calls = raw call names/attrs, resolved by the
//                   import graph on the JS side.

const { spawnSync } = require('child_process');

const PY_SCRIPT = String.raw`
import ast, json, sys, os

ROUTE_NAMES = {"get", "post", "put", "delete", "patch", "route", "api_view"}

def dotted_candidates(rel):
    p = rel[:-3] if rel.endswith('.py') else rel
    parts = p.split('/')
    out = []
    prefixes = [(), ('src',), ('backend', 'src'), ('lib',)]
    for pref in prefixes:
        if tuple(parts[:len(pref)]) == pref and len(parts) > len(pref):
            rest = parts[len(pref):]
            if rest[-1] == '__init__':
                rest = rest[:-1]
            if rest:
                out.append('.'.join(rest))
    if not out:
        rest = parts[:-1] if parts[-1] == '__init__' else parts
        if rest:
            out.append('.'.join(rest))
    return out

def strip_prefix(parts):
    for pref in (('src',), ('backend', 'src'), ('lib',)):
        if tuple(parts[:len(pref)]) == pref:
            return parts[len(pref):]
    return parts

def decorator_route(dec):
    names = set()
    for x in ast.walk(dec):
        if isinstance(x, ast.Attribute):
            names.add(x.attr.lower())
        elif isinstance(x, ast.Name):
            names.add(x.id.lower())
    return bool(names & ROUTE_NAMES)

def collect_calls(fn):
    # walk statements only: decorators are attributes, not calls this
    # function makes (an @app.post decorator would otherwise add a phantom
    # "post" call edge)
    calls = []
    for stmt in fn.body:
        for x in ast.walk(stmt):
            if isinstance(x, ast.Call):
                f = x.func
                if isinstance(f, ast.Name):
                    calls.append(f.id)
                elif isinstance(f, ast.Attribute):
                    calls.append(f.attr)
    seen, out = set(), []
    for c in calls:
        if c not in seen:
            seen.add(c)
            out.append(c)
    return out

def walk_functions(node, prefix):
    for child in ast.iter_child_nodes(node):
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
            qual = prefix + child.name
            yield {
                "name": qual,
                "line": child.lineno,
                "end": getattr(child, "end_lineno", child.lineno),
                "route": any(decorator_route(d) for d in child.decorator_list),
                "calls": collect_calls(child),
            }
            yield from walk_functions(child, qual + '.')
        elif isinstance(child, ast.ClassDef):
            yield from walk_functions(child, prefix + child.name + '.')
        else:
            yield from walk_functions(child, prefix)

def main():
    root, files = json.load(sys.stdin)
    mod_map = {}
    for rel in files:
        for dotted in dotted_candidates(rel):
            mod_map.setdefault(dotted, rel)

    graph = {}
    for rel in files:
        graph[rel] = {"imports": [], "namedImports": {}, "moduleImports": {}, "functions": []}
        path = os.path.join(root, rel)
        try:
            tree = ast.parse(open(path, encoding='utf-8', errors='replace').read(), filename=path)
        except Exception:
            continue

        pkg_parts = strip_prefix(rel[:-3].split('/'))
        if pkg_parts and pkg_parts[-1] == '__init__':
            pkg_parts = pkg_parts[:-1]

        for n in ast.walk(tree):
            if isinstance(n, ast.Import):
                for a in n.names:
                    r = mod_map.get(a.name)
                    if r and r != rel:
                        graph[rel]["imports"].append(r)
                        graph[rel]["moduleImports"][a.name] = r
            elif isinstance(n, ast.ImportFrom):
                if n.level > 0:
                    base = pkg_parts[: len(pkg_parts) - (n.level - 1)] if n.level > 1 else list(pkg_parts)
                    if n.module:
                        dotted = '.'.join(base + n.module.split('.'))
                        r = mod_map.get(dotted)
                        if r and r != rel:
                            graph[rel]["imports"].append(r)
                            graph[rel]["moduleImports"][n.module] = r
                    else:
                        for a in n.names:
                            dotted = '.'.join(base + [a.name])
                            r = mod_map.get(dotted)
                            if r and r != rel:
                                graph[rel]["imports"].append(r)
                                graph[rel]["namedImports"][a.name] = r
                else:
                    if n.module:
                        r = mod_map.get(n.module)
                        if r:
                            if r != rel:
                                graph[rel]["imports"].append(r)
                            graph[rel]["moduleImports"][n.module] = r
                            for a in n.names:
                                graph[rel]["namedImports"][a.name] = r
                        else:
                            for a in n.names:
                                r2 = mod_map.get(n.module + '.' + a.name)
                                if r2 and r2 != rel:
                                    graph[rel]["imports"].append(r2)
                                    graph[rel]["namedImports"][a.name] = r2
                                    graph[rel]["moduleImports"][n.module + '.' + a.name] = r2

        graph[rel]["functions"] = list(walk_functions(tree, ''))

    json.dump(graph, sys.stdout)

main()
`;

function extractPythonImports(repoRoot, pyFiles) {
  const res = spawnSync('python3', ['-c', PY_SCRIPT], {
    input: JSON.stringify([repoRoot, pyFiles]),
    encoding: 'utf-8',
    timeout: 30000,
    maxBuffer: 16 * 1024 * 1024,
  });
  if (res.status !== 0 || !res.stdout) return null;
  try {
    return JSON.parse(res.stdout);
  } catch {
    return null;
  }
}

module.exports = { extractPythonImports };
