# SlopGate

A deterministic pull-request gate. It reviews the changed lines of a PR for AI-generated slop and for 22 CWE-mapped classes of security defects, verifies whether findings sit on a reachable path from an entrypoint to a dangerous sink, and posts a single self-updating verdict comment. Runs as a GitHub Action or a local CLI.

No LLM, no network calls, no code leaves the runner. Zero runtime dependencies; Node >= 20 and an optional `python3` (Python AST analysis). 91 checks pass via `npm test`.

## What it checks

**Hygiene**: conversational filler, do-not-merge markers, hidden bidirectional/zero-width Unicode, stray control characters. Added lines only, never context.

**Security shields**: per-line and multi-line patterns, anchored on request objects/superglobals or security-context keywords; test files exempt.

| Rule | CWE | Detects |
| --- | --- | --- |
| SG-SEC-001 | 89 | SQL built by string interpolation or concatenation (a query passed with bind parameters is not a hit) |
| SG-SEC-002 | 798 / 256 | Credential literals, seeded accounts, plaintext password comparison |
| SG-SEC-003 | 639 / 862 | Client-supplied identity used without an authorization binding (IDOR) |
| SG-SEC-004 | 78 / 94 | Shell or code execution built from untrusted input |
| SG-SEC-005 | 390 | Exception handlers that swallow failures |
| SG-SEC-006 | 79 | Unsanitized HTML/HTML-injection sinks |
| SG-SEC-007 | 502 | Unsafe deserialization (pickle family, unsafe YAML schemas, untrusted native objects) |
| SG-SEC-008 | 918 / 295 | Unvalidated outbound fetches (SSRF), disabled TLS verification |
| SG-SEC-009 | 426 | Privileged workflow triggers with untrusted checkout or input |
| SG-SEC-010 | 42574 / 693 | Hidden Unicode (trojan source), reviewer-targeted prompt injection |
| SG-SEC-011 | 829 | Floating supply-chain refs (branch, `@latest`, wildcard range, plain-HTTP source); with `requireShaPins`, also any action ref that is not a full commit SHA |
| SG-SEC-012 | 400 | Busy loops, zero-delay polling |
| SG-SEC-013 | 22 / 98 | Unvalidated file paths, archive extraction without member validation, file inclusion |
| SG-SEC-014 | 327 | Legacy hash or cipher choices in security-sensitive contexts |
| SG-SEC-015 | 338 | Predictable randomness used for tokens, nonces, OTPs, salts |
| SG-SEC-016 | 601 | Redirects to request-controlled URLs |
| SG-SEC-017 | 347 | JWT signature verification skipped or algorithm unpinned |
| SG-SEC-018 | 489 | Debug mode enabled in shipped code paths |
| SG-SEC-019 | 611 | XML entity expansion not disabled (XXE) |
| SG-SEC-020 | 942 | Wildcard or reflected cross-origin policy combined with credentials |
| SG-SEC-021 | 434 | Upload configuration without file-type validation |
| SG-SEC-022 | 942 | Wildcard host/origin allowlists in server configuration |

### Rule scope notes

Two rules state what they cover exactly, instead of implying more than they check.

**SG-SEC-011** flags references that move on their own: a branch, `@latest`, a wildcard range, a git ref over plain HTTP. A version tag is a released version rather than a floating ref, so a tag pin is not a hit by default; a tag is still mutable, but the gate can only read the ref text. Set `"requireShaPins": true` in `.slopgate.json` to also require a full 40-character commit SHA for `uses:` references: with it on, a tag pin or a branch ref both block, and a full SHA or a local (`./path`) action never does. It changes nothing else: container images and package ranges keep their previous matching.

**SG-SEC-007** treats `yaml.load` per language, because its safety is a language fact. In JS (js-yaml >= 4, and the `yaml` package) parsing uses a safe schema that rejects `!!js/function` and the other JS types, so a bare JS `yaml.load` is not flagged; an explicitly full or unsafe schema still is. In Python, `yaml.load` without a `Loader` is unsafe at every version and is flagged. `yaml.safe_load`, `Loader=SafeLoader` and `Loader=FullLoader` are accepted opt-outs in both.


**AST analyzers**: real syntax trees via Python's stdlib `ast` and a vendored, pinned `@babel/parser` (JS/TS/TSX). They provide syntax-error gates with exact lines, higher-precision versions of several shields, and one-hop taint rules for Python and PHP (including cross-line and top-level superglobal flows). In Python, a tainted value handed to a DB driver as a bind parameter is not a sink: only the query text is.

**Import graph**: file- and symbol-level reachability across Python, JS/TS and PHP (composer psr-4, WordPress hooks as entrypoints). The verdict reports whether each finding sits on a path from a route or hook to a sink, or is confined.

**CI triage**: separates real job defects from maintainer-gated jobs and upstream runner flakes.

**SARIF 2.1.0** output via `--sarif` or the `sarif_file` input.

## GitHub Action

```yaml
name: gate
on: [pull_request]
permissions:
  contents: read
  pull-requests: write
jobs:
  gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: wizardeur/slopgate@v1.9.1
        with:
          base_branch: main
```

`fetch-depth: 0` is required. The gate diffs against the merge base, and it fails closed: if that diff cannot be computed, the step stops the gate with setup instructions instead of scanning a partial range. There is no `HEAD~1` fallback, because on a depth >= 2 checkout it would scan the last commit only and look like a normal verdict. Pinning this action to a tag or a full commit SHA is your choice as a consumer; note that SG-SEC-011 does not flag tag pins unless you enable `requireShaPins`.

Inputs: `base_branch`, `fail_on_slop`, `post_pr_comment`, `auto_close_slop`, `ci_diagnostics`, `auto_polish`, `min_block_severity`, `config_path`, `sarif_file`, `github_token`. Outputs: `slop_score`, `lines_reduced`, `invariants_verified`, `ci_classification`, `flaky_jobs_count`. The verdict comment is a single post that updates in place on every push to the PR.

## CLI

```sh
node bin/slopgate.js --base main            # diff HEAD against origin/main
node bin/slopgate.js --diff pr.diff --json  # evaluate a diff file, JSON output
node bin/slopgate.js --sarif out.sarif      # also emit SARIF
git diff main...HEAD | node bin/slopgate.js # diff on stdin
```

`--base` carries the same guard as the Action: only `origin/<base>...HEAD` is a complete view of the change, so a run that cannot compute it exits 1 with the exact fix (for example a shallow clone with no `origin/<base>` ref) rather than scanning a partial range.

## Configuration

`.slopgate.json` at the repo root:

```json
{
  "disable": ["SG-SEC-018"],
  "ignorePaths": ["vendor/**"],
  "minBlockSeverity": "MEDIUM",
  "requireShaPins": false,
  "analyzers": { "external": [{ "id": "php-lint", "when": "\\.php$", "cmd": "php -l {file}" }] }
}
```

`disable` removes rules; `ignorePaths` (globs) exempts paths from every layer; `minBlockSeverity` (LOW/MEDIUM/HIGH/CRITICAL) sets the blocking floor, and findings below it are advisory; `requireShaPins` (default `false`) makes SG-SEC-011 require a full commit SHA for `uses:` references, which is the only setting that makes a mutable tag visible to the gate. Inline `// slopgate-ignore` (or `#`, `/* */`, `<!-- -->` variants) suppresses every layer at that line, including AST and graph findings on pre-existing lines of changed files.

## Vendoring (optional)

Any repository, public or private, can reference the action directly once this repository is public. Vendor a copy instead if you want to pin the exact code you run and decouple from upstream releases: copy the repository under `tools/slopgate/`, reference it with `uses: ./tools/slopgate`, exempt the copy via `ignorePaths`, and re-sync when you adopt a new version.

## Development

```sh
npm test        # 91 checks, no test framework, no dependencies to install
```

The gate has zero runtime dependencies; the only third-party code in the tree is the vendored, version-pinned `@babel/parser` under `vendor/` (MIT). Layout: `src/shields.js` (the rules), `src/engine.js` (pipeline: normalization, suppression, severity gating, scoring), `src/diff.js` (fail-closed diff acquisition shared by both entry points), `src/analyzers/` (Python AST, JS/TS AST, import graph, external tools), `src/verdict.js` and `src/github.js` (verdict comment), `src/sarif.js`, `src/action.js` and `bin/slopgate.js` (entry points), `test/` (fixtures + checks).

## License

[MIT](LICENSE)
