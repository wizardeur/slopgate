# SlopGate

A deterministic pull-request gate. It reviews the changed lines of a PR for AI-generated slop and for 22 CWE-mapped classes of security defects, verifies whether findings sit on a reachable path from an entrypoint to a dangerous sink, and posts a single self-updating verdict comment. Runs as a GitHub Action or a local CLI.

No LLM, no network calls, no code leaves the runner. Zero runtime dependencies; Node >= 20 and an optional `python3` (Python AST analysis). 84 checks pass via `npm test`.

## What it checks

**Hygiene** — conversational filler, do-not-merge markers, hidden bidirectional/zero-width Unicode, stray control characters. Added lines only, never context.

**Security shields** — per-line and multi-line patterns, anchored on request objects/superglobals or security-context keywords; test files exempt.

| Rule | CWE | Detects |
| --- | --- | --- |
| SG-SEC-001 | 89 | SQL built by string interpolation or concatenation |
| SG-SEC-002 | 798 / 256 | Credential literals, seeded accounts, plaintext password comparison |
| SG-SEC-003 | 639 / 862 | Client-supplied identity used without an authorization binding (IDOR) |
| SG-SEC-004 | 78 / 94 | Shell or code execution built from untrusted input |
| SG-SEC-005 | 390 | Exception handlers that swallow failures |
| SG-SEC-006 | 79 | Unsanitized HTML/HTML-injection sinks |
| SG-SEC-007 | 502 | Unsafe deserialization (pickle family, unsafe YAML, untrusted native objects) |
| SG-SEC-008 | 918 / 295 | Unvalidated outbound fetches (SSRF), disabled TLS verification |
| SG-SEC-009 | 426 | Privileged workflow triggers with untrusted checkout or input |
| SG-SEC-010 | 42574 / 693 | Hidden Unicode (trojan source), reviewer-targeted prompt injection |
| SG-SEC-011 | 829 | Unpinned dependencies, actions, container images |
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

**AST analyzers** — real syntax trees via Python's stdlib `ast` and a vendored, pinned `@babel/parser` (JS/TS/TSX): syntax-error gates with exact lines, higher-precision versions of several shields, and one-hop taint rules for Python and PHP (including cross-line and top-level superglobal flows).

**Import graph** — file- and symbol-level reachability across Python, JS/TS and PHP (composer psr-4, WordPress hooks as entrypoints). A finding on a path from a route or hook to a sink is reported as reachable; confined findings say so.

**CI triage** — separates real job defects from maintainer-gated jobs and upstream runner flakes.

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
      - uses: ./tools/slopgate   # or slopgate@v1.9 where a cross-repo ref works
        with:
          base_branch: main
```

Inputs: `base_branch`, `fail_on_slop`, `post_pr_comment`, `auto_close_slop`, `ci_diagnostics`, `auto_polish`, `min_block_severity`, `config_path`, `sarif_file`, `github_token`. A shallow checkout fails closed with instructions — the gate never passes vacuously.

## CLI

```sh
node bin/slopgate.js --base main            # diff HEAD against origin/main
node bin/slopgate.js --diff pr.diff --json  # evaluate a diff file, JSON output
node bin/slopgate.js --sarif out.sarif      # also emit SARIF
git diff main...HEAD | node bin/slopgate.js # diff on stdin
```

## Configuration

`.slopgate.json` at the repo root:

```json
{
  "disable": ["SG-SEC-018"],
  "ignorePaths": ["vendor/**", "tools/slopgate/**"],
  "minBlockSeverity": "MEDIUM",
  "analyzers": { "external": [{ "id": "php-lint", "when": "\\.php$", "cmd": "php -l {file}" }] }
}
```

`disable` removes rules; `ignorePaths` (globs) exempts paths from every layer; `minBlockSeverity` (LOW/MEDIUM/HIGH/CRITICAL) sets the blocking floor — findings below it are advisory. Inline `// slopgate-ignore` (or `#`, `/* */`, `<!-- -->` variants) suppresses every layer at that line, including AST and graph findings on pre-existing lines of changed files.

## Vendoring

Personal GitHub accounts cannot resolve cross-repo private actions. Copy the repository under `tools/slopgate/` in the consumer repo and reference it with `uses: ./tools/slopgate`; exempt the copy via `ignorePaths`. Keep the copy in sync with upstream releases.
