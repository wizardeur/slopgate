# Changelog

All notable changes to SlopGate. Versions follow the tag names; the floating
`v1` tag does not exist, so a consumer pins an exact version and must move it
deliberately.

## v1.10.3

**v1.10.2 could not run at all.** It shipped a `node_modules` symlink.

### Fixed

- **`node_modules` was committed in v1.10.2 and every consumer's run failed
  before the gate ran.** A worktree convenience link (`node_modules ->
  /some/checkout/node_modules`, the same symlink `.gitignore` was supposed to
  cover) slipped into the release commit: `.gitignore` listed `node_modules/`
  with a trailing slash, and a trailing slash matches a DIRECTORY, not a symlink
  of the same name. GitHub Actions then tried to stage the action repository and
  died on

      Could not find file '.../_staging/slopgate-.../node_modules'

  measured on dsh-org PR 552 at 2026-10-30T05:54:24Z, before any finding was
  produced. The link is removed and `.gitignore` now carries the bare name as
  well, with the reason written next to it.

### What v1.10.2 was for, unchanged

The SG-SEC-009 context-line fix is in this release exactly as it was in 1.10.2;
1.10.2 never got to run, so this is the first release that carries it to a
consumer. See the 1.10.2 entry for the mechanism.

## v1.10.2

**v1.10.1 did not fix the case it was released for.** Released the same night,
after v1.10.1 was measured still failing on the exact shape it targeted.

### Fixed

- **SG-SEC-009 kept firing on `env:` when the `env:` header was a CONTEXT line.**
  v1.10.1 taught the rule the YAML block a changed line sits in, but the engine
  built that block map from the diff's **added** lines only. A workflow that
  already has an `env:` block and adds a key under it - which is what closing an
  injection looks like in an existing file - has the `env:` header as CONTEXT,
  so the new key read as "unknown block", and an unknown block means "fire as
  before". The rule fired on its own remediation, one release after the release
  meant to stop it.

  Hunks now retain their context lines and the block map is built from both.
  Measured on the real shape (dsh-org PR 552, `.github/workflows/checks.yml:146`):
  zero findings; the same body inline in `run:` still fires; `head.ref` under
  `env:` still fires.

### Why the tests did not catch it

The v1.10.1 fixture added `env:` itself, so the header was an ADDED line and the
map saw it. The fixture reproduced a workflow being created, not one being
repaired. Two fixtures now pin both: `env:` as context (must NOT fire) and
`run:` as context (must fire), and reverting the context feed reds the suite.

## v1.10.1

One consumer-observable change, and it removes a false alarm.

### Fixed

- **SG-SEC-009 no longer fires on its own remediation.** The rule tells you to
  pass untrusted `github.event.*` fields through environment variables, and then
  reported the line that does it:

      env:
        BODY: ${{ github.event.comment.body }}     <- was CWE-426 CRITICAL
        run: echo "${{ github.event.comment.body }}"   <- still is

  Both are one line to a matcher that only sees text. The engine now supplies the
  YAML block each changed line sits in (`env`, `run`, `with`, or unknown), and the
  rule stays silent only inside `env:`/`with:`. **If your workflow was red on the
  `env:` shape, that red goes away.** Inside `run:`, or where the block cannot be
  determined, it fires exactly as before.

### Not weakened

- `github.event.pull_request.head.sha` and `.head.ref` still fire in every block,
  `env:` included: routing a head ref through an environment variable changes
  where it is evaluated, not what it is worth, and a checked-out head ref runs
  attacker code.
- `github.head_ref` - the alias - is now matched explicitly. It was silently NOT
  matched per line before this release: the pattern only knew the dotted
  `github.event.<field>` form. That is a gap this release closes, not inherits.

### Verified

106 checks before, 116 after. Three mutations, each restored, each reddening the
suite: removing the `env:`/`with:` exception, reverting "a named key is its own
block", and removing the `head_ref` branch.

## v1.10.0

Twelve commits since v1.9.2. Two of them change something a consumer can
observe; the rest are internal.

### Changed

- **SG-SEC-005 is now advisory (LOW) instead of a blocking finding**, for the
  documented-swallow shape. A `catch` that swallows an error on purpose, with a
  comment saying so, was being reported as a finding and failing the gate. It is
  now reported at LOW severity and does not fail the build. **If your gate was
  green-by-exception on this rule, or red because of it, the red goes away.**
  Nothing else about the rule moved: an UNDOCUMENTED swallow is still reported at
  its original severity.

- **The action runs on `node24`** (`action.yml` `runs.using`), not `node20`.
  GitHub is retiring the node20 runtime for actions, and an action that still
  declares node20 gets a dated failure that lands in the CONSUMER's CI, not
  here.

### What deliberately did NOT change

- **`engines.node` stays `>=20`.** The runtime GitHub ships and the
  compatibility the library promises are two different promises, and this
  release moves only the first. The test job still pins `node-version: '20'`
  so the suite keeps exercising the oldest supported line; a runtime bump
  cannot hide an API that needs something newer.

- No new inputs, no removed inputs, no rename, no changed default. A workflow
  that pinned `@v1.9.2` and moves to `@v1.10.0` changes nothing except the two
  items above.

### Verified

Under node v24.13.0: the suite reports 106 checks passed, the same count it
reports on 20, and `node bin/slopgate.js --help` exits 0.