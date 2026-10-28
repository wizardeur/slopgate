# Changelog

All notable changes to SlopGate. Versions follow the tag names; the floating
`v1` tag does not exist, so a consumer pins an exact version and must move it
deliberately.

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