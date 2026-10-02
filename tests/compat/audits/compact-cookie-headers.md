# Co-present compact-cookie header evidence

Issue #295 is a separate harness prerequisite for #205. Reference: the installed
Better Auth 1.7.6. Discovery and the initial implementation used actual main
`4bcd25c3084ac16b39c96b8dc42804f80dc21900`. No root or scoped `AGENTS.md`
exists. This change contains no native production, reference package,
allowlist, capability requirement, coverage-floor or timestamp-policy changes.

## Actual regression and boundary

Two independent actual Source instances, each with migrations, the official
SDK, real compact cache publication, six installed server plugins and SQLite,
produced 21 false header differences under the unchanged main comparator.
Every mismatch was a retained complete logical/current-context Cookie header
or the issued input Cookie header. The existing compact envelope/decoder,
authenticated session, actual callback receipts and persistence checks passed.
The complete original captures remain unmodified in
`/tmp/issue205-compact-source-captures.json`, SHA256
`2058f97ef74ee3fef1fe26c620c58663b45d945957590363ff21e2da75ef7ea0`.
The probe, log, raw cookie hashes and 21 original diagnostics are frozen in
`/tmp/issue205-compact-source-frozen-manifest.json`. Its standalone state
projection emitted quoted absent extension-column expressions; this is not a
complete extended-schema storage claim. The new primary owner below reads
actual `SELECT *` rows instead.

The support change reuses the existing authenticated compact-cache receipt and
its unchanged parser, schema, HMAC, canonical bytes, decoded-copy validation,
real observation interval, configured max-age and expiry checks. Only one exact
unchunked live `better-auth.session_data` receipt is eligible. Its decoded user
must own the decoded session; the session token and owner must match the real
corresponding SDK issuance and signed-cookie issuance on both sides. The
co-present signed credential independently passes the existing HMAC and
canonical-percent/base64 checks. Full compact payloads, decoded fields, expiry
and all complete observations still pass through the existing comparison.

Only those two verified credential values can be reconciled inside a complete
header. Cookie scaffold, names, spacing, order, every other value and all
attributes remain literal. Chunks receive no new reconciliation. Missing or
failed compact receipts cause an owning-header failure even when invalid bytes
are equal. Existing application-data, JWT and trace-shape exclusions remain.

The observable contract is strict comparison of independently random but
authenticated credentials within full actual callback/response headers. A
credible regression accepts a foreign/rotated cache, unchecked MAC, unknown
receipt or changed header attribute, or rejects valid corresponding Source
runs. Structured cache owners alone cannot reach this co-present raw-header
contract. The new case extends the existing strongest real Source owner and
adds no production seam, stubbed cryptography or expected callback receipt.

## Primary owner and negative controls

The retained signed-only owner is unchanged in behavior. Its shared capture
additionally supports a real compact-enabled Source instance. The new primary
owner uses actual official SDK signup for two users, same-user sign-in rotation,
full traced requests/responses, actual JWT/JWKS and independent JOSE verification,
real one-time-token generation/consumption/replay, and restoration through all
real returned cookies. It keeps complete logical and physical headers/session
receipts. SQLite `SELECT *` reads retain every user, account, session and
verification column. Actual password hashes retain their bytes with typed
salt/key metadata, and the published verifier independently accepts the real
password and rejects a foreign password. Cache session ID, token, owner and
expiry are checked against the actual stored signup session.

Bun's `Headers` iterator emits repeated Set-Cookie entries, so
`Object.fromEntries` loses earlier entries. The compact capture explicitly uses
the actual `headers.get("set-cookie")` combined value and `getSetCookie()` for
restoration; no cookie is removed, synthesized or reordered.

Each negative asserts its exact owning path and reason: foreign and rotated
caches, a foreign issuance from the opposite Source side, missing/swapped
receipt, raw-cookie shape/attributes/chunk corruption, canonical token bytes,
decoded principal mismatch, invalid MAC, observation interval, configured TTL,
duplicate/missing base cookies, unrelated text, Path/HttpOnly/SameSite/Max-Age,
order, literal unrelated chunks, absent/wrong cache secret and missing signed
issuance. Identical malformed bytes and identical canonical envelopes with a
corrupt MAC must fail at the owning header.

Further controls deliberately alter actual captured user name, session owner,
session ID/token, version and expiry, recompute a real HMAC and retain the full
mutated bytes/decoded copy. Both the envelope and decoded fields must still
fail at their respective payload paths; altered owner/token also fail at the
owning header. An unrelated rejection cannot satisfy these controls. Four
application-data locations remain strict.

## Recorded proof and limits

- Original frozen six-plugin Source captures compare with exactly 21 failures
  under unchanged main and zero under this repair, with the capture SHA verified
  before both comparisons: `/tmp/issue295-frozen-source-before-after.log`.
- The final standalone Source captures retain all full headers and rows at
  `/tmp/issue295-source-final-captures.json`, SHA256
  `0fe524b139844780b2e96482877163efbe205ea1d3706e70dae95d7948ae8422`.
  These exact captures report 11 header failures under unchanged main and zero
  after repair: `/tmp/issue295-final-capture-before-after.log`.
- The actual primary plus retained signed-only owner pass 2/2, 236 assertions:
  `/tmp/issue295-primary-final1.log`. Strict TypeScript passes:
  `/tmp/issue295-typecheck-final2.log`.
- Strict TypeScript and the complete retained harness pass 74/74, 1,068
  assertions, preserving the original 73 tests/903 assertions and adding one
  primary 165-assertion owner: `/tmp/issue295-strict-checkpoint.log` and
  `/tmp/issue295-harness-checkpoint.log`.
- Setup failures are retained in `/tmp/issue295-source-before-owner*.log`:
  incomplete cookie restoration, an incorrect assumption that publication keeps
  the incoming cache bytes, and the repeated Set-Cookie iterator loss. The
  corrected application capture uses all actual emitted cookies and observes
  each legitimate publication independently.
- The first negative-control expectation used the wrong diagnostic path for
  changed raw-cookie attributes; the actual owning path is
  `compactSessionCache.rawCookies.0.attributes`. Both attempts are retained in
  `/tmp/issue295-negative-owner1.log` and `negative-owner2.log`.
- A temporary expanded active direct-getSession hook probe exposed a separate
  Source-versus-Source numeric cached `session.updatedAt` difference at
  `observation.observed.events.7.session.updatedAt`.
  `/tmp/issue295-source-after-owner.log` and
  `/tmp/issue295-source-after-captures.json` preserve it. Restoration remains
  outside the active callback observation, as in the retained signed-only
  owner. This does not delete any existing #205 owner or fix/claim its separate
  unfinished cache-response observation. No numeric metadata rule changes here.

Full canonical, final composition and independent downstream gate results will
be added only after they finish. This comparator-only change makes no new native
clean coverage claim. OpenClaw/Crabbox/autoreview and repository PR helper tools
are unavailable; the actual strict owner/full repository gates and independent
parent review are used. The canonical command is
`devenv shell -- bash scripts/check.sh`; `devenv test` is a no-op.
