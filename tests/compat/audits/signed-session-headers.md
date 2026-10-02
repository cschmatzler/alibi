# Signed session header evidence

Reference: Better Auth 1.7.6. Issue #284 is a harness prerequisite for #205,
based on actual main `ff2cfec8d3e0e25c165d60e46494aabd56883e80`. No root or
scoped `AGENTS.md` exists. Source packages, native production code, the
allowlist, capability requirements and the 75% coverage floor are unchanged.

Complete logical Cookie and returned Set-Cookie observations contain genuine
independently random signed credentials. The unchanged #205 Source-versus-Source
control failed both owners (236 assertions): JWT had nine raw Cookie aliases;
OTT had those nine plus returned Set-Cookie. All real JOSE, principal, one-use
storage and cookie-restoration assertions passed. The original artifact is
`/tmp/issue205-signed-cookie-source-counterfactual.log`.

The standalone owner runs two real published Source instances with SQLite
migrations, the official SDK and real HTTP cookie jars. It retains full actual
signup/signin responses, JWT/JWKS and independent JOSE verification, middleware
logical and physical headers, one-time-token generation/consumption/restore,
user/session snapshots and complete transport traces. Its physical POST body is
the application literal `{}`; logical credentials come from the real incoming
Cookie header. A common supplied Host/Origin is an actual application input.
Neither request header collection is redacted or synthesized as an expected
callback receipt.

The regression protects authenticated credential relationships in complete
headers. A credible failure is literal random-cookie drift, acceptance of a
foreign/rotated credential, or an unchecked signature/attribute. Existing
structured cookie metadata tests cannot reach raw logical/physical callback
headers. This single real owner extends the strongest boundary and uses no
test-only production API. The comparator is the actual scenario gate.

Reconciliation independently checks HMAC-SHA256, canonical standard-base64
signature bytes and exact canonical percent encoding. Each token must match the
actual recorded sign-in/signup body and its actual issuance-cookie receipt on
both sides. Only corresponding observed issuance pairs enter the token graph.
Every byte around the credential remains literal: cookie name, order, spacing,
other cookie values and all Set-Cookie attributes. Application data, JWT claims
and transport shape labels retain their existing literal policy. Missing secret
or issuance cannot grant reconciliation.

The actual owner asserts each negative control's exact owning path and reason:
foreign and same-user rotated cookies, an issuance from the other Source side,
corrupt signatures (including identical corrupt bytes on both sides), changed
encoding, names, duplicates, other cookie text, order, Path/HttpOnly/SameSite/
Max-Age attributes, missing issuance, wrong secret and four application-data
locations. A failure in an unrelated field cannot satisfy a control.

Measured proof before publication:

- Original standalone owner failed at nine raw aliases, 41 assertions:
  `/tmp/issue284-source-before.log`; complete captures remain in
  `/tmp/issue284-source-before-captures.json`. Those same saved captures compare
  with zero differences after the repair (`/tmp/issue284-identical-before-after.log`).
- Final complete captures, including actual same-user sign-in rotation, are
  `/tmp/issue284-source-after-captures.json`. The exact unchanged main comparator
  reports ten raw header mismatches on those captures; the repaired comparator
  reports zero (`/tmp/issue284-frozen-captures-before.log` and
  `/tmp/issue284-frozen-captures-after.log`). No Source re-execution is needed for
  that counterfactual.
- Final new owner passes, 71 assertions. All existing 71 harness tests and 754
  assertions remain: full harness 72/72, 825 assertions
  (`/tmp/issue284-harness2.log`). TypeScript strict checking passes
  (`/tmp/issue284-typecheck2.log`).

The first broad harness attempt failed because variable cookie text was placed
in the new physical POST body, producing genuinely different Content-Length;
the fixture was corrected to the real constant-body application call. Missing
reference dependencies also prevented the existing evidence subprocess owner;
the frozen dependencies were installed. Both observations remain in
`/tmp/issue284-harness.log`, rather than weakening either assertion.

This publication is a draft pending the immutable canonical gate and independent
review. OpenClaw/Crabbox/autoreview/PR helper tools are not installed. The actual
repository canonical command is `devenv shell -- bash scripts/check.sh`;
`devenv test` is a no-op. No unexecuted gate is claimed.
