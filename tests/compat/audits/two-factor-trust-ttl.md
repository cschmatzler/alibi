# Two-factor challenge and trusted-device lifetimes

This bounded capability follows backup configuration freeze `cae2fec`. Better
Auth and the official client remain pinned to 1.7.6. No schema, migration,
dependency, comparator, coverage, inventory or selector changes are included.

Published `plugins/two-factor/index.mjs` uses nullish defaults for both lifetimes
and creates database dates from `Date.now() + seconds * 1000`. Explicit zero,
negative values and fractional seconds therefore survive configuration. Its
installed `better-call/dist/cookies.mjs` floors nonnegative Max-Age, omits it for
negative values, rejects values above 400 days, and does not infer Expires from
Max-Age. Actual public-handler probes independently establish bounded behavior
in `/tmp/two-factor-trust-config-oracle.ts` and its `.log`.

The API-local lifetime fields now accept f64. A private immutable context policy
retains the configured numbers; existing metadata remains a finite JSON fallback
rather than changing NaN or infinity into defaults. Date construction retains
milliseconds and applies JavaScript Date truncation to the full timestamp. A
factor-local signed-cookie writer preserves shared attributes while applying
these Max-Age rules without synthesizing Expires. Shared cookie utilities are
unchanged. Default lifetimes remain 600 and 2592000 seconds.

The trusted proof is still authenticated with both its outer cookie signature
and the user-bound inner HMAC before looking up its identifier. The lookup now
uses the existing shared verification helper: read the newest snapshot first,
then perform configured global expired-row cleanup, then evaluate the original
snapshot. `verification.disable_cleanup` skips only cleanup. Expired or missing
proofs still require another factor; successful proofs retire their row and
rotate their signed identifier. Errors from lookup, cleanup and storage remain
observable errors rather than suppressed failures.

## Owner-boundary regression evidence

One parameterized official-client owner adds six equivalent fixture profiles:
fractional lifetimes, zero and negative challenge lifetime, zero and negative
trusted-proof lifetime, and cleanup disabled. It validates actual signed cookie
attributes and actual database expiry differences independently of production
helpers. Challenge and attempt rows have the same exact expiry and original
owner/counter. Positive challenges complete through real SMS-free OTP delivery;
zero challenges have no delivery after browser expiry. Negative challenge
requests stop at their cookie and persisted-date observations. The separate
[pending lookup owner](two-factor-pending-lookup.md) now covers the source's
expired-challenge snapshot policy through explicitly transmitted issued cookies.

Actual trust flows check owner-bound persisted sessions, unchanged foreign-owner
state, successful identifier rotation, rejection of the retired proof, forced
expired proof rejection, default deletion of expired rows and explicit cleanup
retention. Nonpositive trust lifetime is exercised through an explicitly sent
actual signed cookie, avoiding an accidental rejection only by the browser jar.
Complete SDK/transport results remain recorded. State projections retain all
row fields; identifier and user values are wrapped only to participate in the
existing cross-runtime identity graph after local original-value assertions.
Enrollment's random code contents are not this capability's owner; its actual
response schema is validated before the bounded method/count projection.

Meaningful before logs:

- `/tmp/two-factor-trust-ttl-sdk-before.log`: with matching configuration
  interfaces but old integer/date/cookie behavior, all six source cases complete
  and Rust fails on actual fractional/negative expiry or inferred Expires;
  52 existing sibling cases pass.
- `/tmp/two-factor-trust-ttl-sdk-cleanup-before.log`: after the date/cookie repair,
  exactly three default-cleanup profiles fail because real expired verification
  rows remain. Zero/negative challenge and cleanup-disabled controls pass.

These tests have one primary HTTP/SDK owner. Existing native two-factor tests
remain lifecycle and callback controls; no duplicate private-helper tests or
new test-only production seams were added.

## Explicit limits and follow-ups

Nonfinite dates and dates outside chrono's supported range fail closed, but their
full upstream error-wire behavior is not claimed. The 400-day serializer limit
is retained; extreme date/cookie configurations are not an allocation or date
parity claim. Duplicate installed identifiers and all adapter-hook side-effect
ordering are not proven here. Expired pending-challenge lookup ordering is covered by the separate
[pending lookup owner](two-factor-pending-lookup.md). Authenticated OTP session-hook cancellation is approved as the next
separate route-local capability. The independent backup-fixture reset repair is
owned separately; this branch does not change reset wiring or callback receipts.

Only focused family verification is run here. Coordinator review and canonical
full gates remain separate. The external autoreview tool named by test-audit is
unavailable in this environment. Final focused results are recorded below after
completion.

Final focused results: 58 two-factor SDK scenarios / 2,958 assertions
(`/tmp/two-factor-trust-ttl-sdk-final.log`), 17 native two-factor cases
(`/tmp/two-factor-trust-ttl-native-final.log`), client TypeScript and workspace
library Clippy with warnings denied (`/tmp/two-factor-trust-ttl-typecheck-final.log`
and `/tmp/two-factor-trust-ttl-clippy-final.log`) pass. Workspace/excluded-server
formatting and `git diff --check` pass. Production changes are confined to the
factor owner; new fixture profiles configure real runtimes and expose no new
production route.
