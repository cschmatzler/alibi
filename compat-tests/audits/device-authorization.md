# Device authorization — pinned 1.7.6

The official client proves issuance, owner claim/approval, bearer redemption
with a persisted session, denial, consumption/replay, expiry cleanup, polling,
prebinding and foreign-user rejection. Additional profiles exercise asynchronous
custom generators, exact custom-code spelling, Unicode limits, custom lifetime,
interval, client validation and verification URL query/fragment behavior.

The actual baseline failed 11 of the initial 16 scenarios. Schema/media
validation now runs before decision authentication and matches upstream error
bodies. Generated-code uniqueness retries at most three times and does not
repeat the application issuance callback.

The unconstrained optional device user reference permits upstream-supported
prebinding. SQLite installed-table upgrades preserve custom columns/generated
columns/checks/indexes/triggers/views and inbound references. A post-replacement
integrity failure proves rollback and restored connection settings before retry.

Strict harness aliases relate persisted camel-case codes to issued snake-case
codes. TypeScript-versus-TypeScript independently reproduced the previous false
failures. The one-second bearer TTL floor allowance requires an observed real
session with matching token/absolute expiry and execution intervals; changed
expiry, unobserved tokens and larger TTL differences still fail. The new device-code aliases do not apply to caller data, custom JWT
claims or trace shapes. Existing runtime user identity checks remain intact. Raw exceptions remain empty.

Independent review found and resolved pre-authentication validation ordering,
missing media rejection, unscoped aliases in JWT claims and missing destructive
migration rollback evidence. Focused proof: 19 SDK scenarios / 326 assertions,
production Clippy, native generator/collision/concurrency checks and installed
SQLite upgrade/rollback. The final canonical `scripts/check.sh` gate passed
with 227 SDK scenarios / 5,064 assertions, 37 harness tests / 210 assertions,
two Chromium tests / 22 assertions, and 79.23% source lines (21,526 / 27,170).

An inherited custom-adapter boundary remains explicit: Rust uses conditional
pending-status decision writes; upstream's delayed asynchronous adapter can let
two already-validated decisions return success. Eight actual simultaneous trials
on pinned Bun SQLite produced one winner, matching Rust. That scheduler result
is not a claim of universal upstream atomicity. Empty custom code generators,
custom-adapter semantics and OAuth-provider grant extensions need their own
configuration evidence before the complete target is closed.
