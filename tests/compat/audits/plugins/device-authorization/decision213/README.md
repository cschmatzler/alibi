# Issue #213: delayed decision closure

Base: `d669f2ff` (newer than requested `fe1c519d`). The actual issue body lists
configuration callbacks, delayed/custom-adapter overlapping decisions and the
full default lifecycle. #360 already landed genuine custom generators, empty
codes, validation/request callbacks, API errors/ordinary exceptions, raw numeric
constructor rejection, signed duration strings, relative/default verification
URIs and complete code/user/session effects through both SQL adapters. Its
22 scenarios / 474 assertions per adapter, 18 native cases and comparator
negative controls remain prior proof, not new runs. #407 independently proves
true NoDB device storage, owner/client binding, denial/consumption/replay,
expiry and restart loss. Those receipts are retained in their original locations.
No configuration or default inventory was replayed here.

## Source measurement and production repair

The private checkout installed exact published 1.7.6 packages with Bun. All
installed Better Auth `.mjs` bytes were compared with the npm tarball before
measurement; no package module was mutated. The fixture uses the real public
custom database adapter interface around the published memory adapter, delaying
only `deviceCode` updates. It invokes unmodified published HTTP handlers. Both
validated writes are held until both handlers reach the adapter. It then releases
denial followed by approval, and approval followed by denial. Both requests
return literal `200 {"success":true}` in both orders. The physical intermediate
row follows the first write and the final row follows the last completed write.
The two writes' `where` clauses contain only the record ID. Sequential decisions
are rejected after processing. Final approval creates exactly one owner session;
final denial creates none; both consume the grant and reject replay. User and
account records remain byte-equivalent. Full bodies, headers, writes and physical
records are retained in `source.json`.

Rust previously used a conditional pending-status write after validating the
snapshot, imposing a stronger single-winner guarantee than Source. Both real
native stores failed the delayed regression for that intended reason: SQLx
returned `(400, 200)` and SeaORM `(200, 400)`. `native-before.log` and each
`*-before.json` retain those responses and physical rows. The handler now uses
its existing update-by-ID operation after the unchanged validation guards.
No shared trait, storage implementation, session policy or schema was changed.

The native regression holds an independent SQLite `BEGIN IMMEDIATE` writer
lock while polling both handler futures for 250 ms, then releases the lock.
It exercises both initial polling orders and real SQLx/SeaORM handler/store
paths. This is a bounded scheduler measurement, not a deterministic last-write
order or a general isolation theorem. Both successful responses and whichever
final persisted decision completes last must agree with the subsequent token
response and exact session count. All physical columns of device, user, account
and session records are retained before/after; user/account snapshots must remain
unchanged. Sequential rejection, code consumption and replay are checked at the
same real boundary. Existing ownership, client, expiry, pending/slowdown and
single-redemption proofs remain in #360/#407 and the plugin's earlier receipt.

This guarantee requires a successful adapter update and a retained record during
the measured overlap. It does not assert behavior for arbitrary custom-adapter
failures, concurrent deletion, transactions across session creation or every
storage engine/scheduler. Claim and redemption keep their existing conditional
operations; overlapping decisions are separate from claiming and consuming.

## Test-audit and security review

The regression protects the observable stale-pending overlap contract against
reintroducing a conditional decision write. Existing immediate scheduler tests
could not reliably expose delayed writes; the pre-fix failure establishes the
regression. It uses real public handlers and physical stores without a production
test seam. The removed API test
`test_device_approve_allows_only_one_concurrent_decision` explicitly preserved a
"Deliberate hardening divergence"; it enforced the superseded Source-incompatible
policy and is replaced by the physical delayed boundary. Sequential decision
rejection and concurrent redemption coverage remain. No helper deletion follows:
conditional store operations remain legitimate public store APIs.

Authorization review: media/schema/session validation, expiry, pending snapshot,
claim requirement and exact claimed owner checks still precede either decision.
Both overlapping decisions therefore use the same authorized owner. Conditional
claim prevents foreign claim races, and conditional token consumption prevents
multiple bearer admissions. Ordinary callback error redaction and Source package
bytes are unchanged. No callback/session-policy/helper owners overlap other workers.

Reproduce only the affected checks (jobs 2, owned target/cache):

```sh
cd tests/compat/reference-server
bun install
DEVICE_213_OUTPUT=../audits/plugins/device-authorization/decision213/source.json bun run fixtures/device-decision-213.ts
cd ../../..
CARGO_BUILD_JOBS=2 CARGO_TARGET_DIR=/tmp/close213-target DEVICE_213_EVIDENCE=$PWD/tests/compat/audits/plugins/device-authorization/decision213 devenv shell -- cargo test --locked --test integration delayed_device_decisions -- --nocapture
```

No full suite, `devenv test`, coverage gate or hosted CI was run. The current user
instruction explicitly replaces that old issue-body gate with focused proof;
existing comparisons and coverage requirements were not weakened. GitHub Actions
are disabled. Final focused checks and review state are recorded below.
