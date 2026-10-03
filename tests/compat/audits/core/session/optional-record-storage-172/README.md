# Native optional record storage, issue 172

PR #402 adds actual two-factor and passkey records to `StatelessStore`, built
from the existing `without_database` public constructor and native
`StatelessSchema`. It uses typed instance-local maps and one exact-generation
mutation helper. SQLx/SeaORM models are never reconstructed or fabricated.
Other optional storage remains explicitly unsupported. This is a useful bounded
production slice, not issue 172 closure.

The pre-change NoDB handler fails at two-factor enable with HTTP 501,
`get_two_factor_by_user_id requires an application store`. The resulting native
workflow enables TOTP with encrypted secrets/backups, consumes a backup once,
rejects replay, and disables the factor. Passkey management lists native records,
rejects another authenticated owner's rename/delete, permits the owner, and
excludes private credential storage. This passkey fixture provisions a real
native record through the public store interface; it does not pretend to prove
cryptographic WebAuthn registration or authentication.

## Source and retained pairs

Source is authentic published Better Auth **1.7.6**, executed with Bun. The owned
fixture's dependency tree was copied to private inodes before any restoration;
Better Auth and the memory adapter were restored from freshly downloaded npm
1.7.6 tarballs. All 364 `.mjs` modules across Better Auth, core, memory adapter
and passkey match fresh published packages after execution, with link count 1.
The coordinator's dependencies were not modified. Integrity receipts retain
individual key module SHA256 hashes and full-package comparison results.

Read published `db/adapter-base`, memory adapter, two-factor schema/verification/
backup consumption and passkey routes. Source initializes tables for registered
schemas and supports records via general CRUD and predicate updates. In-memory
`incrementOne` converts a null/non-number counter to zero before adding; the new
native implementation therefore increments `None` to `Some(1.0)`. Existing SQL
NULL arithmetic is retained. Lock operations and backup CAS affect the exact
factor generation. Updates never resurrect missing records.

`source-workflow-final.json.gz` retains unmodified raw HTTP bodies/cookies and
actual Source store snapshots, including backup replacement, wrong-owner
unchanged passkey state, factor deletion, null-counter arithmetic, conditional
locks, one winner among four simultaneous backup claims, and empty records in a
fresh instance. Each native `*-workflow.json.gz` retains all eleven HTTP calls.
`raw-pairs.json.gz` places every raw Source/native body and status together.
All three native owners match Source statuses and top-level body key sets. Raw
bodies remain different where generated IDs, secrets, backups and timestamps or
JSON key ordering differ; no observation rewriting/error/field normalization was
introduced. Existing SQL identity schema defaults are not asserted to equal
native NoDB identity snapshots.

## Focused checks and review

`focused-final.log.gz`: `cargo test --test integration --features seaorm
storage::optional_records:: -- --nocapture` passes three grouped owners on
actual SQLx, actual SeaORM and true `without_database`. SQL owners independently
assert zero session rows and completed deletion of real factor/passkey rows.
The NoDB owner retains live provisioned records before restart, then verifies
fresh-instance loss; checks null-counter behavior, lock boundary, competing
backup claims, preservation of a sibling factor, exact verified passkey updates,
and missing-generation updates returning absent without resurrection.

`before.log.gz` contains the intended NoDB unsupported-storage regression. It
also exposed a fixture issue: the sensitive SQL disable call selected the cache
and could not reconstruct the application user model. The owner now explicitly
bypasses cookie caching for that physical typed operation, retaining the existing
handler authority contract. No production authority behavior was changed.
`after-initial.log.gz` and `focused-final.log.gz` retain the resulting passes.
A later native-test import repair uses the actual public `types` module inline.

`clippy-core.log.gz`: production core Clippy passes with `-D warnings`.
`clippy-integration.log.gz`: strict integration Clippy is blocked by existing
`chunks_exact_to_as_chunks` in legacy token conversion and `panic_in_result_fn`
in dynamic origin tests. `clippy-integration-scoped.log.gz` passes with only
those two categories allowed for that command; no unrelated files or lint policy
were changed. Source fixture oxlint passes. Targeted rustfmt/oxfmt and
`git diff --check` pass. Hosted Actions are disabled, so no CI pass is claimed.
No full compatibility sweep, `devenv test`, coverage or mutation campaign ran.

Self-review applied test-audit and wrdn-authz. Traced ordinary session middleware
through authenticated cache decoding and signed-token ownership binding to factor
owner selection and passkey owner comparison. Sensitive typed handlers retain
physical authority; no native record write accepts unverified cache claims.
Each storage operation holds the instance mutex only until it returns, with no
await inside; conditional changes inspect the current stored generation.
No workflow-wide transaction or stronger durable/concurrency ledger was added.
Successful earlier writes remain when later steps fail. Records have no automatic
expiry; existing plugin verification/lock/session policies own their lifetime.
Restart loses all optional records. Captured-session-cookie replay limits remain
those documented by the scoped stateless lifecycle implementation.

## Rebase and remaining scope

Initial base `98bfe876`; tested code checkpoint `28d6d7f3`. Rebased production
head `d4de08e7` on `02ed8058`, which adds merged PRs #401 (cookie policy) and
#400 (generic OAuth token parameters). `rebase-range-diff.log` reports both
commits unchanged. `incoming-shared-review.diff.gz` records the constructor/cookie
review: this owner's static HTTP origin/default cookie selection is unchanged;
no incoming changes touch native optional records or either plugin. No passing
checks were repeated for this unrelated rebase or evidence documentation.

Remaining issue 172 scope includes native organization/member/invitation/team/
role, API-key, device and JWK storage; cache-aware APIs for physical application
models; and any still-unproven exhaustive concurrency/callback-failure behavior
and independent second-agent review. Existing session issuance, whole native
UserView preservation, provider scalar authority, account cookies and popup
behavior are retained. This worker performs no nested delegation.
