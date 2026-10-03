# Native API-key records, issue 172

PR #405 adds API-key rows to the built-in `StatelessStore` reached by
`AuthBuilder::without_database`. The fresh base is merged PR #402 at `f12408bb`.
Issue comments/current source and open PR ownership were inspected before edits;
there was no open API-key owner. The coordinator checkout remained `aa0d1388`.
The isolated owned worktree was `/tmp/better-auth-172-apikey`; no other worker's
files, shared checkout, excluded packages or dependency specifications changed.

The existing `ApiKeyStore` contract now has real instance-local creation, ID/hash
lookup, insertion-order reference listing, mutable-field updates, deletion and
explicit expiry cleanup. Existing plugin consumers supply configuration/owner
filtering, sorting/pagination and permission checks. Native rows retain hash,
owner and configuration independently of cookie identity; updates cannot rewrite
those fields. Validation precedes mutation, absent rows cannot be resurrected,
and expiring/deleting a row never repopulates it from a cookie.

Both existing usage contracts are implemented. The combined current-row operation
stages changes under one lock. The Source snapshot operation independently guards
refill generation, remaining > 0, rate window and request-count budget, then
performs a separate final timestamp write returning the current row. Refilling
compares the actual observed date, and a CAS loser falls through to guarded quota
consumption. Rate losers reread the row and retry. Rate rejection preserves an
already-consumed quota and leaves the rate window/final timestamp unchanged.
No workflow-wide transaction, durable ledger or cache-derived record authority
is claimed. Plugin validation owns enabled/expiry/permission checks before usage.

The existing trusted verification input placed `skip_serializing_none` after its
derive, serializing absent optional config/permissions as null and rejecting them
before storage. Moving that attribute before derive fixes the public endpoint
helper inline. Focused handlers use the real installed endpoint pipeline.

## Published Source and raw evidence

The owned Bun fixture runs unmodified published Better Auth and
`@better-auth/api-key` **1.7.6**, with native no-database memory storage. Read
published `claimUsageInDatabase`, `consumeRemaining`, `consumeRateLimit`,
`evaluateRateLimit`, and the memory adapter CRUD/predicate/increment code.
Dependencies were copied to private inodes before any mutation. Fresh npm
1.7.6 tarball comparison before/after execution confirms all 365 relevant `.mjs`
modules match byte-for-byte, with link count 1; coordinator dependencies were not
modified. Tarball hashes/counts are in the integrity receipts.

`source-workflow-final.json.gz` retains all raw HTTP bodies/cookies, actual Source
records before/after denied ownership changes, trusted permission/quota/rate
results, actual concurrent refill results, memory null-counter increment and
fresh-instance record/verification loss. `raw-pairs.json.gz` contains the original
16 Source/native observations for each of actual SQLx, actual SeaORM and NoDB.
Statuses, top-level response key sets and rejection codes agree; raw generated
IDs, keys, timestamps, encrypted cookies and rate-delay timing are different.
No observation rewriting, field/error normalization or comparator changes occurred.

Native backend workflow files retain the full trace and observed rows. In the
initial SQL artifacts `foreignAfter` is the post-cleanup lookup (`null`); the NoDB
artifact captures it before cleanup. The tests independently assert the complete
foreign row unchanged before deletion for all three owners. This point-in-time
difference is retained rather than relabeling the observations.
`native-record-controls.json.gz` retains genuine NoDB provisioned rows, refill
snapshot/current row, concurrent counts, combined-operation counters and actual
restart verification/list response.

## Focused proof and failures

`before-storage.log.gz`: after repairing fixture blockers, real SQLx and SeaORM
pass and true NoDB fails on key creation with HTTP 500 from unsupported native
storage. `after-initial.log.gz`: the same grouped handlers pass all three owners,
including real generated keys, cross-owner/config denial without writes, filtered
listing without secret hashes, owner rename/delete, trusted permission rejection,
quota then rate denial, invalid-date update without partial mutation and expiry
cleanup. SQL owners independently assert zero physical session/API-key rows at
completion. Compile-time generic backend implementations construct the actual
SQLx and SeaORM stores; an environment label does not substitute an adapter.

`after-controls.log.gz`: the NoDB owner passes on four runtime worker threads;
eight same-snapshot consumers produce exactly three admissions/five exhaustion
rejections from one due refill, retaining the genuine row. The distinct combined
operation admits two fractional-budget uses, consumes quota before one rate denial,
then returns exhaustion with the actual remaining -0.5 and requestCount 2. The
owner also keeps a real generated key before restart, observes fresh-instance
loss despite an authentic captured cookie, and rejects absent-generation updates
and consumption without reconstruction. NoDB opens no SQL connection.

Original failures are retained: missing `pkg-config` was fixed by the owned build
environment; initial empty-body diagnostics and trusted DTO null inputs are in
`before.log.gz`/`before-repaired-fixture.log.gz`. The original Source fixture's
billing delete omitted configId and correctly returned 404; the final fixture
addresses its actual config. The additional native controls pass with an unused
result warning, subsequently repaired by binding the genuine update result;
that warning-only edit did not repeat passing adapter checks.

Production Clippy for core/API passes with `-D warnings` and only the existing
unrelated `clippy::double_must_use` category allowed for that command. The strict
failure in unchanged `core/src/endpoint.rs` and scoped pass are both retained.
Targeted rustfmt/oxfmt and `git diff --check` pass. Actions are confirmed disabled,
with no hosted checks: no CI-green claim. No full suite, devenv test, coverage,
compatibility sweep, mutation inventory or delegated review ran.

## Self-review and remaining acceptance

Applied test-audit and wrdn-authz. Traced authenticated session resolution through
existing handler authority, `get_owned_api_key` config/owner checks, default
storage routing and genuine validated snapshots to the new native rows. Ordinary
cache identity can list an empty fresh store but cannot recreate a credential.
Conditional usage writes use only the stored row ID and mutable counters; no
user-controlled owner/tenant/hash is copied from a snapshot. Locks end between
Source phases and contain no await. Source null-counter arithmetic uses zero,
separate from unchanged SQL NULL semantics. Existing organization authorization
and active #403/#404 files are untouched.

The typed `ApiKey.start: Option<String>` cannot represent an unpaired UTF-16
substring from a custom JS generator. Native creation explicitly rejects that
input before insertion; Source memory permits it. This is a remaining Rust schema
limit, not invented Source rejection or claimed lossless parity. Ordinary built-in
ASCII generation and valid Unicode strings are supported.

Issue 172 stays open: native organization/member/invitation/team/role, device-code
and JWK families remain unsupported; physical application models still need
cache-aware interfaces where cookie-only authority is intended. Exhaustive
concurrency/callback-failure differentials and independent second-agent review
remain unclaimed. All native records are lost on restart. Existing captured-cache
session replay limits remain unchanged.
