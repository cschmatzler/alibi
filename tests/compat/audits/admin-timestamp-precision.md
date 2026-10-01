# Admin timestamps and the pinned official client

This slice follows guest-wire freeze `0411389c`. Production changes are exactly
two serialization attributes on the private `AdminUserView`'s createdAt and
updatedAt fields. Existing public `better_auth_core::utils::datetime::serialize`
provides the source's three-digit UTC Date.toJSON format. DateTime types, input
precision, stored values, nullable banExpires and every other field are unchanged.
No core, schema, migration, lockfile, inventory or comparator change is included.

## Proven origin of the recurring failure

Two unchanged sibling owners exposed timestamp shifts while the request itself
took milliseconds. The complete logs are preserved:

- `/tmp/admin-guest-wire-sdk-timestamp-diagnostic.log`: role-input update,
  source01:05:04.998 versus client-visible Rust01:07:30.686.
- `/tmp/admin-guest-wire-sdk-fresh-timestamp-diagnostic.log`: empty-action read,
  source01:06:55.100 versus client-visible Rust01:11:03.600.
- `/tmp/phone-numeric-evidence-canonical.log`: earlier impersonation listUsers,
  source22:11:23.952 versus client-visible Rust22:13:48.927.

Installed `better-auth/dist/client/parser.mjs` accepts one through seven
fractional digits. It constructs Date.UTC with
`parseInt(ms.padEnd(3,"0"))` as milliseconds, without truncating a longer
fraction. Consequently `.145927` means 145927 milliseconds to this client,
rather than 145.927 milliseconds. Chrono's automatic formatting usually emits
nine digits, which this parser leaves as a string, but emits six digits whenever
nanoseconds are divisible by 1000. The resulting SDK shifts are intermittent.

The exact installed parser probe `/tmp/admin-permission-oracle/timestamp-parser.ts`
and `/tmp/admin-timestamp-parser-oracle.log` independently show:

- `2026-10-01T01:06:55.248600Z` parses to `01:11:03.600Z`.
- `2026-09-30T22:11:23.145927Z` parses to `22:13:48.927Z`.
- Three-digit input remains the correct Date; nine-digit input remains a string.

These literals demonstrate the observed shift calculus; the old failed logs did
not retain their corresponding raw native fractions, so they are not claimed as
recovered bytes from those requests. Temporary full HTTP recording in
`/tmp/admin-timestamp-fetch-probe.ts` produced
`/tmp/admin-timestamp-http-probe.jsonl` and
`/tmp/admin-timestamp-http-probe-family.jsonl`. It confirms real source public
dates have three digits while private admin DTO responses regularly had nine.
Both runtimes' immediate signup dates align with actual system time in
`/tmp/admin-guest-wire-current-clock.log`. No stale database, clock adjustment or
comparator tolerance is needed to explain the deterministic regression below.

Core UserView, AccountView, VerificationView, OrganizationView and InvitationView
already use the existing millisecond serializers for their DateTime fields.
SessionView already manually serializes milliseconds. The admin-specific view
had omitted those attributes on exactly these two fields; banExpires already
formats milliseconds. The installed runtime emits Date.toJSON for public dates.
The official parser and comparator remain unmodified.

## Primary deterministic owner

One official-client owner creates actual administrator and target sessions, then
uses a private fixed-column fixture SQL operation to install exact existing-row
timestamp literals. Its response reads actual stored SQL lexemes back. Source
and Rust use the same six-digit, nine-digit and trailing-zero inputs. This
operation supplies imported persisted data, not the API response or SDK result.
There is no production clock/seeding hook or public authority bypass.

Public getUser, setRole and listUsers must return the correct actual target,
three-digit raw dates, genuine SDK Date instances and exact epoch milliseconds.
The update's returned Date also matches its full actual wire string. A later
existing fixture read proves the micro/nano precision survived the public update
in storage; existing credentials and original session tokens remain unchanged.
An ordinary target cannot demote the administrator, and both actual owners retain
their original current sessions. Every raw transport, SDK field and state field
remains in the strict comparison.

`/tmp/admin-timestamp-sdk-before.log` runs the exact final owner with fixture
support and old production. The source finishes all cases. Rust fails on the
first actual SDK epoch: expected1790806283145, received1790806428927. That is the
145782-millisecond shift caused by the six-digit fraction, not an elapsed-time
tolerance. The nine-digit case also requires Date instances after repair.

The existing helper tests already own millisecond formatting, nullable handling
and preserved high-precision DateTime input. Existing native admin tests retain
their distinct lifecycle/store contracts. No duplicate private serializer test
was added beside the real HTTP/SQLite/official-client owner.

## Verification and boundaries

- Complete focused admin family: 26 owners / 1590 assertions pass,
  `/tmp/admin-timestamp-sdk-final.log`.
- Source-to-source actual HTTP SDK: one owner / 188 assertions pass,
  `/tmp/admin-timestamp-oracle-sdk-final.log`.
- Existing native admin tests: 12 pass,
  `/tmp/admin-timestamp-native-final.log`.
- Client TypeScript and strict API library Clippy pass,
  `/tmp/admin-timestamp-typecheck.log` and `/tmp/admin-timestamp-clippy-final.log`.
- Strict fixture Clippy reaches only the unchanged baseline
  `two_factor_policy_fixture.rs:254` collapsible_if diagnostic, recorded in
  `/tmp/admin-timestamp-fixture-clippy-final.log`. The coordinator owns its
  separately prepared repair; no suppression or unrelated edit is included.

Arbitrary application JSON/string fields and raw fixture storage observations
are not normalized. Expanded Date years, unrelated private DTOs, source body
schema ordering and global authentication error behavior are not claimed here.
Full gates, publication and inventory integration remain coordinator-owned. The
external autoreview tool named by test-audit is unavailable in this environment.
