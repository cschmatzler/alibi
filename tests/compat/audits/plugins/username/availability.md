# Username availability success evidence

Reference: published `better-auth@1.7.6`, `plugins/username/index.mjs`
`isUsernameAvailable` endpoint. This capability uses the existing configured
username plugin and real database; it adds no fixture or inventory exceptions.

The public endpoint validates before its normalized database lookup. A raw
empty username is invalid, whereas a nonempty name under three characters is
too short. Rust previously classified both inputs as `USERNAME_TOO_SHORT`.
The handler now matches the reference's empty-value check before length checks.

The official-client success scenario first proves availability, signs up with
an uppercase name, observes the persisted lowercase identity through a fresh
unauthenticated lookup of both cases, and checks an unrelated name remains
available. A real session returns that normalized username. Read-only user,
account and session state is captured before/after guest queries and must remain
identical. No caller identity or credential is trusted for this public lookup.
The validation scenario covers empty, short, long and invalid names with their
actual error codes. Existing native lookup tests remain the primary store-level
coverage; no duplicate native empty-name regression was added.

The intended failure is recorded in `/tmp/username-availability-before.log`:
one SDK scenario passed and the empty-name assertion failed with
`USERNAME_TOO_SHORT` instead of `INVALID_USERNAME`. After the owner repair,
`/tmp/username-availability-sdk-final.log` has two scenarios and 24 assertions
passing against both real runtimes. Five existing focused native tests pass
(`/tmp/username-availability-native-final.log`). TypeScript, workspace library
Clippy with `seaorm`, formatting and diff checks pass. Independent coordinator review is clear. The integrated canonical gate passes:
257 SDK scenarios / 7,272 assertions, 37 harness tests / 210 assertions,
two Chromium tests / 22 assertions and 79.00% source lines
(23,533 / 29,790). Log: /tmp/username-selected-canonical.log.
The inventory requires success, rejection and unchanged persisted-state evidence.

This selected evidence does not claim configurable username normalization,
validators, renamed schema fields or additional username server APIs. Those
remain separate parity capabilities.


Configured policy (#206)
-----------------------

The configured family now uses `UsernameConfig`, synchronous fallible normalizers
and awaited validators at the actual email/password and update-user boundaries.
Length is measured in UTF-16 units. Explicit pre/post ordering retains the pinned
plugin's different sign-in and signup/update rules; availability validates raw
input. Schema parsing, database candidate transforms and adapter binding each
perform their own actual normalization stage. A case-preserving lookup must not
lowercase the configured stored identifier. Foreign update collisions and
immutable changes retain physical ownership checks. Display omission and read-only
schema input are exercised with actual equivalent field configurations, rather
than faked receipts.

The existing official-client username owner now has 16 scenarios. The configured
cases cover bounds, preservation, raw/normalized ordering, Greek and supplementary
Unicode, display validation/normalization, callback errors, read-only fields,
foreign principals, persisted user/account/session state, hook request context,
verification and one-day remember-me sessions. Callback observations come from
actual installed callbacks; ordinary errors retain the reference's empty 500.
A Source fixture uses the actual plugin schema to declare read-only username input.
Application additional fields alone cannot override that plugin's input policy.

At the configuration-only pre-fix checkpoint, `/tmp/issue206-before-2.log`
reproduces ignored bounds, unwanted lowercasing, rejected post-normalization input
and allowed immutable mutation. An initial dependency-resolution failure and an
incorrect display-disabled Source fixture are excluded from regression evidence.
After repair, `/tmp/issue206-merge-checks.log` records all 16 scenarios / 458
assertions and all ten existing native email/password tests passing. Strict root
library and all-target core/API/SeaORM Clippy pass. TypeScript and formatting pass.

Validation follows the requested focused-check/merge-first workflow. No fresh
full coverage or canonical green result is claimed for this change. The separate
frozen-main broad batch has 846/850 native and 1503/1548 SDK owners passing; those
notification-policy and rate-limit regressions remain explicit follow-up work.
No Source pin, comparer, required evidence, coverage floor or hook is bypassed.
