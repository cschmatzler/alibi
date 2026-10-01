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
Clippy with `seaorm2`, formatting and diff checks pass. Independent coordinator review is clear. The integrated canonical gate passes:
257 SDK scenarios / 7,272 assertions, 37 harness tests / 210 assertions,
two Chromium tests / 22 assertions and 79.00% source lines
(23,533 / 29,790). Log: /tmp/username-selected-canonical.log.
The inventory requires success, rejection and unchanged persisted-state evidence.

This selected evidence does not claim configurable username normalization,
validators, renamed schema fields or additional username server APIs. Those
remain separate parity capabilities.
