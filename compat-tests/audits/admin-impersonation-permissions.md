# Admin impersonation permission and self-session lifecycle

The published 1.7.6 admin route first requires the original authenticated actor's
user:impersonate permission. An admin target then requires either the legacy
allowImpersonatingAdmins option or that same actor's user:impersonate-admins
permission. The target's roles and client body permission claims grant neither.
Its route has no separate self-impersonation prohibition. The Rust handler now
passes its resolved actor role into the existing permission engine, retains both
checks and configured ID bypass behavior, and permits the actual Source self
session lifecycle. No configuration field, schema, dependency or store API changes.

Real migrated SQLite Source probes exercise privileged, ordinary, legacy and
an elevated-only actor. Four official-client primary owners prove guest rejection,
a signed wrong actor with forged permissions/role/allow claims, an admin target
whose own role grants nothing, distinct actual session issuance and current cookie
selection, target/owner/foreign persisted readback and original session restoration.
Privileged and legacy can select the target; ordinary cannot. Elevated-only cannot
skip base impersonation authority. All actors with base permission can create a
separate same-user impersonation session and stop it without deleting their
original session. Every denial and final lifecycle preserves peer state.

Source-self passes four scenarios / 226 assertions. The actual prior production
fails three of four primary owners: privileged actor is incorrectly refused for
the admin target; ordinary and legacy actors hit the Source-absent self guard.
The elevated-only denial owner already passes. Before evidence is retained in
/tmp/admin-impersonation-sdk-before.log. Repaired dual-runtime owners pass four /
226, and the whole admin family passes 40 / 3,464. Twelve native admin tests,
locked fixture build, client TypeScript, formatting and production/fixture strict
Clippy pass. Twenty-five additive inventory requirements retain earlier evidence.
The complete integration gate remains pending.

Independent SIWE-owner review finds the changed actor/target authorization and
session lifecycle bounded clear; the exact committed tree is checked separately.
A preexisting custom numeric-ID alias boundary remains: target admin-ID
classification uses the requested selector rather than its canonical stored ID.
This string-ID fixture does not claim equivalence for that adapter configuration.
Wider cookie/session-hook, trusted-ID and plugin interaction modes remain subject
to their independent audits. No comparator allowance, placeholder response,
or oracle modification is added.
