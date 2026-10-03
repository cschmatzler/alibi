# Organization teams: Better Auth 1.7.6

This capability change enables the pinned organization's nine team routes, typed server-only team creation/removal, and their invitation and session interactions. Dynamic roles belong to a separate descendant change; the prerequisite's role tables and stores remain inactive here. This document does not claim complete organization-plugin parity.

## Configuration and Rust interfaces

`OrganizationConfig.teams` enables team routes and default-team creation. Teams are disabled by default. Once enabled, creating the organization's default team defaults to true and removing the last team defaults to false. Configuration supports numeric team/member limits, asynchronous limit policies, lifecycle callbacks, and a custom default-team factory.

`OrganizationLimitResolver` receives the actual session and user. The maximum-teams callback also receives the HTTP request, allowing header- and principal-dependent policies; server-only calls have no request principal. `DefaultTeamContext` supplies the actual request, user, session, and auth configuration, with the typed team store provided separately. Its session is the handler's already authenticated snapshot, so creating a default team does not trigger a second session refresh. Team hooks receive team/user/organization data, matching the pinned hook contracts. Callback mutation and veto affect persisted team and membership records.

`OrganizationPlugin::create_team` and `remove_team` are trusted server APIs with explicit organization scope. `create_team_with_headers` and `remove_team_with_headers` resolve an actual signed-cookie principal and enforce organization permissions and current active-team protection. These low-level APIs do not run builder-wide dispatch hooks or inject API-key sessions. The private compatibility fixture calls the published methods without adding public authentication endpoints; its signed-call error envelope observes the actual status, while HTTP scenarios retain complete error bodies.

Ordinary errors from team hooks and the default-team factory return an empty HTTP 500, matching the pinned runtime. Explicit API vetoes retain their status, code and message. This changes error transport only: writes committed before the callback failure, including independent application writes, remain committed. Focused differential regressions exercise the factory failure, all ten team callback boundaries, and signed versus trusted server authority on actual SQLx and SeaORM. Factory suppression/fallback and static-role configuration evidence remain outside this production repair.

Static `roles` is an optional map: `None` uses the pinned default roles; `Some(map)` replaces them, including an explicitly empty map. A custom definition does not inherit owner permissions. Whole-request permission checks must be satisfied by one assigned role; separate roles do not union a permission request. Configuring a custom creator role preserves the pinned built-in invitation role names.

`require_email_verification_on_invitation` accepts an explicit policy, with the default requiring verification when numeric database IDs are configured. Invitation view, acceptance, and rejection require the addressed user. Viewing additionally requires a live pending invitation and an inviter who remains a member. Expired pending invitations can still be rejected.

## Observable transitions

Default-team creation writes the team and creator membership, then selects that team in the session. Its update timestamp is null; explicitly created teams have a create/update timestamp. `keepCurrentActiveOrganization: true` creates the organization and its default membership while preserving both existing session selections. Public timestamps use JavaScript's millisecond JSON precision so the official client receives the correct dates.

Membership insertion preserves one identity for each team/user pair and enforces durable capacity within a transaction. Removing a member, user, team, or organization removes the relevant membership links and releases seats. App-owned numeric user IDs use explicit cleanup rather than a FK to the bundled user model.

Invitations support one or multiple team IDs in the pinned comma-separated format. Acceptance checks recipient, live session ownership/expiry, organization, selected teams, and capacity before committing invitation status, organization/team memberships, and session scope together. Reuse and concurrent losers cannot leave partial memberships. A single-team acceptance selects that team; multi-team acceptance preserves the previous team selection. Team deletion prunes live pending invitation selections while retaining historical accepted selections.

Server-side team deletion preserves an existing session's historical `activeTeamId`, matching the pinned runtime. Requests that use that deleted selection cannot access team members; explicit null selection clears it without changing the token. HTTP deletion still rejects the current active team. Configured projection emits nullable `teamId`/`activeTeamId` only when teams are enabled.

Team membership request IDs follow the upstream `z.coerce.string()` contract. JSON numbers use ECMAScript number formatting (including rounded large integers), and supported JSON primitives/arrays/objects follow JavaScript string conversion. This conversion is limited to the two membership request fields. It does not execute JavaScript; converted values remain bound database inputs and pass the existing permission and tenant checks. Number formatting uses [ryu-js](https://docs.rs/ryu-js/1.0.3/ryu_js/struct.Buffer.html).

## Evidence and ownership

The shared storage prerequisite owns six SQL regressions for capacity, concurrency, recipient/session/tenant failures, atomic invitation acceptance, deletion cleanup, numeric custom schemas, and populated migrations. Its transaction/hook lifecycle and CAS snapshot repairs received independent review and its canonical gate passed.

The teams change owns eight native API tests: all team routes and permission boundaries; callback mutation/veto/order; custom factory context and preserved session selection; numeric and asynchronous limits; server methods; static-role replacement/empty-map/whole-request checks; invitation verification, expiry, and removed-inviter policy; and real persisted custom-ID membership requests. The numeric-ID test fails on the strict-string pre-fix handler. Omitting the actual callback user or request also makes the asynchronous-policy regression fail. The factory case configures refresh on every access and records actual SQLite expiry writes: the pre-fix second lookup refreshes twice for one request, while the repaired flow refreshes once.

Six official-client differential scenarios (528 assertions) use teams-only, no-default-team, request-dependent-limit, and removable-final-team profiles. They inspect returned data and raw persisted teams, membership IDs, stored counters, invitations, and sessions. Controlled server operations include successful create/remove and tenant/final-team rejections. The harness observes actual configured URLs and cookie scopes, and its negative controls preserve each ordered team identity in multi-team invitation strings. The old aggregate-string comparison demonstrably missed wrong team relationships. The focused harness currently runs 23 tests, including the new ordered-identity and configured-cookie-path controls.

The runtime inventory enables teams explicitly and requires success, rejection, authorization, and state evidence for all nine routes. Generated docs add those nine paths while retaining every previous operation. The pinned documentation library previously returned zero tag pages because the schema omitted top-level tag declarations; the generator now declares its used tags and rejects an empty result. A real library invocation fails before the repair and produces eight tag pages afterward.

The separate docs site's TypeScript check currently reports five existing collection/module typing errors (`PageData` fields and `.source/server.ts` without exports). An archived prerequisite checkout produces the same errors with the unchanged pinned dependency lock. This does not affect Rust documentation or OpenAPI regeneration, and remains a separate documentation integration issue.

## Remaining organization integration boundaries

Additional fields/model renaming, organization/member/invitation lifecycle callbacks, functional organization and membership limits, invitation delivery, resend/cancel-pending reissue, arbitrary configured ID generators, and broader server-only organization/member methods still need implementation or evidence. Team callback/factory/static-role and invitation-policy overrides have native evidence; equivalent differential fixture profiles remain outstanding for those branches. Custom factory access to other application stores can be captured in the Rust factory; the provided store interface here is limited to teams.

Dynamic-role route/configuration behavior and role-name concurrency are handled separately. Older core list methods outside the new storage queries still require a configured query-limit audit. These boundaries remain on the implementation ledger and are not excluded from the complete parity target.

Raw fractional and nonfinite quota policies, their explicit public migration, Source semantics and focused evidence are documented in [raw-limits.md](raw-limits.md).
