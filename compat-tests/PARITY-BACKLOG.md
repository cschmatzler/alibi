# Remaining Better Auth capabilities

Status: selected implementation resumed at the user's request on 2026-09-30.
Finish and merge the already prepared work, including SIWE; then complete
multiple sessions, further organization/admin/two-factor/passkey/API-key
branches, and username-availability/two-factor-disable success evidence.
Wider pinned parity work follows these priorities. Excluded external integration
packages will receive no implementation work. Prepared unmerged work remains
separate from delivered capabilities.

This snapshot describes merged `origin/master` at `04c6bce` (through PR #35),
not the older, dirty coordinator worktree. The reference remains Better Auth
1.7.6. The [upstream audit](audits/upstream-target.md) records source locations
and wider boundaries. An audit gap means equivalence has not been established;
it is not automatically a confirmed defect or wholly missing implementation.

## Existing work worth considering first

| Capability | Current state | Work still needed |
| --- | --- | --- |
| JSON numbers and persistence | Numbers merged PR #26; user JSON persistence and stale-binding repair merged PR #27. | Custom remote JWT signing inputs remain a separate gap. |
| Phone authentication | Reviewed local implementation: password sign-in, OTP send/verify, password reset, server-only consumption, optional signup and custom verification. Thirteen SDK scenarios / 1,058 assertions plus native/storage tests pass. The integrated gate passed: 255 SDK scenarios and 79.00% source coverage. | Merged PR #28; external SMS/verifier policy remains application-owned. |
| OAuth correctness fixes | Local fixes preserve previously granted scopes and atomically create a new user with its OAuth account. Actual failing-before and passing-after evidence exists. | Finish independent/integrated review, canonical validation and publication. |
| Organization invitation listing | Verified HTTP ownership, expired/processed invitations, trusted server-only scope and configured page-limit behavior are proved. | Independent review clear; canonical gate passed with 268 SDK scenarios and 79.25% source coverage. Publication ready. |
| Admin user deletion | Real enrolled-factor flow proves credential/session revocation and rejects unauthorized principals; installed-schema repair preserves two-factor rows. | Independent review clear; canonical gate passed with 265 SDK scenarios and 79.34% source coverage. Merged PR #35. |
| Organization metadata lookup | Local route and ownership/session-state checks implemented. | Absent/empty/raw JSON behavior is repaired and frozen. Review and integrate. |
| OpenAPI and reference page | Frozen generator, source metadata, reference page and complete default/custom-session documents; eleven scenarios / 494 assertions pass. | Complete dependencies, notably update-session, independent review, integration and publication. |
| One Tap | Frozen implementation with local RSA Google JWKS, configuration and lifecycle evidence. All 14 complete-token official-client scenarios / 664 assertions pass. | Integrate the reviewed narrow comparator repair and shared OAuth prerequisites, complete review/gate and publish. |
| SIWE | Merged PR #25; full canonical gate passed with 238 SDK scenarios and 78.65% source coverage. | Nonstandard media/legacy-date/custom-storage boundaries are documented, not new selected tasks. |

## Missing capability families on merged master

| Capability | What it provides | Preparation |
| --- | --- | --- |
| Anonymous authentication | Guest accounts, deletion and safe conversion/linking to real accounts. | Earlier prototype exists; extraction, review and integrated evidence remain. |
| Session updates | Validated/configured extra session fields with persisted updates and hooks. | Frozen implementation passed independent review, sixteen official-client scenarios / 696 assertions and real custom-column/native privacy contracts. Integrated validation and publication remain. |
| OAuth proxy | Production OAuth credentials serving preview/development hosts with encrypted, origin-bound profile transfer. | Actual pinned multi-server flow investigated; implementation remains. |
| OAuth popup | Popup login and secure browser completion messaging. | Missing from the original route profiles; audit only. |
| One Tap, organization metadata, OpenAPI | See the local work table above. | Unmerged capabilities still count as missing on master. |

The merged inventory has nine missing method/path identities after multiple sessions landed. All eight originally reported implemented routes now have successful-flow
evidence, with actual ownership and persisted state checks. Wider configuration
branches remain separate gaps.
Multiple sessions are merged PR #31 with 262 SDK scenarios and 79.30% source coverage.
Username availability is merged PR #29 and two-factor disable PR #30. Device approval/denial/token and GET /ok
now have successful evidence on master.

## Gaps within existing features

These families already exist. Remaining work includes confirmed differences
and configuration branches that have not been fully implemented or proved.

- **Core account behavior:** additional user-field policies and transforms,
  custom signup/duplicate-user behavior, server-only set-password, email change
  and deletion variants, and lifecycle callback/error ordering.
- **Sessions and cookies:** compact/JWT/JWE caches, stateless sessions, cache
  versions, cached-session revocation, secret rotation, cookie overrides and
  production HTTPS/domain/proxy configurations.
- **Storage and rate limiting:** secondary-only/combined storage, verification
  storage modes, custom stores and atomic rate-limit behavior. A Redis feature
  build passing does not establish those runtime modes.
- **Organizations:** further invitation/member/organization hooks and limits,
  custom fields and schema mappings, metadata representation (including known
  raw JSON text differences), server-only operations and plugin combinations.
- **Two factor:** passwordless/configurable
  methods, server-only TOTP/backup-code operations, OTP/trusted-device variants
  and authentication-method interactions.
- **Admin:** custom permissions/multiple roles/admin IDs, extra fields, ban
  enforcement across new login methods and impersonation variants.
- **Passkeys:** sessionless registration, callback-controlled ownership/name,
  extensions, origin/RP configurations and custom challenge cookies.
- **API keys:** server-only expired-key cleanup, custom callbacks, secondary
  storage/fallback/deferred updates and further quota/organization interactions.
- **Email OTP, magic links, JWT and one-time tokens:** remaining custom schema,
  callback, rate-limit, remote signing, cache/storage and secret/configuration
  branches; implemented default flows do not prove every option.
- **OAuth providers:** dedicated built-in defaults/profile mapping are present
  for Google, GitHub and Discord; the other 33 built-in providers remain to be
  accounted for. Generic configuration is possible but does not prove their
  upstream defaults. Discovery, ID-token verification, nonce/audience checks,
  refresh, logout and provider-specific configuration need further work/evidence.
- **Cross-cutting hooks/security:** dynamic base URL/origin/provider policies,
  proxy handling, media validation, disabled paths, lifecycle cancellation and
  interactions among plugins need configuration-specific evidence.

## Additional plugins and package boundaries

Dedicated middleware-plugin equivalents/evidence remain for bearer, CAPTCHA,
compromised-password checks, last-login-method tracking and custom-session
transforms. Related basic behavior may already exist in core; that alone does
not establish each plugin's configuration and composition semantics.

OAuth authorization server, MCP, CIMD, enterprise SSO, SCIM, Stripe, i18n, Expo
and Electron are excluded at the user's request. They are not backlog tasks.

Redis-storage runtime equivalence, framework/client integrations, custom
database-adapter behavior and runtime tooling/telemetry are separate scope
decisions. Matching TypeScript framework or tooling APIs is not a requirement;
decide which observable runtime integrations the Rust library should support.

## Selected implementation order

Merge the prepared correctness fixes and numeric/persistence prerequisites,
phone, SIWE, organization metadata/listing, admin deletion, OpenAPI and One Tap.
Then finish multiple sessions and the selected organization/admin/two-factor/
passkey/API-key branches and success evidence. Each capability retains its own
production tests, review, integrated gate and pull request.

Anonymous authentication, OAuth proxy/popup, new provider families and the wider
core/storage/middleware audit follow the selected priorities unless required earlier.
The excluded integration packages are outside scope.
