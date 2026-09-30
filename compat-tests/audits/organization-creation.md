# Organization creation policies: Better Auth 1.7.6

This slice ports fixed and asynchronous organization creation policies, membership-count limits, the trusted creation branch, and creator-role fallback/authorization interactions. It does not claim complete organization-plugin or lifecycle-hook parity.

## Source contract and Rust interface

The pinned implementation is `better-auth/dist/plugins/organization/routes/crud-org.mjs` (`createOrganization`), `adapter.mjs` (`listOrganizations`), `permission.mjs`, and `routes/crud-members.mjs` (`updateMemberRole`). The actual installed runtime was independently exercised before implementation, including static denial, zero limits, both callback return values, empty/custom creator roles, public guests, and trusted server calls.

Public creation uses the authenticated persisted principal. An authenticated caller's body `userId` cannot select another user; a public guest supplying an existing ID receives an empty JSON 401. The private compatibility fixture invokes the upstream server API without headers/request/session and Rust's public `OrganizationPlugin::create_organization_for_user` with the same intended persisted user. That Rust helper resolves the ID before calling the shared implementation; it is not a registered authentication endpoint.

`OrganizationConfig.creation_policy` holds an immutable `Arc<dyn OrganizationCreationPolicy>`. Its asynchronous methods receive the actual persisted user's `UserView` and return `AuthResult<Option<bool>>`. `None` retains the corresponding fixed setting; `Some` overrides it. `allow_creation` returns permission, while **`limit_reached` returns true to deny creation**. Errors propagate even for trusted calls. Trusted creation bypasses an allow-policy denial, while still evaluating that policy and enforcing numeric/asynchronous limits.

`organization_limit` is `Option<f64>`, matching the upstream Number contract. Limits compare the organization's membership list length, including memberships whose role is not creator. Fractional limits are not truncated: a limit of 1.5 permits the second organization and rejects the third membership. Negative limits reject creation; positive infinity and NaN do not reject finite membership counts. `None` supplies no fixed limit. Listing precedes either limit branch, and rejection precedes the duplicate-slug check.

`effective_creator_role()` ports `creatorRole || "owner"` and is used by creation, plugin role metadata, and bounded owner-protection consumers. Configuring `founder` creates that role but does not grant all permissions. The SDK proof denies organization update until an explicitly configured `editor` grant is assigned. The creator's explicit member-role override is retained, as are sole-owner demotion protections when the configured creator role is an empty string.

## Evidence and test ownership

Six official-client differential scenarios own the HTTP/server-call configurations and persistence transitions. The paired fixtures configure the unchanged pinned authentication runtime and real Rust handlers; callback receipts record actual supplied principals and callback order. The limit callback queries the actual SQLite membership table. Private observations query persisted organizations, membership IDs/roles, session tokens and active organization IDs, and unowned organization rows. That last projection catches an implementation that inserts an organization before rejecting, even when no member was inserted.

The scenarios establish:

- Static and negative-limit rejection cannot create records for the authenticated or foreign user. Guests cannot claim a body-selected account. Trusted creation bypasses only the allow denial, preserves unrelated sessions, still enforces limits, and rejects unknown users.
- Fractional limits count both owner and ordinary-member memberships. Successful creation updates the current token's selection while preserving another token. Limit rejection preserves both users' persisted rows and selections.
- Positive infinity and NaN retain the pinned unlimited numeric comparison branch.
- Asynchronous allow/limit callbacks receive the persisted principal despite a forged body ID; true limit results reject both public and trusted callers, and ordered receipts agree.
- Customized creator roles require actual configured permission grants. Empty creator-role configuration defaults to owner and prevents removing the sole effective owner.
- Application callback errors propagate before organization/member writes or session selection, including trusted calls; unowned-row observations guard partial writes.

A separate native public-handler/SQLite regression owns the Rust-specific partial-override contract: implementing only `allow_creation` overrides fixed false, while the trait's default `limit_reached` preserves a fixed limit of one. It observes actual organization/member rows and the persisted current session before and after rejection. This distinct public API cannot be expressed by upstream's single-value configuration fields.

The SDK cases fail against the prior core implementation (retaining only the new interface declarations and a mechanical f64 comparison so the fixture compiles): five failures identify the old guest response, wrong fixed-limit error, ignored callback, wrong update-denial error, and ignored callback errors; the nonfinite comparison case remains green. The native partial-policy regression fails at its first permitted creation with the old implementation's 403, then passes after the repair. Final focused proof is six SDK scenarios / 302 assertions, one native SQLite regression, 28 existing organization API tests, strict production/native Clippy, both Rust format checks, client TypeScript and the bounded reference fixture TypeScript check. No comparison exception or coverage requirement was weakened.

## Remaining boundaries

The upstream membership list uses the configured adapter page limit. The existing Rust `list_user_organizations` returns the complete list, so a nondefault `defaultFindManyLimit` can still change the numeric count. This slice deliberately preserves that existing storage contract and does not claim configured adapter-pagination parity.

Organization/member lifecycle hooks, configured additional fields/model names, broader membership/invitation policies, and concurrent creation-limit admission remain unproved here. The pinned creation check and writes are sequential; this change does not add an atomic capacity guarantee or rollback rejected after-write hooks. Callback `UserView` projection follows the application's existing registered core/plugin fields; arbitrary user-schema additions are a separate contract.

Creation/update metadata still need the pinned record-only input validation, and broad malformed-body/authentication ordering remains unresolved. The existing typed trusted helper consumes a `CreateOrganizationRequest`; this evidence uses valid server input and does not establish upstream Zod behavior for invalid typed values. A successful absent-metadata organization update exposed a separate mutation response mismatch (upstream omits the field, Rust emitted null). The coordinator owns that repair and its absent/empty/populated metadata persistence evidence; the creator-grant scenario uses explicitly stored metadata to isolate its authorization contract.
