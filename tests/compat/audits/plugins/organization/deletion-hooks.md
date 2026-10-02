# Organization deletion lifecycle hooks (Better Auth 1.7.6)

Installed `better-auth/dist/plugins/organization/routes/crud-org.mjs:255–292`
checks configuration, authenticates the user, resolves membership and verifies
delete permission. It clears only the matching current token's active
organization, then loads the stored organization. A genuine missing row
throws empty 400 before either callback. It awaits
`beforeDeleteOrganization({organization,user},ctx)`, runs the adapter's scoped
member/invitation/organization transaction, awaits `afterDeleteOrganization`
and returns that original organization. There is no lifecycle-wide
transaction. Before-hook rejection leaves rows retained after selection has
been cleared; after-hook rejection leaves deletion committed. Other selected
tokens and the current active team retain their values.

Actual runtime probes show two callback arguments even though the endpoint
context is optional in the source TypeScript type. Both callbacks receive the
same raw metadata string and original authenticated session snapshot. That
session still names the organization while SQL already contains a cleared
current-token selection. Calling `auth.api.deleteOrganization` with actual
signed-cookie headers and no Request provides `ctx.request === undefined`
and the supplied header values; it does not invent an actor or request.

`OrganizationDeletionHooks` exposes awaited default `before_delete` and
`after_delete` methods returning `AuthResult<()>`. Its immutable
`OrganizationDeleteContext` contains a raw `OrganizationResponse`, `UserView`,
original `SessionView`, actual supplied header values and an optional native
request snapshot. `OrganizationConfig.deletion_hooks` is an optional immutable
Arc configuration, excluded from serialization. A callback can capture its
application store to perform independent writes. Native request snapshots
copy public method/path/headers/body/query into fresh request bookkeeping;
they do not share interior response/session accumulators. Native dispatch
already strips the configured base path, so this request uses the canonical
AuthRequest route path rather than the full browser URL. The observer compares
the source endpoint-context path with that native path, and retains actual
request presence, method and header plus the complete unchanged HTTP trace.

The idiomatic public
`OrganizationPlugin::delete_organization_with_headers(ctx,headers,body)`
resolves a real signed-cookie session with normalized header names, while
callbacks retain the supplied values and receive no Request. It returns
`AuthResult<Option<OrganizationResponse>>`; absence follows the existing
missing-row contract after membership lookup. HTTP and this trusted helper
share one deletion core and the same hook/store order. No public request field
selects the user, callback configuration, authority or lifecycle mode. Existing
HTTP middleware/session resolution is retained.

This is a low-level plugin helper, not a general server-API facade.
`better-auth/dist/api/to-auth-endpoints.mjs:34–55` invokes
`dispatchAuthEndpoint`, whose `dispatch.mjs:173–210` runs global user/plugin
before and after pipelines, including API-key virtual-session injection.
A context-only Rust helper has no builder dispatch pipeline. Signed-cookie
calls are proved; global server hooks, API-key-only header equivalence,
arbitrary HeadersInit/multiple-value shapes and dynamic server base-URL
resolution are explicit separate boundaries. The existing HTTP dispatch can
still supply trusted virtual sessions through normal middleware. Direct
JavaScript mutation of callback arguments/context, arbitrary application
columns, generic JS thrown values and Rust panic parity are outside this typed
immutable callback contract. Captured application-store writes are supported
and exercised.

Six official-client scenarios cover actual before/after delivery and raw
numeric metadata; genuine configured 400 rejections and their exact partial
rows; guarded foreign/guest/schema/disabled/missing-row calls without callback
delivery; trusted signed-cookie success and rejection without a request;
original callback/response snapshots after a real before-hook store write;
and an actual asynchronous hook gate that blocks deletion. They observe real
organizations, members, pending invitations, retained teams/team members,
users and current/sibling/foreign sessions. The trusted fixture passes
mixed-case cookie/header names using their actual request values, so the
public helper's normalization is exercised rather than merely declared.
The missing-row fixture removes an actual organization under the existing
controlled legacy-row operation, retaining genuine membership. Callback
receipts and SQL observations come from callback execution, not synthesized
delivery. Fixtures remain under private application-owned interfaces.

The asynchronous waiter waits for an actual recorded callback with a bounded
timeout and asserts that the request has not completed. Its real release
request uses an independent complete tracing fetch, then both concurrent
traces are retained in a defined observation order. This avoids comparing
network completion order while keeping every request, status, body, header
and cookie. The gate is always released during assertion cleanup. No
comparison rules or allowances were changed.

Replaying the exact pre-hook handler with a mechanically compatible trusted
helper forwarding that old core fails five scenarios: missing callbacks,
ignored configured rejection, requestless callback absence, omitted before
write and premature asynchronous completion. The complementary guard case
already passes. A separate intentionally incorrect implementation reloads
the organization after the real before-hook write; the snapshot owner fails
because `after_delete` receives `Written By Hook` instead of the original
name. Those failing implementations are restored before final validation.
Focused proof passes all 64 organization/configuration SDK scenarios with
4,056 assertions, including the six new scenarios with 532 assertions, and
325 API library tests. Strict API and fixture Clippy, client and changed
reference-fixture TypeScript, formatting and diff checks pass. The coordinator
owns the full gate, inventory, integration and publication. This slice changes
no store interface, schema, migration, lockfile or oracle runtime.

A real disconnected-request probe remains unresolved. Both runtimes reach the
paused before callback and clear the current token's active organization.
After aborting the client, waiting 200 ms for disconnect propagation and
releasing the actual hook, pinned Bun continues: the after callback runs and
organization/member rows are deleted. Rust cancels the HTTP future: only the
before receipt remains and organization/member rows persist. Teams and team
members remain in both runtimes. Exact evidence is retained in
`/tmp/org-deletion-hooks-abort-runtime.log` and the standalone probe. This is
the same framework task-ownership boundary observed for creation hooks; no
callback detachment or synthetic success is introduced here. Ledger ownership,
foreign-key-enabled source behavior, PostgreSQL runtime and raw legacy JSON
boundaries remain documented by the separate deletion-defaults/storage audit.
