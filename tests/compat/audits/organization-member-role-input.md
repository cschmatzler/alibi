# Member-role input and nested authentication against Better Auth 1.7.6

The pinned `dist/plugins/organization/routes/crud-members.mjs:231-287`
declares the ordered role union, required memberId string and optional
organizationId string before org-session middleware. Its handler rejects a
falsy string role with an empty 400 response before selecting an organization.
An empty array or whitespace-only role first resolves the organization, then
normalizes comma-separated roles and rejects an empty result with the same empty
response. The preceding member-role lifecycle capability deliberately documented
this preexisting input gap; this follow-up closes it at the actual HTTP boundary.

`org_input::member_role_update` uses the existing private source-backed media and
JsValue decoder. It preserves role/memberId/organizationId issue order, rejects
null and wrong field types, ignores undeclared client fields and validates before
authentication. It adds no minimum string length or role registration policy.
Malformed JSON and unsupported media retain the pinned code/message and status.
The route emits actual empty bytes with application/json for the source's empty
400, rather than an invented coded validation error or JSON null.

Organization selection uses source truthiness once: an empty organizationId
falls back to the current session selection, while whitespace and padded IDs
remain literal. The resolved ID is passed into the existing private business
function. Other organization handlers retain their existing resolver behavior.
The member permission, initial role validation, hook patches, optional-store
operation and persistence ordering remain unchanged. No public userId field can
select an actor or grant membership. There are no generic core, public request
type, schema, storage, dependency, migration or route-registration changes.

## Nested-session errors and cleanup

Pinned `dist/api/routes/session.mjs:246-263` getSessionFromCtx catches errors
from its nested getSession invocation and treats the result as no session.
The session middleware at 292-297 then returns UNAUTHORIZED. A direct getSession
call can still return the original application/storage policy error. The existing
Rust authenticated_session implementation similarly maps persisted session/user
read errors to Unauthenticated. This route maps that result to the pinned
401 UNAUTHORIZED only around require_session; it does not catch subsequent
membership, role-store or callback failures. Existing before/after callback
error scenarios still distinguish rejected writes from already committed writes.
Virtual-session lookup errors retain their existing separate propagation policy;
global API-key dispatch/configuration equivalence is not claimed here.

The existing queued cookie cleanup remains attached to the resulting error.
Revoked signed cookies clear the browser credential without further stored
mutation. Expired signed sessions delete only the actual expired row and clear
the credential. Unrelated sessions and the legitimate sibling remain usable.
No new session-management interface or policy seam is introduced.

## Primary owner and meaningful baseline

Five cases extend the existing official-client
`tests/organization-extensions/member-role-hooks.test.ts` primary owner:

* Authenticated empty strings, arrays and normalized-empty roles reject without
  actual hook receipts or any SQL state change; a legitimate retry persists its
  role and runs both callbacks.
* Ordered union/field validation precedes guest authentication. Valid guest
  requests cannot claim the owner through a public userId property, and an
  authenticated member without permission remains denied before callbacks.
* Malformed JSON and two unsupported media types reject before authentication;
  an uppercase JSON media retry reaches the actual callbacks and role write.
* Empty-role/organization-selection precedence covers selected and unselected
  sessions, empty IDs and literal whitespace/padded IDs. A valid empty-ID
  request uses only the current selected organization.
* Real public revocation and actual private persisted expiry produce source
  UNAUTHORIZED, with independently parsed empty, HttpOnly, path=/, Max-Age=0
  cleanup cookies. Full physical state proves only the revoked/expired row was
  removed, no callbacks ran, foreign users/members/organizations were preserved
  and the unrelated owner sibling still authenticates. Real sign-in and update
  recover successfully without altering foreign state.

All private observations read actual SQLite rows through the existing
user-state and hook-state interfaces. Existing application hooks emit their own
receipts; the fixtures do not manufacture callback delivery or successful auth
results. Complete traced requests/responses/cookie attributes remain compared.
Returned observations retain the complete parsed response plus a boolean
distinguishing empty bytes from JSON null, rather than duplicating an unparsed
JSON string containing generated IDs. Constant empty/whitespace selector setup
values are asserted directly and remain in real requests; they are not returned
as redundant identity observations because the harness rejects empty identity
values. No comparator, clock, tolerance, pinned auth runtime or fixture change
is made.

The independent pinned runtime probe is
`/tmp/organization-member-role-input-probe.log`. The first four source-to-source
cases pass 4/462 in `/tmp/org-member-role-input-oracle-initial.log`. Against the
unchanged preceding Rust handler, those same cases fail 0/4 at the intended
empty-role write, auth-before-schema/media, and selection precedence differences
(`/tmp/org-member-role-input-sdk-before.log`, 288 assertions). The fifth source
control passes and its prior native implementation fails the intended
AUTHENTICATION_REQUIRED versus UNAUTHORIZED code/message
(`/tmp/org-member-role-input-session-oracle.log` and
`/tmp/org-member-role-input-session-before.log`). These failures precede the
production repair and do not remove requirements or loosen comparisons.

## Focused checks and bounds

`/tmp/org-member-role-input-sdk-final.log` passes all 11 primary scenarios /
1012 assertions. `/tmp/org-member-role-input-family-final.log` passes all 94
organization/organization-extension/OpenAPI scenarios / 6044 assertions.
After adding direct full-state assertions for revocation and the final retry,
the changed fifth owner passes 1/138 in
`/tmp/org-member-role-input-session-final.log`; the production code and other
scenario bodies are unchanged.

All 332 API native siblings pass
(`/tmp/org-member-role-input-api-native.log`). Both existing real SQLite session
policy/empty-token integration owners pass
(`/tmp/org-member-role-input-session-policy-native.log`), independently guarding
direct policy errors versus nested middleware rejection. SDK TypeScript, strict
API and actual fixture Clippy, locked fixture build, and formatting/diff checks
pass in their `org-member-role-input-*` logs. The public no-default-features
rustls/axum/SeaORM/Redis consumer also builds successfully
(`/tmp/org-member-role-input-consumer.log`).

This is a route-local HTTP input capability. It does not claim new server-only
member input wrappers, all organization routes' body/auth order, arbitrary
custom model fields, global virtual-session error equivalence or general
request cancellation behavior. The unchanged prior hook audit retains its
joined-member/custom-column and trusted patch bounds. No test-only production
seam is added. External autoreview tools named by the test-audit skill are not
available here; independent review and all canonical gates, inventory, locks and
publication remain coordinator-owned.
