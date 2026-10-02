# ECMAScript role-input whitespace against Better Auth 1.7.6

Pinned `dist/plugins/organization/routes/crud-members.mjs:276-282` splits every
incoming update role on commas, applies JavaScript String.trim, drops empty
components and retains duplicates. Rust str::trim disagrees at U+FEFF (BOM,
trimmed by JavaScript) and U+0085 (NEL, preserved by JavaScript). The previous
input and callback proofs covered ordinary spaces, but did not establish these
Unicode boundaries. The measured difference is repaired separately without
changing those frozen capabilities or their original logs.

The private normalized_update_roles helper is used only by member-role update:
its empty-role guard, role validation and joined stored/callback role use the
same ECMAScript whitespace and line-terminator set. This is the same character
set already ported in private SIWE/passkey parsers. Their helpers are deliberately
not exported across plugins or expanded into a new public utility solely for
this test. The helper preserves borrowed components, array order and duplicates.
The creator-role check over the already normalized new input no longer trims it
again with Rust's different whitespace definition.

Generic RoleInput::roles, stored requester/target role splitting, existing
permission policy and other endpoints remain unchanged. This does not claim
those other input/storage paths have matching Unicode normalization. Trusted
callback role patches are still stored verbatim without revalidation.

Two cases extend the existing official-client member-role owner. Actual
BOM/NBSP/ideographic-space array components and a duplicate admin normalize to
admin,member,admin in the public response, physical stored member and both
actual callback phases. The complete ECMAScript whitespace set normalizes to an
empty input and returns empty 400 without a callback or mutation. NEL-only and
NEL-wrapped admin remain literal unknown roles, return the actual ROLE_NOT_FOUND
message and preserve complete owner, target, foreign, organization, membership
and sibling-session rows. A legitimate array retry persists duplicates and
reaches the callbacks. All receipts come from real configured application hooks;
no fixture emits success, expected normalized roles or fabricated persistence.

The independent runtime probe is
`/tmp/organization-member-role-unicode-probe.log`. Both unchanged pinned-self
SDK cases pass in `/tmp/org-member-role-unicode-oracle.log`. Against the preceding
native input repair, both fail for the intended reason: BOM-wrapped admin is
incorrectly ROLE_NOT_FOUND, while NEL-only is incorrectly an empty response
(`/tmp/org-member-role-unicode-before.log`, 0/2 and 104 assertions). Neither the
fixture nor comparator changed between that failure and the production fix.

After repair, the complete member-role callback/input owner and existing
default member SDK sibling pass 17 scenarios / 1216 assertions in
`/tmp/org-member-role-unicode-sdk-final.log`. All 332 API native siblings pass
(`/tmp/org-member-role-unicode-api-native.log`). The locked fixture build,
actual fixture strict all-target Clippy and client TypeScript pass in
`org-member-role-unicode-{build,fixture-clippy,typecheck}.log`. API strict library
Clippy also passes (`/tmp/org-member-role-unicode-api-clippy.log`). Formatting and
git diff checks pass.

No new API, dependency, lockfile, migration, schema, route, inventory entry,
clock/tolerance/comparator policy, pinned runtime modification or production
test seam is introduced. The test-audit external autoreview tools are unavailable;
the coordinator owns independent review, full gates and publication.
