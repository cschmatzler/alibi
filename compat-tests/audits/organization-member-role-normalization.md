# Member role normalization against Better Auth 1.7.6

Pinned `dist/plugins/organization/routes/crud-members.mjs:278-288` splits each
string/array element on commas, trims each role and removes empty entries before
validation and adapter storage. `dist/plugins/organization/organization.mjs:18-20`
`parseRoles` joins the resulting array without deduplication. The prior Rust
handler validated these normalized roles but persisted the original input.
The update handler now stores `RoleInput::roles().join(",")`; public body types,
authorization, storage interfaces and other endpoints remain unchanged.

The primary existing SDK owner `tests/organization/members.test.ts` adds one
scenario using real invitations and accepted membership, public official-client
role updates, and independently queried persisted membership state. String and
array inputs include whitespace, comma-separated entries, empty parts and
repeated roles; the persisted role retains duplicates. A final single trimmed
role also changes actual state. No fixture or comparator is changed for this
prerequisite.

`/tmp/org-member-role-normalization-before.log` runs against the prior frozen
native server: its actual returned role is `  admin , member, ,admin  ` rather
than `admin,member,admin`, so the owner fails before the repair.
`/tmp/org-member-role-normalization-oracle.log` and
`/tmp/org-member-role-normalization-final.log` pass one source-self and one strict
dual-runtime scenario respectively, each with 30 assertions. The broader member
SDK owner is included in the subsequent lifecycle capability checks. This bounded
repair does not claim empty-role errors, body/auth ordering or missing-row
behavior are now fully equivalent.
