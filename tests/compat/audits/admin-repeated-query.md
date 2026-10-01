# Repeated admin query parameters against Better Auth 1.7.6

The pinned better-call router materializes repeated URL query names as arrays
before endpoint validation. Admin get-user requires one string id; list-users
validates its declared fields in schema order. The Rust Axum conversion formerly
kept only the last value, so a malformed guest request reached authentication
instead of its array validation error and an authenticated request could select
the final supplied owner.

AuthRequest now exposes set_query_pairs over decoded pairs and query_values over
ordered per-name values. The existing public query map remains available with
its previous last-value representation. A direct legacy-map change replaces the
captured values if that last value changes; removal makes the name absent. Use
set_query_pairs to explicitly replace the complete query, including repeated
values with the same last value. Existing from_parts callers remain single-value
compatible. No TypeScript-shaped public request object is introduced.

The actual Axum boundary retains decoded pairs, and dispatch preserves them
while still recreating the trusted session, response-header and completed-session
accumulators. Caller-provided authority is never retained by this preservation.
Only the admin HTTP schemas opt into array handling in this slice. Their string,
string/number-union and enum errors retain the original field ordering before
session and permission checks; undeclared fields still do not choose a selector.

The primary official-client tracing owner is
`tests/admin/repeated-query.test.ts`. It exercises ten declared fields as guest,
regular user and actual admin, duplicate equal IDs, percent-encoded equivalent
names and aggregate errors ordered by schema rather than query insertion order.
The complete wire body, status, content type and absence of cleanup cookies are
asserted. Valid guest/regular requests still deny, a real authorized single-ID
read succeeds with repeated undeclared fields, and both owners' entire physical
user/account/session state remains unchanged. No comparator or fixture changes.

The source control `/tmp/admin-query-source-control-strengthened.log` passes
1 scenario / 90 assertions. The genuine previous Rust executable fails the same
owner with status401/empty body instead of status400/array validation
(`/tmp/admin-query-native-before-evidence.log`). This failure was recorded before
production edits. The earlier source-control attempt ran before server readiness;
its unreachable-server failure is excluded from behavioral evidence.

The repaired full admin family passes 35 scenarios / 3,114 assertions in
`/tmp/admin-query-family-final.log`. Native core 156, admin 12 and actual Axum
integration 36 tests pass in `/tmp/admin-query-focused-native-clippy.log`.
Strict optional workspace Clippy and TypeScript pass in
`/tmp/admin-query-clippy-corrected.log` after replacing checked indexing with an
exhaustive slice pattern. A locked actual fixture build records the final source
in `/tmp/admin-query-build-corrected.log`; final exact-binary owner proof is in
`/tmp/admin-query-corrected-sdk-final.log`. Full integration, inventory evidence
and publication remain coordinator-owned.

This closes repeated-array rejection for declared get-user/list-users fields.
Accepted repeated filterValue arrays still need corresponding typed adapter
semantics; numeric coercion/defaults, other endpoint query schemas, request-hook
query projections, JavaScript prototype-key behavior and custom filters remain
explicit broader gaps. The legacy map still exposes one value to consumers that
have not opted into query_values. Neither this API addition nor the passing
admin suite establishes complete query parity across the runtime.
