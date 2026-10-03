# Two-factor enable session cancellation

This route capability depends on typed session-create cancellation 1655472 and
the earlier skip-enrollment write-order repair 9a35025. The published Better
Auth 1.7.6 `plugins/two-factor/index.mjs` creates a replacement session before
writing the factor. Its internal adapter returns null for a configured
before-create-session hook returning false; the subsequent cookie writer
throws, and the actual HTTP handler emits an empty 500 response. A genuinely
thrown application APIError remains its declared status and JSON body.

The enable handler catches only AuthError::SessionCreationCancelled and emits
an empty 500. All other errors propagate unchanged. The default store error
response remains 403. Other CRUD cancellation, other two-factor routes and
pending completion are not remapped: pending source completion explicitly
uses a different FAILED_TO_CREATE_SESSION JSON error. There is no string-based
classification or general Forbidden conversion.

Two equivalent profiles use actual lifecycle hooks returning Cancel or
throwing Forbidden with the exact existing cancellation message. The official
client cases capture the real response bytes alongside the ordinary SDK
result, assert empty 500 versus JSON 403, and inspect actual SQLite state:
the accepted user update remains true, no factor is written, the original
single session and signed-cookie owner/token remain unchanged. Wrong passwords
fail before the hook. The existing user-update APIError 400 scenario remains
unchanged. Before the mapper, cancellation fails with 403 instead of 500,
while the same-message application error passes
(`/tmp/two-factor-session-cancel-sdk-before-corrected.log`). Afterward all three
scenarios / 74 assertions pass (`/tmp/two-factor-session-cancel-sdk-after.log`).

The existing native hook matrix is extended rather than duplicated. Its six
cases independently inspect historical unverified generations and trusted
org/team/admin/IP/agent fields through actual public plugin dispatch and real
DatabaseHooks. It confirms the same-message exception stays Forbidden and only
the semantic cancellation returns empty 500; both retain the original factor
and session after the accepted user update. The original user rejection cases
retain false and APIError 400. This test fails before the mapper
(`/tmp/two-factor-session-cancel-native-before.log`); all ten native two-factor
tests pass afterward (`/tmp/two-factor-session-cancel-native-final.log`).

The SDK scenario records raw bytes only for the lifecycle response whose
empty-body or declared JSON contract is relevant; all ordinary wrong-password
SDK fields and transport observations remain compared through the unchanged
harness. No comparator exemption, response field removal, timeout increase,
test-only production seam, shared inventory, dependency, schema or lock change
is made. Other endpoint-specific null-session behavior remains a separate
capability. The coordinator owns independent review and canonical gates.

Final focused validation: twenty-one distinct official SDK scenarios / 704
assertions pass (`/tmp/two-factor-session-cancel-sdk-family-final.log`), ten
native two-factor tests pass, and TypeScript, workspace library Clippy with
seaorm, formatting and diff checks pass.
