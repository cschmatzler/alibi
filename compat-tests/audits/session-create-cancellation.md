# Typed session-create cancellation

The public unit error `AuthError::SessionCreationCancelled` distinguishes an
explicit session-create hook cancellation from an application Forbidden
exception. Its default response remains 403 with the unchanged message
`session creation cancelled by database hook`, without an error code.
Only the actual SeaORM before-create-session Cancel result produces it. Other
CRUD cancellations continue using their existing Forbidden errors. Custom
stores can intentionally return the semantic variant. There is no helper
wrapper, message matching or global endpoint/status remapping.

The real store owner test covers both cancellation and an explicitly thrown
Forbidden with the same message, through direct creation and the public
transaction helper. It checks the distinct public variants, unchanged wire
response and absent session. The transaction cases also create a user before
the rejected session and confirm its rollback; direct cases retain their
already-created user. This independently protects type propagation through
the transaction facade and the public default response. Route-specific source
behavior belongs to a separate capability atop this prerequisite.

The transaction facade returns AuthError unchanged after rollback, and
SessionIssueError already retains it in Auth. The only exhaustive AuthError
match requiring an arm is status_code; ordinary error conversion uses the
existing wildcard. No schema, dependency, lock, inventory or comparator change
is needed. The coordinator owns independent review and integration.

Focused validation: the four-case real store test passes
(`/tmp/session-cancel-storage-native-final.log`); workspace library Clippy with
seaorm2 passes (`/tmp/session-cancel-storage-clippy.log`). Formatting and diff
checks pass. This prerequisite does not claim endpoint-specific null-session
responses; those require their own public-boundary regression.
