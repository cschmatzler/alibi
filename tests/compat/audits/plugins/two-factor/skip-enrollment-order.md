# Skip-enrollment persistence order

This bounded correction depends on the frozen verification-policy capability
234eccc. The published Better Auth 1.7.6 `plugins/two-factor/index.mjs`
139–169 updates the user, creates the replacement session and deletes the old
session before creating or updating the factor when skip verification is set.
The Rust owner previously persisted the factor first. A configured rejected
user update therefore left an orphan factor, and cancelled session creation
could replace a historical unverified factor despite failing enrollment.

The production change moves that existing factor write after the existing
skip-verification transition. It preserves password checks, authenticated
session ownership, replacement-session fields, errors and normal enrollment.
It adds no transaction, rollback, schema field or store operation: the source
intentionally retains an accepted user update when subsequent session creation
is cancelled.

The official-client scenario owns the HTTP user-update rejection contract.
Equivalent real database hooks reject a valid enrollment with APIError 400
`USER_UPDATE_DENIED`; an incorrect password independently fails before the
hook. The test reads the actual SQLite user, factor and session state, confirms
no factor was written, and retains the original signed-cookie owner/token.
It fails against the frozen pre-fix owner because `twoFactorExists` is true
(`/tmp/two-factor-skip-order-sdk-before.log`) and passes after the repair.
All response fields remain part of the ordinary comparison.

The native route test independently owns lifecycle cancellation and historical
generation preservation, which the public SDK case cannot seed or inspect in
full. Its four cases use actual DatabaseHooks with fresh or existing unverified
factors, and either a rejecting user update or cancelled session creation.
They assert callback owner/order, original encrypted generation and clocks,
nullable/fractional policy fields, original session and its org/team/admin/
IP/agent fields, and continued signed-cookie ownership. User rejection leaves
the user flag false; session cancellation retains the accepted true flag.
The pre-fix test fails on the orphan factor
(`/tmp/two-factor-skip-order-native-before.log`). No test-only production seam
or mocked persistence supplies those states.

An independent four-case runtime probe invokes the actual pinned handler with
equivalent configured hooks and queries its real SQLite rows
(`/tmp/two-factor-skip-order-oracle.log`). It confirms the write order and
retained user flag. It also confirms a separate wire limitation: source
session-create cancellation yields an empty 500 response, while the existing
Rust store currently returns its documented Forbidden 403 cancellation error.
This commit preserves that error contract; a separately coordinated typed
session-create cancellation capability will map only that semantic error at
the relevant route. Genuine application 400/403 errors must remain unchanged.

Focused validation: ten native two-factor tests pass
(`/tmp/two-factor-skip-order-native-final.log`); nineteen distinct official SDK
scenarios / 652 assertions pass
(`/tmp/two-factor-skip-order-sdk-family-final.log`), including the new scenario
/ 22 assertions. Client TypeScript and workspace library Clippy with seaorm
pass; formatting and diff checks pass. No comparator exemption, skip, timeout,
coverage, dependency, lock, migration or shared inventory change is made.
The coordinator owns independent review and canonical gates.
