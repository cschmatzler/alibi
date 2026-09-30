# Persistent session reads

Reference: the installed, pinned `better-auth@1.7.6` session routes and
`getSessionFromCtx` middleware. This slice depends on the email-verification
caller fixes and millisecond organization date serialization.

The refresh deadline is persisted `expiresAt - expiresIn + updateAge`, not
`updatedAt`. A refresh keeps identity and token, returns the updated persisted
snapshot, and renews the signed cookie. Deferred GET reports `needsRefresh`
without changing storage; POST performs refresh or expired-row cleanup.
Configured refresh suppression and the first signed nonempty `dont_remember`
cookie are honored. The published official client sends the undocumented
signup `rememberMe` option through its supported `fetchOptions.body` merge.

Revocation authenticates against persistent storage and never refreshes its
target. List-sessions applies the default one-day freshness check; zero and
`None` disable it. Missing/expired sessions and signout clear configured session,
account and OAuth state cookies in the source order. Direct explicit application
errors keep their status and body; nested middleware still rejects authentication.

Evidence: 13 focused SDK scenarios / 294 assertions; six public-builder SQLite
integration tests for refresh, deferred cleanup, nested middleware, foreign
revocation, deletion during update and failed writes; two public-builder policy
and signed-empty-cookie regressions; session-manager unit tests. The latter
cookie test verifies its signature decodes to the empty string before testing
the parser. Removing the empty-token guard renews the actual empty-token row
and wrongly returns its owner; removing policy-error preservation changes 403
to 500. Both negative controls fail for the intended reason.

Independent review resolved refresh error handling, freshness defaults,
configured signout cleanup and the signed-empty-cookie test input. Canonical
validation is recorded on the PR after the frozen tree passes the full gate.

Remaining boundaries: cookie-cache/stateless and secondary-only session modes,
chunked cache/account-cookie cleanup, plugin-specific consumers of session
middleware, and broader configuration combinations require additional slices.
Passing these scenarios does not establish complete session or repository parity.
