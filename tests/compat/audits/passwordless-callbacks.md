# Passwordless callback request and delivery contexts

The oracle remains published Better Auth 1.7.6. Its actual email-OTP generator
and sender, magic-link sender, phone OTP/reset sender, external verifier and
verification-completion hook receive an endpoint context. Magic-link token
creation and phone-number validation receive only email and number respectively;
those native scalar callbacks remain scalar.

Native callbacks now receive an owned `CallbackContext`. Its optional actual
`AuthRequest`, original `RequestHookContext`, and admitted `EndpointCall` retain
transport input and logical transformed input independently. A checked
`context::<ApplicationSchema>()` accessor returns the initialized native context
and its real hook-aware store. The context shares the actual instance's store,
configuration and extensions rather than exposing a TypeScript-shaped adapter.
Trusted calls without HTTP input retain no fabricated physical request.
The original request retained by request hooks also reaches verification
callbacks invoked through an override or signup transaction that does not pass
an explicit request to the existing override trait.

Email and phone notification work owns the sender, delivery and callback
context. The default native policy propagates awaited errors. The explicit
LogAndContinue policy matches the pinned runtime's lifecycle catch boundaries.
Configured background delivery starts hot work, logs delivery/observer failures,
and survives a dropped completion observer. Phone send-OTP retains its direct
await/propagate boundary when background execution is absent. Magic-link
sending always awaits directly, matching Source even when background handling
is configured. Issuance precedes sending, and failures retain the actual proof.

Primary new HTTP evidence captures callbacks in both actual servers, reads the
real adapter at delivery/completion time and consumes the actual delivered code
or link. Three scenarios cover email generation/delivery, magic-link delivery,
phone delivery/external verification/completion, OTP verification override,
current-mailbox/new-mailbox change, and password reset. Phone completion reads
the persisted verified owner after proof deletion. Full account/session/user
state, foreign recipient rejection and replay remain explicit assertions.
Source ingress bytes are captured before its router consumes the Request body;
that capture supplies no proof, acceptance result or callback ordering.
Random request proof values retain local exact-code assertions and are compared
through the existing opaque token identity contract; no comparer changes apply.
The initial two scenarios completed Source and failed the earlier native fixture
because callback context was absent.

The existing passwordless HTTP and SQLite owners retain expiry, attempt limits,
wrong operation/user/mailbox, concurrent one-use consumption, signup/anonymous/
two-factor combinations, reset policy ordering and storage-policy evidence.
The email delivery error owner now spans ordinary/coded errors under both
native awaited policies, independently proving persisted proof, successful
later consumption, exactly one session and replay rejection. A distinct native
lifecycle owner pauses real delivery, rejects/drops its completion observer,
drops the initiating request, then resumes delivery against the live store and
consumes its retained proof. It does not replace or mock issuance/consumption.

Focused check results and broader pre-existing failures are recorded in the PR.
This change does not change the Source pin, public route inventory, required
evidence, comparison policy or coverage floor.
