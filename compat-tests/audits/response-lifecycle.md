# Pinned response lifecycle contract

The `better-auth@1.7.6` runtime in `dist/api/dispatch.mjs` runs matching response
hooks after endpoint success and API errors. A before hook returning a response
short-circuits that pipeline. Matching after hooks retain headers already
emitted by the endpoint when another hook rejects the operation, and later
hooks can inspect that rejection.

Rust exposes this through `AuthPlugin::after_request`, using the normalized
authentication path and the internally established session. Typed context
extensions are registered during initialization and shared with trusted
server-only callers. Client-supplied request state is discarded at dispatch.

Nested handlers can queue response headers on their request. Internal clones
share this accumulator, allowing session middleware to forward renewal cookies
to an outer endpoint. Cookies retain their order and multiplicity, survive an
endpoint rejection, and are visible to response hooks. Incoming requests start
with a new accumulator, so queued caller state and earlier requests cannot
inject response headers.

Eight native integration regressions exercise initialization, normalized paths,
virtual session propagation, forged request rejection, early responses,
endpoint/after-hook rejection, nested cookies, ordering between response hooks,
unknown-route isolation and the initialized email provider used by both handlers
and server-only callers. Two controlled differential scenarios use the official client and genuine
pinned middleware hooks. They prove persisted signup/session/account state and
browser authentication after an after-hook rejection, wrong-password rejection,
header visibility between hooks, before-hook write suppression, and empty
unregistered routes/methods. The focused core suite passes 22 scenarios with 62
assertions; no comparison exceptions or oracle behavior changes were introduced.
The full canonical gate remains required for this extracted branch. JWT and
one-time-token response hooks are separate capabilities.
