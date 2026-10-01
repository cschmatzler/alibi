# HTTP base origins, callbacks and WebAuthn proof origins

The reference is published Better Auth 1.7.6, including its actual request
handler, origin middleware, email/username sign-in and passkey plugin. This
slice implements canonical HTTP(S) base-origin comparison and the measured
relative redirect path rules. HTTP URL parsing preserves default-port,
case, credentials and path/query origin semantics. Relative paths reject
encoded slash/backslash anywhere in the path, literal backslash and C0/C1
controls; query and fragment encoded separators remain valid.

Successful email and username sign-in now retain the callback URL, redirect
flag and Location header, including the observed empty-string body value
without a Location header. Two-factor redirects keep their existing branch.

The primary official-client scenarios retain complete transport, issued tokens,
current session identity, all prior persisted sessions and foreign-user state.
The real ES256 primary proves that accepting canonical HTTP request origins
preserves exact WebAuthn proof-origin comparison, challenge consumption,
registration ownership, authentication counters, session issuance and replay
rejection. No proof-origin validator or comparison normalization changed.

Evidence: original Rust fails all three primary scenarios for the intended
origin/path guard differences. Source-self passes 3 scenarios / 526 assertions;
final dual-server core family passes 30 / 878. Core native 156, existing
email-password native 10, strict core/API and fixture Clippy, locked fixture
build and client TypeScript checks pass. An independent review found leading
HTTP URL whitespace and accidental custom-base canonicalization: both are
corrected. The existing native custom-base contract demonstrably failed before
the latter repair and passes afterward.

Explicit trusted patterns, wildcard/host-only matching, custom-scheme Source
matching, dynamic origins/base URLs, environment/proxy settings and other
callback endpoint families remain separate audit boundaries. Existing native
custom-base behavior is preserved; Source custom-base support is not claimed.
Full integrated validation and coverage remain pending the next frozen gate.
