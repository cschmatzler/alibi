# Naver provider (issue #153)

Authority is the installed unchanged Better Auth 1.7.6 Naver factory/types and
actual grant helpers. Authorization uses nid.naver.com/oauth2.0/authorize with
ordered profile,email defaults and configured/requested duplicate scopes.
The factory supplies neither codeVerifier nor loginHint: no PKCE or login_hint.
Trusted authorization/redirect overrides remain. nid.naver.com/oauth2.0/token
uses public or secret-post credentials, code-only client_key, no default token
lifetime invented, and real refresh behavior which ignores clientKey.

Bearer GET openapi.naver.com/v1/nid/me must have exact string resultcode00 before
mapping. HTTP errors, null data or another resultcode deny before the mapper.
The application mapper receives the whole original envelope before admission.
profile.response.id binds account identity independently of mapped ID;
name uses response.name or nickname or empty, image uses profile_image, email
uses response.email and verified-email defaults false. message does not replace
the resultcode condition. Missing/null response still reaches mapper with the
valid resultcode envelope, then fails raw identity. Existing account-info reads
without new identity admission. No built-in ID-token verifier/JWKS or remote
logout exists; generic trusted async hooks remain configurable on the provider.

Authoring gate: one actual Source factory/SDK owner table independently protects
ordered Naver defaults, absent PKCE/loginHint, exact envelope/resultcode gate,
truthy name fallback and whole-envelope mapper/raw subject ordering. Existing
flat/envelope-first/GraphQL providers cannot detect this Naver contract. Retain
actual authorization/token/userinfo requests, all complete mapper/physical/foreign
rows, signed-session/state/replay, refresh/link/getter and local logout. No
private helper test or test-only production export. Arbitrary malformed complex
projection and broader lifecycle/framework modes remain181/184/188/193; retain
any actual owner failure rather than erasing unsupported fields.

Implementation, before proof, independent review and final gates pending.
