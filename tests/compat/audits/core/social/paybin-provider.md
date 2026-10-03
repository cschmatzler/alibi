# Paybin provider contract (issue #155)

Authority: published Better Auth **1.7.6** `@better-auth/core/dist/social-providers/paybin.mjs`, its declarations, account-subject resolver, authorization helper and code/refresh token helpers. The unchanged published Source factory runs on deterministic local HTTP: only its actual fixed issuer token destinations are redirected. Native uses `OAuthProvider::paybin` / `paybin_with_options(PaybinOptions)`. Controls supply grant responses, never callback admission or database rows. The official-client owner is `tests/core/social/paybin.test.ts`.

Authoring gate: this owner independently protects Paybin's issuer endpoint construction, PKCE grant, ordered scopes, decoded grant-profile fallback and original account subject. Credible regressions include normalizing issuer slashes, deduplicating scopes, dropping PKCE, using Basic credentials, fetching an invented userinfo URL, replacing raw subject with mapper ID, or inventing JWT verification. Other provider owners do not instantiate this factory. Mapping variants share one table; lifecycle cases retain actual transport and persisted owner/foreign rows. No production test-only seam is added. Optional `COMPAT_OBSERVATIONS_DIR` diagnostics retain both complete observations and raw traces before the unchanged comparator runs.

## Protocol

Issuer is `options.issuer || "https://idp.paybin.io"`. Authorization and token endpoints append `/oauth2/authorize` and `/oauth2/token` without trimming a trailing slash. Authorization endpoint and redirect URI overrides use nonempty configured values. Client ID and secret are required when authorization starts; PKCE is mandatory and the persisted verifier produces the observed S256 challenge. Default scopes are `openid email profile`, followed by configured then requested scopes, preserving duplicates and order. Disabled defaults remove only those defaults; no scopes omit `scope`.

Nonempty login hints and configured prompt are forwarded; allowed additional parameters can replace prompt. The official sign-in route rejects reserved state, client, redirect, scope, response-type, nonce and PKCE additions. `responseMode` is not forwarded by this factory. There is no discovery, userinfo endpoint, ID-token nonce generation, provider revocation or RP logout.

Code and refresh requests use client-secret-post; optional client key appears only in the code form. Code includes the state-owned PKCE verifier and configured/default callback URI. Refresh sends only refresh token and client credentials. Token redirects are refused. Absent and zero token expiry remain null; fractional seconds preserve milliseconds. Refresh rotates stored tokens while preserving existing scope, user rows, foreign accounts and sessions. Sign-out revokes only the local session and sends no provider request.

## Identity

Without a grant ID token, the factory returns no user information. Otherwise it **decodes** the JWT payload; it does not verify signature, issuer, audience, expiry or nonce. A real separately signed grant with foreign issuer/audience/nonce and expired claims is admitted, explicitly demonstrating the published limitation. Direct ID-token sign-in is unsupported and rejects before HTTP. There is no JWKS operation to exercise.

Account subject derives from the original `sub` independently of application mapping; missing/null/empty subjects deny and numeric subjects use JavaScript string formatting. The mapper receives the original payload before subject denial. Its mapped ID stays in public account-info output but cannot replace persisted account identity.

Name uses `name || preferred_username || ""`, retaining absent/null/empty/zero fallbacks and numeric values. Email is the original email; absent/null/empty denies admission. Image preserves absence, explicit null, empty and numeric values in account-info; typed persistence stores scalar strings. `emailVerified` preserves `email_verified || false` in raw output; native typed persistence matches Source's boolean conversion (numeric `42` persists false). Mapper fields override the public defaults. Unknown payload fields remain in account-info `data`.

## Proof and self-review

The targeted suite retains authorization URLs, actual issuer-path code/refresh receipts, real independently signed token payloads, complete canonical users/accounts/sessions including account passwords, account-info responses, replay and signup/verified-email controls. Invalid provider, direct proof, unissued state, issued state without its bound cookie, reserved parameters and missing credentials cause no provider requests. Foreign refresh denial causes no writes or HTTP; owned refresh rotates credentials. No comparator exclusions or normalization rules were added.

Self-review traced callback state consumption before code exchange; `resolve_account_subject` before linking/persistence; and `AccountSelection::resolve` through `get_user_accounts_record(session.user_id)` before refresh. No authorization bypass was found. The issuer comes from trusted application configuration. Decoded grant claims follow the exact Source contract; arbitrary direct claims cannot enter this flow.

The baseline native API fails to compile the new real fixture with E0432/E0599 (missing `PaybinOptions` / `paybin_with_options`). Initial targeted runs also caught wrong expectations for numeric verification, attempting to override reserved parameters, and preserved the residual errors below. The final targeted dual-adapter receipts and lint/typecheck results are recorded in the PR. Full-suite and source-instrumentation campaigns remain coordinator-owned; no full gate was run locally.

## Explicit residuals — issue remains open

- Numeric email is outside the declared string profile shape. Source redirects with `internal_server_error`; native currently redirects with `email_not_found`. The independently signed numeric-email callback preserves foreign rows on both adapters, but exact raw error parity is not claimed.
- Malformed grant JWT: Source throws and its real auth route returns HTTP 500; native denies with HTTP 302 `unable_to_get_user_info`. Neither admits or writes. Exact raw error parity is not claimed.
- Application-owned asynchronous userinfo/refresh overrides remain available on the returned generic provider, but dedicated Paybin override/encrypted-token permutations and broader instrumented coverage are not established here.

The two error residuals are retained as explicit failing comparisons outside the passing canonical owner, with both raw observations and reproduction source archived. They are not hidden by skips, blanket normalization or a generic error expectation. This scoped PR does not close #155.

Evidence archive: `/home/cschmatzler/.local/share/better-auth-rs-evidence/issue155/` retains pinned published factory/helpers and package metadata, baseline/initial failures, final SQLx/SeaORM raw observations and route evidence, residual reproduction source/receipts and validation logs. The owned worktree/target cleanup preserves this archive.
