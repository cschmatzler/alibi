# Facebook provider (issue #144)

The authority is the installed unchanged Better Auth 1.7.6 Facebook factory and
its declared profile/options, shared token helper, actual provider ID verifier,
and JOSE remote JWKS selection/claim validation. The application must exercise
that real factory with deterministic local HTTP responses and real signed tokens;
controls may not invent admission, physical rows, or callback receipts.

## Audited contract

Authorization requires a primary client ID and client secret. It uses Facebook
v24.0 dialog OAuth, ordered duplicate-preserving email/public_profile defaults,
configured and requested scopes, form query encoding, loginHint, and optional
config_id. Disabled defaults and trusted authorize/redirect overrides remain
explicit. The factory omits PKCE from both authorization and code exchange.
Token and refresh forms use the v24.0 Graph endpoint; client_key is code-only.
No provider remote logout operation exists.

Limited Login is a real RS256 JWT verified against the fixed limited.facebook.com
JWKS authority, https://www.facebook.com issuer, all configured client audiences,
and exact requested nonce. Its published policy has no maximum token age;
iat is optional, although present numeric dates must retain JOSE type checks.
Remote JWKS filters key type, declared algorithm, key use, verify operations,
header key ID and public-key status, trying every usable duplicate candidate.
Other factories retain their distinct first-key, One Tap and Apple policies.

Non-three-part ID tokens are permitted by the verifier only as opaque candidates.
The user-info operation must independently use the supplied access token, query
Graph debug_token using a configured primary app credential, and require strict
is_valid true, a configured app ID and a truthy user ID. Only then may Graph /me
run, using bearer auth and ordered base-plus-configured fields. The returned
profile id must equal the inspected user_id before the application mapper runs.
An unrelated-app token or mismatched identity never reaches a mapper or write.

JWT profiles decode name/email/picture and default verified-email false without
Graph requests; Graph profiles use picture.data.url and nullish false verification.
The mapper receives the original profile. Physical identity resolves profile.sub
when that property exists, otherwise profile.id, independently of a mapped ID.
Missing/null/blank raw identity rejects at the established admission boundaries.
Async user-info/refresh overrides and signup switches remain available on the
returned native provider. Unsupported complex additional-field projections,
configured callback error composition and general malformed transport inputs
remain their existing #184/#181/#188/#193 issue scopes.

## Authoring and measured status

One strongest real SDK owner per contract will retain complete authorization and
token/profile/debug HTTP receipts, genuine signed JWKS proofs, original mapper
input, full physical account/user/session rows, foreign identity, proof replay,
rotation and local sign-out. Existing generic factories cannot prove Facebook
initialization or app-bound opaque-token validation, and existing age-bound
Google/Cognito owners cannot prove the optional-age policy.

This is read-only contract discovery. No factory, fixture, completed owner,
capability addition or green gate is claimed yet. An isolated actual-parent
before proof and independent authorization/persistence review are required
before this issue can close. No Source edit, comparator allowance, hook bypass
or dependency patch is authorized by this audit.
