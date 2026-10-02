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
header key ID and public-key status, rejecting ambiguous matching candidates. The installed jwtVerify does not
consume the resolver's optional retry iterator; the actual factory returns
INVALID_TOKEN for both valid-after-wrong and valid-after-malformed duplicates.
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

The initial factory passes strict Clippy and the real application fixture passes
strict Clippy/build. The initial actual Source/native program passes 55/57 owners
(1,980 assertions, /tmp/issue144-initial-real-owner.log, terminal exit1). Two
oracle-side expectations incorrectly inferred automatic duplicate-key retries
from the remote resolver iterator; actual installed jwtVerify propagates the
ambiguous-key error. Native policy and those expectations are corrected to
measured factory rejection; Source and comparer stay unchanged.
The corrected and expanded actual program passes all 89 owners (2,978 assertions,
`/tmp/issue144-final89-owner-strict.log`, terminal exit 0), including strict API
and fixture all-target Clippy, fixture build and TypeScript checking. The initial
86-owner program also passed (`/tmp/issue144-expanded86-real-owner-correct-type.log`,
2,880 assertions). Real 1024-bit RSA signed credentials are rejected by both
actual factories before identity writes. An independent production review of
app/user binding, raw identity, nonce/signature, remote key selection and other
factories found one optional-age numeric-date drift: JOSE accepts numeric
`iat:1e500` and `iat:-1e500` when no age policy exists. Both real Source halves
passed while the initial Native finite-only check failed
(`/tmp/issue144-numeric-before.log`, 1/3 passing, terminal exit 1). Native now
retains numeric type validation and applies the existing age comparisons only
where configured; the two raw signed owners pass without changing Google,
Apple or Cognito's one-hour limits.

The isolated actual-parent before proof preserves unchanged 358f5f6a production
and uses the exact real Source/HTTP controls with the old public generic provider.
It compiles, then fails for the intended native authorization drift: an unexpected
PKCE code challenge, while the Source default owner passes
(`/tmp/issue144-generic-before-owner.log`, 25 assertions, terminal exit 1).
No 404, unavailable constructor or fabricated receipt is used as before evidence.
On frozen d19a4d271f8f7c3c7054789861569a4c1ebffb4d composed on actual main
fa8837ec, the canonical `scripts/check.sh` run passes both strict default and
optional-feature workspace all-target Clippy matrices, Rustls checking, both
formatting checks, 794 default native tests, 845 optional native tests, two fixture
tests, TypeScript, all 71 harness checks (754 assertions), 36 Axum checks, three
endpoint checks and two inventory checks. Full SDK execution passes 1,203/1,209
owners, 80,762 assertions, including all 89 Facebook owners
(`/tmp/issue144-current-final-canonical.log`, terminal exit 100). Six remaining
failures are two organization owners with eight timestamp aliases, configured
remote JWT finalReceipts.events1/2/3.payload.exp, and the three generated
seed12648430 snapshot22 Unauthorized code/message comparisons owned by #221.
The configured signer exact exp aliases were already observed in the independent
main Source/Source1000 capture; no claim is made that that counterfactual proves
every organization timing alias. The full canonical gate is not claimed green.

Separately, documentation with warnings denied and both actual browser owners
pass (`/tmp/issue144-current-docs-browser.log`, terminal exit 0, 22 browser
assertions). Clean real instrumented execution passes all 845 native tests and
all five SDK groups, retaining unchanged assertions and exclusions. Complete
fixture/native production line coverage is 31,204/40,435 = 77.170768%, above the
unchanged 75% floor (`/tmp/issue144-current-clean-coverage.log`, terminal exit 0).
The complete collector adds only --no-fail-fast to collect all existing SDK
groups; both coverage target environment variables point at this checkout's
isolated coverage/target. Ordinary gates retain the repository build cache.

All 3,947 actual parent capability requirements remain in their original order;
338 measured Facebook cells are appended, totaling 4,285. Every added cell is
present in final actual passing Source/native evidence. Foreign signup/setup
routes and unclassifiable callback denials are excluded. Final publication edits
are audit text only; production, fixtures, tests, lockfiles and capability bytes
remain identical to the frozen measured head. No Source edit, comparator allowance, hook bypass
or dependency patch is authorized by this audit.
