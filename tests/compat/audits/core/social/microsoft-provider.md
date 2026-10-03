# Microsoft Entra ID provider (issue #152)

The installed better-auth 1.7.6 factory is
`@better-auth/core/dist/social-providers/microsoft-entra-id.mjs`, with its public
types in the adjacent declaration. The initial proof started from `4bcd25c3`; the completed implementation rebases only its own draft work onto `74309f36`, retaining the current fixture layout and requirement inventory.

The factory orders openid/profile/email/User.Read/offline_access before
configured and request scopes, uses PKCE and loginHint/prompt, strips authority
trailing slashes, and defaults to the common tenant. Code grants support
secret-post/public authentication, code-only clientKey and genuine asynchronous
clientAssertion; secret plus assertion is a constructor error. Refresh carries
the exact default/configured scope string and the same assertion callback, while
ignoring clientKey. Token helpers refuse redirects and preserve actual expiry
semantics. There is no provider logout operation; the local session logout is
the applicable supported lifecycle.

Direct submitted ID tokens require the actual selected JWK signature, audience,
one-hour iat bound and exact optional nonce. A specific tenant has a fixed issuer;
all configurations additionally bind signed tid to the configured authority's
issuer and restrict organizations/consumers to their actual account class.
Tenant claims never select the HTTP/JWKS authority. Code callbacks decode the
exchange ID token rather than imposing the separate direct-token verifier.
The original oid must be a nonblank string before photo lookup or mapping. The default public profile preserves missing/null/numeric JSON independently of typed physical values through the existing `user_output` interface.

Profile-photo requests fetch actual Graph bytes at the configured supported size
(default48), use access-token bearer authorization, and augment the original
profile before the mapper. Non-success photo responses retain the original
picture. Raw oid remains the account key; the application mapper cannot replace
it. Email-verification optional/list claims and absent/null/empty/numeric profile
fields require measured Source cases rather than assumptions.

The primary owner is the actual official SDK over unchanged Source and native
HTTP servers, real locally signed keys, actual provider transport receipts and
complete SQL rows including foreign principals. Credible before regressions are
missing factory defaults, skipped protocol callbacks, incorrect proof/tenant
admission and incorrectly mapped persistence. Existing provider owners cannot
prove Microsoft's configured tenant, assertion and photo protocols. No test-only
production seam, fake principal, Source package patch or comparator change is
needed. The bounded shared assertion/refresh-scope interface serves actual public
application configuration, with its callback context observed at both grants.

## Executable evidence

The canonical owner is `tests/compat/client-tests/tests/core/social/microsoft.test.ts`.
Its 75 actual SDK scenarios cover configured authorization and tenants, real
cryptographic/key/nonce/audience/age/account-class admission, exact trusted JWKS
destinations, raw oid admission before optional photo or mapping, real photo
bytes and supported size, asynchronous assertion contexts at both grants,
code-only clientKey, refresh scope, decode-only exchanged ID tokens, redirect
refusal, foreign refresh rejection, replay and logout. The mapper owner proves
additional public properties and mapped id remain separate from the real raw
account identity. The original profile table owns null/missing/empty/numeric
public account-info values, complete SQL records and foreign preservation.

The public application factory's secret-plus-assertion constructor error is
measured by the default authorization owner. Source's ignored disableSignUp
option is measured as an allowed direct sign-in; its forwarded
`disableImplicitSignUp` remains denied unless the client explicitly asks to sign
up. These expectations come from the unchanged pinned published factory and
create-context implementation.

Before the initial factory implementation, `/tmp/issue152-default-before-owner.log`
is terminal1 at the SDK boundary: Source provides all five defaults, the generic
native provider provides only requested scopes. The initial strict fixture build
is `/tmp/issue152-generic-before-build.log`.

Before the public-profile repair, `/tmp/pr296-public-mapping-before2.log` is
terminal1 with six passing cases and five intended failures: null name, numeric
name, numeric image, null image and explicit null email_verified. Each Source leg
passes the independently asserted raw public shape; native loses or coerces the
value. The existing user_output interface repairs those shapes while retaining
the original typed persisted values. An earlier attempted owner lacked an
account access token and is not claimed as a mapping regression.

Current focused canonical SDK execution is terminal0: 75/75 and 2,594 assertions
in `/tmp/pr296-focused-final.log`. Independently launched unchanged Source/Source
and Source/native pairs each pass the same 75 scenarios and 2,594 assertions in
`/tmp/pr296-source-self75.log` and `/tmp/pr296-native75-evidence.log`.
Source-self validates the expectations; it is not native parity evidence.
Actual source/native route evidence sets are identical. The capability additions
are only measured provider operations; shared signup/session scaffolding is not
re-claimed. `/tmp/pr296-independent-recount.json` records the exact cell set and
preserved baseline. Production and native fixture strict clippy both pass in
`/tmp/pr296-strict.log` and `/tmp/pr296-fixture-strict.log`.

Authorization/data-exfiltration review traced direct signed claims to configured
JWK destinations, authenticated original oid to physical account ownership, and
observed application assertion callbacks to fixed token requests. Claims do not
select network authorities. No ownership or credential destination blocker was
found. Trusted application overrides remain ordinary production configuration.

Full unchanged `devenv shell -- ./scripts/check.sh` is still pending. No coverage
floor, pin, comparator, harness control or comparison field has been relaxed.
