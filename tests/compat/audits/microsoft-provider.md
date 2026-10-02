# Microsoft Entra ID provider (issue #152)

The installed better-auth 1.7.6 factory is
`@better-auth/core/dist/social-providers/microsoft-entra-id.mjs`, with its public
types in the adjacent declaration. This work starts from actual main
`4bcd25c3084ac16b39c96b8dc42804f80dc21900`; #291 is independently frozen and its
receipt/ledger migration will be retained on composition.

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
The original oid must be a nonblank string before photo lookup or mapping.

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

## Deferred implementation checkpoint

The user reprioritized OAuth providers after all other issues. This draft is
paused as an incomplete checkpoint; it is not ready to merge. The initial public
factory, authenticated-claims policy and asynchronous assertion transport are
present, but their actual tenant/cryptographic/photo/grant owners have not run.
The native fixture intentionally remains the generic before-proof configuration
and has not been switched to the new factory. Its default-scope owner therefore
remains an intended failure, not a final acceptance test.

Before production edits, strict fixture build and TypeScript pass in
`/tmp/issue152-generic-before-build.log`. The actual official SDK before owner is
terminal1,0/1,26 assertions in `/tmp/issue152-default-before-owner.log`: Source
returns all five default scopes before requested scopes; generic native returns
only requested scopes. Full foreign SQL preservation and Source PKCE assertions
remain measured. Both Cargo lockfiles and production were unchanged during that
before proof.

The already-running initial production-only command completes terminal0 in
`/tmp/issue152-production-first-strict.log`: workspace formatting and strict
`cargo clippy -p better-auth-api --all-targets --locked -- -D warnings`. This is a
compile/lint result, not native runtime parity or complete canonical validation.
No subsequent provider implementation or proof runs proceed after reprioritizing.
Outstanding work includes wiring the real factory into the fixture, all signed
tenant/account-class/nonce/key controls, real asynchronous assertion contexts at
both grants, refresh scopes and photo bytes, raw mapping/admission/foreign rows,
complete capability evidence, canonical/browser/docs/coverage and independent
final review. Root's approved design does not substitute for those measurements.
