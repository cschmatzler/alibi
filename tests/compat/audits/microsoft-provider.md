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

Implementation and genuine before/after owners are in progress. No pending proof
is represented as passing.
