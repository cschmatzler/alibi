# Generic OAuth discovery — #188 / PR #403

`GenericOAuthConfig::resolve` adds one-time discovery to native generic providers.
The URL and headers are trusted application configuration. Configured endpoint
options take precedence, including explicit empty strings. Successful discovery
fills authorization, token, user-info and end-session metadata. Failed HTTP,
JSON or issuer parsing falls back to configured endpoints; unusable discovery
providers are skipped. Invalid JWKS URLs skip the provider. Required verification
without usable discovery keys skips discovered providers or returns a sanitized
configuration error when no discovery was configured.

```rust,ignore
let mut generic = GenericOAuthConfig::new("configured-client", "configured-secret");
generic.discovery_url = Some("https://idp.example/.well-known/openid-configuration".into());
generic.provider.scopes = vec!["profile".into()];
generic.require_id_token_verification = true;
if let Some(resolved) = generic.resolve().await? {
    let metadata = resolved.metadata;
    let oauth = OAuthPlugin::new().add_provider("configured-idp", resolved.provider);
    // Register oauth with AuthBuilder; metadata remains application-owned.
}
```

Published Better Auth 1.7.6 generic-oauth enables OIDC scope/subject behavior
when discovery advertises signing algorithms, and verification only when issuer
and JWKS metadata exist. Native resolution follows those decisions. Verified
code-grant tokens must satisfy public key/signature, advertised algorithm,
issuer, audience, time and expected nonce checks before any custom profile
callback or principal write. Existing RSA public-key/modulus validation is reused.
Direct client ID tokens retain the existing fail-closed admission path. Decoding
a profile from a token delivered by the trusted code exchange is not a new
client-token authentication shortcut. Original profiles determine account
subjects independently of mapped user IDs. Requested scopes precede configured
scopes; openid is added only when absent. New policy switches default off for
all existing factories. Existing code/refresh transport, credential, static
parameter, header and PKCE helpers are byte-identical to #400's base.

The single generic SDK owner uses actual metadata/token/user-info HTTP servers
and actual SqlxStore and SeaOrmStore persistence. Seventeen Source/native
comparisons pass per adapter: discovery, overrides, fallback, invalid issuer,
unusable metadata/JWKS/required verification, mapped profile ownership, provider
HTTP errors, OIDC success and issuer/audience/nonce/signature/algorithm/expiry
rejections. Lifecycle observations include foreign refresh denial, rotation,
consumed-state replay, logout and complete users/accounts/sessions. Wrong OIDC
tokens produce zero custom callback receipts and no account/session writes.
Discovery headers and exactly one metadata fetch are asserted. Static grant
parameters, configured code headers, PKCE challenge binding and credential
transport are exercised through actual forms. Provider logout is explicitly
disabled in the Source fixture: RP-initiated logout is a separate remaining mode.

The original production base was restored exactly and compiled against the
same fixture transport. Because that base has no discovery API, the baseline
fixture uses its public static provider with omitted endpoints. Source completes
the discovery-only lifecycle while native start fails500 before any grant.
The preserved baseline production diff is empty. A review regression separately
records Source completing requested-scope order while native returned
`profile requested`; the resolver fixes it to `requested profile`. After that
scope and public-key review change, only the twelve affected lifecycle/OIDC
scenarios were rerun, passing for both adapters. The five unaffected skip/HTTP
error cases retain their earlier passing pairs.

Nonce comparison changes only add `nonce` and the `idTokenNonce` alias to the
existing identity bijection. Actual persisted state nonce equals the issued
URL nonce, and the signed JWT claim retains that identity. The focused comparator
regression fails before the aliases and passes afterwards; negative cases reject
missing or unequal URL, state and JWT nonce relationships. Its existing JWT/JWKS
control also passes. No global claim normalization or exclusions were added.
Raw forms, SDK transport/state pairs and original verification rows are retained
in the archives. The receipt names the two observation choices: metadata fetch
lists initialize at different times, and original state JSON bytes are retained
separately while their actual nonce binding is asserted and compared.

Fresh published better-auth/core 1.7.6 archives restored every installed runtime
file into a private inode before execution. The integrity manifest records raw
file hashes, equality and link counts; receipt.json records archive hashes.
Production check and strict Clippy, client typecheck, fixture-only reference
typecheck, focused TypeScript lint/format and whitespace validation pass.
Review was self-review with authz, data-exfil and test-audit; no independent
reviewer was delegated. GitHub Actions is disabled, so there are no CI results.
No full compatibility, development-environment or coverage gate was run.

The tested base, proof checkpoint and rebased production head are in receipt.json.
The final explicit Vec::Splice drop is the same statement-boundary drop as the
tested code and passed strict Clippy. Rebase onto #402/#404 preserves both commits
in range-diff; inspected upstream changes affect optional records/organization,
not OAuth transport or discovery. No passing tests/builds were replayed for that
unrelated rebase. Issue188 remains open for dynamic refresh parameter context,
RP-initiated logout and the broader callback/expiry/concurrency acceptance not
covered by these bounded modes.
