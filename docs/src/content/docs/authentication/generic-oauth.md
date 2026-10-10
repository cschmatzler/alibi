---
title: "Generic OAuth / OIDC"
description: "Connect any OpenID Connect or OAuth 2.0 server — Keycloak, Auth0, Okta, Authentik — with discovery, ID-token verification and provider logout."
---

The [built-in providers](/authentication/social-sign-on/#provider-catalog) cover well-known services. For anything else — your company IdP, Keycloak, Auth0, Okta, Authentik, Zitadel, a self-hosted GitLab — use `GenericOAuthConfig`. It builds an ordinary `OAuthProvider` from an OIDC discovery document or explicit endpoints, so everything on the [social sign-on](/authentication/social-sign-on/) page (flows, linking, tokens, state) applies unchanged.

## Connect an OIDC provider

Discovery is performed **once, at startup**, from operator-supplied configuration — never from request input. Resolve the configuration, then register the provider:

```rust
use crate::auth_schema::AppAuthSchema;
use alibi::plugins::OAuthPlugin;
use alibi::plugins::oauth::GenericOAuthConfig;
use alibi::sqlx::SqlxStore;
use alibi::{AuthConfig, AuthError, AuthResult, Alibi};

async fn build_auth(
    config: AuthConfig,
    store: SqlxStore<AppAuthSchema>,
) -> AuthResult<Alibi<AppAuthSchema>> {
    let mut keycloak = GenericOAuthConfig::new("my-client-id", "my-client-secret");
    keycloak.discovery_url =
        Some("https://sso.example.com/realms/acme/.well-known/openid-configuration".into());
    keycloak.provider.scopes = vec!["openid".into(), "profile".into(), "email".into()];

    let resolved = keycloak
        .resolve()
        .await
        .map_err(|error| AuthError::config(error.to_string()))?
        .ok_or_else(|| AuthError::config("Keycloak discovery returned no usable endpoints"))?;

    Alibi::<AppAuthSchema>::new(config)
        .store(store)
        .plugin(OAuthPlugin::new().add_provider("keycloak", resolved.provider))
        .build()
        .await
}
```

The redirect URI to register at the IdP is `{base_url}/api/auth/callback/keycloak` (the id you pass to `add_provider`). Users start with `POST /sign-in/social` and `{"provider":"keycloak"}`.

`resolve()` returns:

| Result | Meaning |
| --- | --- |
| `Ok(Some(resolved))` | A usable provider, plus `resolved.metadata` (issuer, JWKS URL, signing algorithms, end-session endpoint) |
| `Ok(None)` | Discovery was configured but yielded no authorization or token endpoint — **skip** the provider |
| `Err(error)` | Contradictory configuration, for example required ID-token verification without JWKS metadata, or secretless public-client auth with a secret set |

If discovery fails to download, the explicit endpoints you configured are used as a fallback.

## Configuration reference

| `GenericOAuthConfig` field | Purpose |
| --- | --- |
| `provider` | The underlying `OAuthProvider`: `scopes`, `authorization_params`, `disable_sign_up`, `disable_implicit_sign_up`, `require_email_verification`, … |
| `discovery_url`, `discovery_headers` | OIDC discovery document and any headers it needs |
| `authorization_url`, `token_url`, `user_info_url` | Explicit endpoints. Any value you set **overrides** discovery |
| `end_session_endpoint`, `post_logout_redirect_uri`, `disable_provider_logout` | Provider logout (below) |
| `require_id_token_verification` | Fail at startup unless discovery supplies keys to verify ID tokens |
| `disable_id_token_nonce_binding` | Do not bind the ID token to a per-request nonce |
| `map_profile` | `Arc<dyn OAuthProfileMapper>`: map the raw profile onto your user/additional fields |
| `access_token_expires_in` | Fallback lifetime (seconds) when the token response has no `expires_in` |
| `account_key` | Application resolver for the stable account identifier |

Behavior you get automatically with discovery metadata:

- ID tokens from the code grant are verified against the provider's JWKS (issuer, audience = your client id, allowed algorithms) before the profile is admitted, and a nonce binds the response to the browser that started the flow.
- `openid` is added to the scopes when the provider advertises OIDC signing algorithms.
- The account identifier is the `sub` claim for OIDC providers and the profile `id` for plain OAuth 2.0.
- PKCE is used by default.

### IdP-initiated authorization

Set `provider.allow_idp_initiated = true` to accept a callback containing a code without state. The server redirects to a fresh authorization flow with new state and PKCE. It exchanges no grant and creates no identity until the browser returns through the normal state-bound callback. The default is `false`.

### Plain OAuth 2.0 (no discovery)

```rust
use alibi::plugins::oauth::GenericOAuthConfig;

fn custom_oauth() -> GenericOAuthConfig {
    let mut custom = GenericOAuthConfig::new("client-id", "client-secret");
    custom.authorization_url = Some("https://auth.example.com/oauth/authorize".into());
    custom.token_url = Some("https://auth.example.com/oauth/token".into());
    custom.user_info_url = Some("https://api.example.com/v1/me".into());
    custom.provider.scopes = vec!["profile".into(), "email".into()];
    custom.access_token_expires_in = Some(3600.0);
    custom
}
```

Without an ID token, the profile comes from `user_info_url` (a bearer-authenticated GET). The default mapping reads `id`, `email`, `name`, `image` and `email_verified`; use `map_profile` for anything else.

### Token endpoint authentication and extra parameters

Fine-grained transport options live on the provider's authorization policy:

```rust
use alibi::plugins::oauth::{GenericOAuthConfig, OAuthTokenEndpointAuth};

fn tuned(mut custom: GenericOAuthConfig) -> GenericOAuthConfig {
    if let Some(policy) = custom.provider.authorization.as_mut() {
        // How the client authenticates at the token endpoint.
        policy.token_endpoint_auth = Some(OAuthTokenEndpointAuth::ClientSecretBasic);
        // Extra form fields on the authorization-code exchange.
        policy
            .authorization_code_params
            .insert("audience".into(), "https://api.example.com".into());
        // Extra form fields on every refresh.
        policy
            .refresh_token_params
            .insert("audience".into(), "https://api.example.com".into());
        // Sent on the authorization request.
        policy.fixed_authorization_params.push(("prompt".into(), "select_account".into()));
    }
    custom
}
```

`OAuthTokenEndpointAuth` supports `ClientSecretBasic`, `ClientSecretPost`, `PrivateKeyJwt` and `None` (public clients). Use `PrivateKeyJwt` with an `OAuthClientAssertion` getter (or `OAuthPrivateKeyJwtOptions`) that returns a freshly signed assertion for each token request. Refresh parameters can also be computed per request with `OAuthRefreshTokenParamsResolver` — validate tenant and scope entitlements before forwarding anything derived from request data.

## Provider logout

When discovery advertises an `end_session_endpoint` (or you set one), `POST /sign-out` for a session created through this provider answers with the provider's logout URL after clearing the local session:

```bash
curl -b cookies.txt -X POST http://localhost:3000/api/auth/sign-out \
  -H 'Content-Type: application/json' -H 'Origin: http://localhost:3000' \
  -d '{"callbackURL":"https://app.example.com/signed-out"}'
# {"success":true,"url":"https://sso.example.com/realms/acme/protocol/openid-connect/logout?id_token_hint=…&post_logout_redirect_uri=…","redirect":true}
```

Pass `"disableRedirect": true` to receive the URL without a redirect. `post_logout_redirect_uri` sets a default return URI; `disable_provider_logout` keeps sign-out local. The `callbackURL` must be a [trusted redirect target](/concepts/security/).

## Common setups

| Provider | Discovery URL |
| --- | --- |
| Keycloak | `https://<host>/realms/<realm>/.well-known/openid-configuration` |
| Auth0 | `https://<tenant>.auth0.com/.well-known/openid-configuration` |
| Okta | `https://<org>.okta.com/.well-known/openid-configuration` (custom auth server: `/oauth2/<id>/…`) |
| Authentik | `https://<host>/application/o/<slug>/.well-known/openid-configuration` |
| Google Workspace (custom) | `https://accounts.google.com/.well-known/openid-configuration` |

Register one provider id per IdP: `add_provider("acme-sso", …)`, `add_provider("partner-okta", …)`.

## Frontend

The official client talks to the same `/sign-in/social` endpoint. For the typed `signIn.oauth2` helper of the TypeScript generic-oauth plugin, call `signIn.social({ provider: "<id>" })` instead; the server has no separate `/sign-in/oauth2` route. See the official [Generic OAuth guide](https://www.better-auth.com/docs/plugins/generic-oauth) for client-side usage.
