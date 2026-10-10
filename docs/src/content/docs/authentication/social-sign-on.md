---
title: "Social sign-on"
description: "Sign in and link accounts with 36 built-in OAuth providers: setup, flows, scopes, tokens and customization."
---

`OAuthPlugin` implements OAuth 2.0 / OpenID Connect sign-in with PKCE, state protection, account linking and token storage. Provider credentials stay on the server. The plugin is installed by the builder with no providers; register your own to enable it.

Not finding your provider? Use [Generic OAuth](/authentication/generic-oauth/) for any OIDC or OAuth 2.0 server (Auth0, Keycloak, Okta, …).

## Setup

```rust
use crate::auth_schema::AppAuthSchema;
use alibi::plugins::OAuthPlugin;
use alibi::plugins::oauth::OAuthProvider;
use alibi::sqlx::SqlxStore;
use alibi::{AuthConfig, AuthResult, Alibi};

async fn build_auth(
    config: AuthConfig,
    store: SqlxStore<AppAuthSchema>,
    google: (&str, &str),
    github: (&str, &str),
) -> AuthResult<Alibi<AppAuthSchema>> {
    Alibi::<AppAuthSchema>::new(config)
        .store(store)
        .plugin(
            OAuthPlugin::new()
                .add_provider("google", OAuthProvider::google(google.0, google.1))
                .add_provider("github", OAuthProvider::github(github.0, github.1)),
        )
        .build()
        .await
}
```

The first argument of `add_provider` is the **provider id**. Clients send it as `provider`, and it forms the callback URL, so keep it stable.

### Register the callback URL

Each provider's developer console needs this redirect URI:

```text
{BETTER_AUTH_URL}{base_path}/callback/{provider id}
# e.g. https://auth.example.com/api/auth/callback/google
```

It must match `AuthConfig::base_url`, the mount path and the provider id exactly (individual providers allow overriding it with `redirect_uri` in their options).

## The sign-in flow

1. **Start.** The client posts the provider and where to go afterwards:

   ```bash
   curl -i http://localhost:3000/api/auth/sign-in/social \
     -H 'Content-Type: application/json' -H 'Origin: http://localhost:5173' \
     -d '{"provider":"github","callbackURL":"http://localhost:5173/dashboard"}'
   ```

   ```json
   {"url":"https://github.com/login/oauth/authorize?response_type=code&client_id=…&state=U9Br0rf9…&scope=read%3Auser+user%3Aemail&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fapi%2Fauth%2Fcallback%2Fgithub&code_challenge_method=S256&code_challenge=…","redirect":true}
   ```

   The response also sets a `better-auth.state` cookie. Browsers using the official client follow `url` automatically; set `"disableRedirect": true` to receive the URL with `"redirect": false` and navigate yourself.

2. **Authorize.** The user signs in at the provider, which redirects to `GET /callback/{provider}` with `code` and `state`.
3. **Callback.** The server checks `state` (and PKCE), exchanges the code, loads the profile, creates or links the user, issues the session cookie and redirects to `callbackURL`. New users go to `newUserCallbackURL` if given; failures go to `errorCallbackURL` with `?error=<code>`.

Request body of `POST /sign-in/social`:

| Field | Meaning |
| --- | --- |
| `provider` | Registered provider id (required) |
| `callbackURL`, `newUserCallbackURL`, `errorCallbackURL` | Post-flow destinations; must be relative or a [trusted origin](/concepts/security/) (`403 INVALID_CALLBACK_URL` otherwise) |
| `scopes` | Extra scopes appended to the provider's defaults |
| `loginHint` | Pre-fills the provider's account chooser |
| `authorizationParams` | Per-flow authorization parameters filtered by the provider’s `allowed_request_params` |
| `additionalParams` | Extra authorization-URL query parameters (for example Google `hd`) |
| `requestSignUp` | Explicitly allow sign-up when the provider disables implicit sign-up |
| `additionalData` | Application data carried through the round trip |
| `idToken` | Skip the redirect: sign in with an ID token obtained client-side (below) |
| `disableRedirect` | Return the URL instead of redirecting |

An unknown provider id returns `404 PROVIDER_NOT_FOUND`.

### Sign in with an ID token

Native and mobile clients often obtain an ID token from the provider SDK. Post it instead of starting a redirect; the server verifies signature, issuer, audience and (when given) nonce, and issues the session in the same response:

```bash
curl -i http://localhost:3000/api/auth/sign-in/social \
  -H 'Content-Type: application/json' -H 'Origin: http://localhost:3000' \
  -d '{"provider":"google","idToken":{"token":"eyJhbGciOi…","nonce":"…","accessToken":"ya29…"}}'
# {"redirect":false,"token":"…","user":{…}}
```

Google (additional client ids via `.with_client_ids(vec![…])`), Apple, Microsoft, Cognito, Facebook Limited Login and others verify against the provider's published keys. Disable the branch for a provider with `provider.disable_id_token_sign_in = true`.

## Provider catalog

All constructors return `OAuthProvider`. Providers whose configuration is richer take an `*Options` struct (`OAuthProvider::linear_with_options(LinearOptions::new(…))`); each options struct exposes public fields such as `scope`, `disable_default_scope`, `redirect_uri`, `authorization_endpoint`, `prompt` and `map_profile_to_user`.

| Provider | Constructor | Notes |
| --- | --- | --- |
| Google | `google(id, secret)` | `with_client_ids`, `with_hosted_domain`; verifies ID tokens |
| GitHub | `github(id, secret)` | Resolves the primary verified email; `github_with_endpoints` for GitHub Enterprise |
| Discord | `discord(id, secret)` | |
| GitLab | `gitlab(id, secret)` | `gitlab_with_issuer` for self-hosted |
| Apple | `apple(id, secret)` / `apple_with_options` | Native app bundle audiences, ID-token sign-in |
| Atlassian | `atlassian(id, secret)` / `atlassian_with_options` | |
| Facebook | `facebook(id, secret)` / `facebook_with_options` | Limited Login, `fields`, `config_id` |
| PayPal | `paypal(id, secret)` / `paypal_with_options` | `environment`: sandbox or live |
| TikTok | `tiktok(client_key, secret)` / `tiktok_with_options` | Authenticates with `client_key` |
| WeChat | `wechat(id, secret)` / `wechat_with_options` | `language` option |
| Microsoft Entra ID | `microsoft(MicrosoftOptions)` → `Result` | Tenant, authority, profile photo |
| Amazon Cognito | `cognito(CognitoOptions)` → `Result` | Needs `domain`, `region`, `user_pool_id` |
| Cloudflare, Dropbox, Figma, Hugging Face, Kakao, Kick, LINE, Linear, LinkedIn, Naver, Notion, Paybin, Polar, Railway, Reddit, Roblox, Salesforce, Slack, Spotify, Twitch, Twitter/X, Vercel, VK, Zoom | `name(id, Some(secret))` / `name_with_options` | Secret is optional where the provider supports public clients; `salesforce_with_options` takes an `environment` |

All 36 providers share the upstream defaults for scopes, PKCE, token authentication, default token expiry and profile mapping. Profile values reach the user model as `name`, `email`, `image` and `emailVerified`.

### Customize a provider

Every field of `OAuthProvider` is public, so you can adjust a built-in provider after constructing it:

```rust
use alibi::plugins::OAuthPlugin;
use alibi::plugins::oauth::OAuthProvider;

fn plugin(client_id: &str, client_secret: &str) -> OAuthPlugin {
    let mut github = OAuthProvider::github(client_id, client_secret);
    github.scopes.push("read:org".into());     // always request this scope
    github.disable_sign_up = true;             // existing users only
    github.override_user_info_on_sign_in = true; // refresh name/image from the provider each login

    let google = OAuthProvider::google(client_id, client_secret)
        .with_hosted_domain("example.com")     // Google Workspace only
        .require_email_verification(true);     // reject unverified provider emails

    OAuthPlugin::new()
        .add_provider("github", github)
        .add_provider("google", google)
}
```

| `OAuthProvider` field | Effect |
| --- | --- |
| `scopes` | Base scope list |
| `authorization_params` | Default authorization-URL parameters, e.g. `("prompt", "consent")` |
| `allowed_request_params` | Names accepted from `authorizationParams`; empty by default |
| `disable_sign_up` | Never create users through this provider |
| `disable_implicit_sign_up` | Create users only when the request sets `requestSignUp` |
| `override_user_info_on_sign_in` | Update the stored profile at every sign-in |
| `require_email_verification` | Require the provider to assert a verified email |
| `disable_id_token_sign_in` | Turn off the `idToken` branch |
| `map_user_info` | `fn(serde_json::Value) -> Result<OAuthUserInfo, String>` replacing the profile mapping |
| `get_user_info`, `refresh_access_token`, `verify_id_token` | Replace the transports (`OAuthUserInfoHandler`, …) |

For richer mapping — populating your own [additional fields](/concepts/field-policies/) — implement `OAuthProfileMapper` and attach it with `provider.with_profile_mapper(Arc::new(MyMapper))`. It receives the raw profile JSON and returns the fields to override (including additional ones).

### Per-flow authorization parameters

To request an offline Google grant only when linking Drive, configure the names clients may send:

```rust
let mut google = OAuthProvider::google(client_id, client_secret);
google.allowed_request_params = vec![
    "access_type".into(),
    "prompt".into(),
    "login_hint".into(),
];
```

Then post to `/link-social` with the signed-in user's session:

```json
{
  "provider": "google",
  "callbackURL": "/settings/integrations",
  "scopes": ["https://www.googleapis.com/auth/drive.file"],
  "authorizationParams": {"access_type": "offline", "prompt": "consent"}
}
```

Both `/link-social` and `/sign-in/social` accept `authorizationParams` as an object of string values. Unlisted names are ignored. Reserved OAuth names (`state`, `client_id`, `redirect_uri`, `response_type`, `code_challenge`, `code_challenge_method`, `nonce`, `scope`) and a provider's custom client-ID parameter are ignored even if allowlisted. Use `scopes` to request scopes.

Allowed values override provider defaults and `additionalParams` for that flow. Provider policy's `fixed_authorization_params` still take precedence. A subsequent request without `authorizationParams` uses the original provider defaults, so ordinary sign-ins need not force consent. The field applies to redirect flows; it has no effect on `idToken` sign-in.

`additionalParams` retains its existing behavior and does not use this allowlist.

## Link and unlink accounts

A signed-in user adds another provider with `POST /link-social` (same body as sign-in, minus the sign-up fields). The callback attaches the provider account to the **current** user rather than creating one:

```bash
curl -b cookies.txt http://localhost:3000/api/auth/link-social \
  -H 'Content-Type: application/json' -H 'Origin: http://localhost:3000' \
  -d '{"provider":"google","callbackURL":"/settings"}'
```

At sign-in, a provider account may attach to an *existing* user with the same email only if the provider asserts a verified email, or the provider is trusted. Review `AuthConfig::account.account_linking` before enabling it broadly — see [Linking policy](/concepts/users-accounts/#linking-policy). `GET /list-accounts` and `POST /unlink-account` manage linked accounts.

## Use the provider's access token

Providers return access and refresh tokens; the server stores them on the account row (optionally [encrypted](#token-storage)). Client endpoints for working with them:

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/get-access-token` | Return a valid access token for the linked account `{"accountId":"<id>"}` (ids come from `GET /list-accounts`), refreshing it first when it has expired. `{"useAccountCookie":true}` reads it from the [account cookie](#state-and-cookies) instead |
| `POST` | `/refresh-token` | Force a refresh using the stored refresh token (same body) |
| `GET` | `/account-info` | The provider's own profile for a linked account |

```bash
curl -b cookies.txt http://localhost:3000/api/auth/get-access-token \
  -H 'Content-Type: application/json' -H 'Origin: http://localhost:3000' \
  -d '{"accountId":"a12f3c…"}'
# {"accessToken":"ya29…","accessTokenExpiresAt":"2026-10-04T10:47:38.071Z","scopes":["email","profile","openid"],"idToken":"eyJ…"}
```

Server-side code can do the same without HTTP through `alibi::plugins::oauth::OAuthAccountApi::{get_access_token, refresh_token, account_info}`, which take the already-authorized `user_id` — they are not routes and cannot be called with a client-chosen principal.

### Token storage

```rust
use alibi::AuthConfig;

fn auth_config(secret: &str) -> AuthConfig {
    let mut config = AuthConfig::new(secret);
    config.account.encrypt_oauth_tokens = true; // XChaCha20-Poly1305 keyed from the auth secret
    config.account.update_account_on_sign_in = true;
    config
}
```

With `encrypt_oauth_tokens` the access and refresh tokens are encrypted at rest (XChaCha20-Poly1305 with a key derived from the [secret](/reference/secrets/), versioned for rotation); ID tokens are stored as issued — the same layout as Better Auth 1.7.7. Rows written by older versions of this library use a different format; convert them with [Legacy OAuth token conversion](/guides/legacy-oauth-tokens/).

## State and cookies

OAuth `state` (and the PKCE verifier) must survive the redirect. `AuthConfig::account.store_state_strategy` selects where:

| Strategy | Storage | Default when |
| --- | --- | --- |
| `Database` | A verification row plus a signed `better-auth.state` cookie | A store or secondary storage is configured |
| `Cookie` | An encrypted `better-auth.oauth_state` cookie | [No database](/databases/no-database/) |
| `Automatic` | Resolved at `build()` to one of the above | `AuthConfig` default |

`store_account_cookie` additionally keeps the provider account data in a compact `account_data` cookie, which database-less deployments need for token endpoints. A state mismatch redirects to your error URL with `?error=state_mismatch`; do not enable `skip_state_cookie_check`.

## Related

- [Generic OAuth](/authentication/generic-oauth/) — your own OIDC provider, discovery, end-session
- [OAuth popup](/plugins/oauth-popup/) — sign in from a popup window in SPAs
- [OAuth proxy](/plugins/oauth-proxy/) — stable callback host for preview deployments
- [One Tap](/plugins/one-tap/) — Google One Tap on the server

## Frontend

See the official [social sign-on guide](https://www.better-auth.com/docs/authentication/social-sign-on).
