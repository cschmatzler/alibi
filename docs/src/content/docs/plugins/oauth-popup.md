---
title: "OAuth popup"
description: "Complete social sign-in in a popup window and deliver the session to the opener, for SPAs and embedded apps."
---

Redirect-based OAuth navigates away from your app. A single-page app, an embedded widget, or an app whose cookies cannot be shared with the auth server often wants the provider's consent screen in a **popup** and the result delivered back with `postMessage`. `OAuthPopupPlugin` provides the server half; the official client's `oauthPopupClient()` provides the browser half.

## Setup

Register it alongside `OAuthPlugin` and `BearerPlugin` (embedded clients keep the session as a bearer token):

```rust
use crate::auth_schema::AppAuthSchema;
use better_auth::plugins::oauth::OAuthProvider;
use better_auth::plugins::{BearerPlugin, OAuthPlugin, OAuthPopupPlugin};
use better_auth::sqlx::SqlxStore;
use better_auth::{AuthConfig, AuthResult, BetterAuth};

async fn build_auth(
    config: AuthConfig,
    store: SqlxStore<AppAuthSchema>,
    client_id: &str,
    client_secret: &str,
) -> AuthResult<BetterAuth<AppAuthSchema>> {
    BetterAuth::<AppAuthSchema>::new(config)
        .store(store)
        .plugin(
            OAuthPlugin::new()
                .add_provider("google", OAuthProvider::google(client_id, client_secret)),
        )
        .plugin(BearerPlugin::new())
        .plugin(OAuthPopupPlugin::new())
        .build()
        .await
}
```

Also:

1. Add the app's origin to `AuthConfig::trusted_origin` — the plugin only talks to trusted origins (`403 INVALID_ORIGIN` otherwise).
2. If the app and the auth server have different origins, configure [CORS](/concepts/security/#cors) for the app origin and expose `set-auth-token`.

## Client

```ts
import { createAuthClient } from "better-auth/client";
import { oauthPopupClient } from "better-auth/client/plugins";

const authClient = createAuthClient({
  baseURL: "https://auth.example.com/api/auth",
  plugins: [oauthPopupClient()],
});

await authClient.signIn.popup({ provider: "google", callbackURL: "/dashboard" });
```

## The flow

1. The client opens a popup at `GET /oauth-popup/start?provider=google&popupOrigin=https://app.example.com&popupNonce=<random>&callbackURL=…` — so the popup begins in the **auth server's first-party context** and can set its own cookies even where third-party cookies are blocked.
2. The server validates the origin and the callback URLs, starts the ordinary OAuth flow (the same ten-minute `state`), and signs a ten-minute **marker** cookie that records the opener's origin and nonce. It then redirects to the provider.
3. The provider redirects to the normal `GET /callback/google`. The callback keeps its usual state, account, session and error handling.
4. If a valid marker accompanies the callback, the server responds with a small completion page that posts the result to the opener — the signed session token on success, or an error code — using the pinned script and a strict Content-Security-Policy (`script-src 'sha256-…'`, `default-src 'none'`).
5. The client checks the **auth origin** and the **nonce**, stores the signed token and sends it as a bearer token afterwards; signing out clears it.

`GET /oauth-popup/start` query parameters: `provider` and `popupOrigin` (required), `popupNonce`, `callbackURL`, `errorCallbackURL`, `newUserCallbackURL`, `requestSignUp=true`, `scopes` (comma separated) and `additionalData` (JSON; reserved internal keys are ignored). Untrusted URLs and unknown providers are reported **to the opener** with codes such as `invalid_callback_url`, `provider_not_found` and `popup_sign_in_failed`.

## Behavior and security

- A blocked or closed popup never creates a session.
- A tampered marker cookie is ignored, so the ordinary redirect delivery stays in effect.
- The marker adds no replay ledger of its own: OAuth `state` and the provider's one-time authorization code keep their usual replay protection.
- The result is only ever posted to the `popupOrigin` that passed the trusted-origin check; other windows cannot receive it.
- The session travels as a bearer token because the opener and the auth server are different origins. Treat it like any [bearer token](/plugins/bearer/#security-notes).

## Frontend

See the official [OAuth popup documentation](https://www.better-auth.com/docs/plugins/oauth-popup) and the [social sign-on](/authentication/social-sign-on/) flow it builds on.
