---
title: "OAuth proxy"
description: "Proxy OAuth callbacks for environments with a separate production auth origin."
---

`OAuthProxyPlugin` completes OAuth callbacks through a production auth host and returns to the originating preview host.

## Setup

Configure both origins and register the proxy alongside OAuth:

```rust
use crate::auth_schema::AppAuthSchema;
use better_auth::plugins::oauth::OAuthProvider;
use better_auth::plugins::{OAuthPlugin, OAuthProxyConfig, OAuthProxyPlugin};
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
        .plugin(OAuthProxyPlugin::with_config(OAuthProxyConfig {
            production_url: Some("https://auth.example.com".into()),
            current_url: Some("https://preview.example.com".into()),
            ..Default::default()
        }))
        .build()
        .await
}
```

Register the production callback URL with the provider and allow the preview origin in the server's trusted-origin configuration. The proxy uses database-backed OAuth state; it does not remove provider registration or redirect validation.

## Frontend

See the official [OAuth proxy guide](https://www.better-auth.com/docs/plugins/oauth-proxy).
