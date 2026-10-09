---
title: "Google One Tap"
description: "Verify Google One Tap and Sign in with Google ID tokens on the server."
---

Google One Tap and the "Sign in with Google" button give the browser a signed **ID token**. `OneTapPlugin` verifies that token against Google's published keys and signs the user in — creating the user or linking the Google account just as the redirect-based [social flow](/authentication/social-sign-on/) would.

## Setup

One Tap needs your Google OAuth client id. Register the Google provider and the plugin:

```rust
use crate::auth_schema::AppAuthSchema;
use alibi::plugins::oauth::OAuthProvider;
use alibi::plugins::{OAuthPlugin, OneTapPlugin};
use alibi::sqlx::SqlxStore;
use alibi::{AuthConfig, AuthResult, Alibi};

async fn build_auth(
    config: AuthConfig,
    store: SqlxStore<AppAuthSchema>,
    client_id: &str,
    client_secret: &str,
) -> AuthResult<Alibi<AppAuthSchema>> {
    Alibi::<AppAuthSchema>::new(config)
        .store(store)
        .plugin(
            OAuthPlugin::new()
                .add_provider("google", OAuthProvider::google(client_id, client_secret)),
        )
        .plugin(OneTapPlugin::new())
        .build()
        .await
}
```

No schema changes. By default the plugin uses the Google provider's client id(s) as the allowed ID-token audience.

## Endpoint

| Method | Path | Body | Result |
| --- | --- | --- | --- |
| `POST` | `/one-tap/callback` | `{"idToken":"<google credential>","callbackURL"?}` | `{"session":{…},"user":{…}}` and the session cookie |

```bash
curl -i -c cookies.txt http://localhost:3000/api/auth/one-tap/callback \
  -H 'Content-Type: application/json' -H 'Origin: http://localhost:3000' \
  -d '{"idToken":"eyJhbGciOiJSUzI1NiIs…"}'
```

The server verifies signature, issuer, expiry and audience, requires an email claim, and applies the same account rules as the social callback: it links to an existing user only when the email is verified or `google` is a [trusted provider](/concepts/users-accounts/#linking-policy), and respects `disable_sign_up`.

## Configuration

`OneTapConfig` (via `OneTapPlugin::with_config`):

| Field | Default | Effect |
| --- | --- | --- |
| `client_id` | the Google provider's id(s) | `OneTapClientId::Single(…)` or `Multiple(Vec<…>)` accepted as the token audience. Set it when the browser uses a different Google client than the server flow |
| `disable_signup` | `false` | Do not create new users from One Tap |
| `jwks_source` | Google's `https://www.googleapis.com/oauth2/v3/certs` | `OAuthJwksSource` — supply your own key source or cache |

```rust
use alibi::plugins::{OneTapConfig, OneTapPlugin};
use alibi::plugins::one_tap::OneTapClientId;

fn one_tap() -> OneTapPlugin {
    OneTapPlugin::with_config(OneTapConfig {
        client_id: Some(OneTapClientId::Multiple(vec![
            "web-client.apps.googleusercontent.com".into(),
            "ios-client.apps.googleusercontent.com".into(),
        ])),
        disable_signup: false,
        jwks_source: None,
    })
}
```

If neither the plugin nor the Google provider supplies a client id, the endpoint fails with a configuration error.

## Frontend

Use Google's Identity Services script on the page and send the credential to this endpoint. The official client's `oneTapClient` plugin does this for you; see the [One Tap guide](https://www.better-auth.com/docs/plugins/one-tap).
