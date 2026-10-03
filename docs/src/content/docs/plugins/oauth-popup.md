---
title: "OAuth popup"
description: "Complete OAuth sign-in in a popup and deliver the result to a trusted opener."
---

Register `OAuthPopupPlugin::new()` alongside `OAuthPlugin` and `BearerPlugin`. Add the app origin to `AuthConfig::trusted_origin` and configure the host application's CORS policy for that origin when the app and auth server use different origins.

```rust
use better_auth::plugins::{BearerPlugin, OAuthPopupPlugin};

// Continue configuring your BetterAuth builder and OAuth providers:
// .plugin(BearerPlugin::new())
// .plugin(OAuthPopupPlugin::new())
```

Use the published Better Auth client with `oauthPopupClient()`:

```typescript
import { createAuthClient } from "better-auth/client";
import { oauthPopupClient } from "better-auth/client/plugins";

const authClient = createAuthClient({
  baseURL: "https://auth.example.com/api/auth",
  plugins: [oauthPopupClient()],
});

await authClient.signIn.popup({ provider: "google", callbackURL: "/dashboard" });
```

The popup visits `GET /oauth-popup/start` in the auth origin's first-party context. The server validates the opener origin and callback URLs, issues the existing ten-minute OAuth state, and signs a ten-minute marker carrying the opener origin and client nonce. OAuth callbacks keep their normal state, account, session, and error handling. When a valid marker accompanies a callback redirect, the plugin delivers the signed session cookie or error through the published completion-page script, restricted by its pinned CSP hash.

The official client checks the auth origin and nonce. An embedded app stores the signed token and sends it through the bearer plugin; successful sign-out clears that stored token. A blocked or closed popup creates no session. A tampered marker leaves ordinary OAuth callback delivery in effect. The marker does not introduce a separate replay ledger; OAuth state and provider grants retain their existing replay rules.
