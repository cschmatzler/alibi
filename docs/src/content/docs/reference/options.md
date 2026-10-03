---
title: "Options"
description: "Configure the auth instance and plugin builders."
---

Create `AuthConfig` explicitly, then pass it to both the store and auth builder.

```rust
use better_auth::AuthConfig;

fn auth_config(secret: &str) -> AuthConfig {
    AuthConfig::new(secret)
        .app_name("My application")
        .base_url("https://auth.example.com")
        .base_path("/api/auth")
        .trusted_origin("https://app.example.com")
}
```

| Configuration | Purpose | Guide |
| --- | --- | --- |
| `secret`, `managed_secrets` | Signing and encryption | [Secrets](/reference/secrets/) |
| `base_url`, `base_path` | Public URL and auth mount | [Installation](/installation/) |
| `trusted_origins` | Allowed request and redirect origins | [Cookies](/concepts/cookies/) |
| `session` | Expiry, refresh, cookies, storage | [Sessions](/concepts/session-management/) |
| `user`, `account`, `session.additional_fields` | Application data policies | [Additional fields](/concepts/field-policies/) |
| `verification` | Verification credential storage | [Secondary storage](/concepts/secondary-storage/) |
| `advanced.ip_address` | Trusted proxies and client identity | [Rate limits](/concepts/rate-limit/) |
| `background_tasks` | Observe background delivery | [Notifications](/concepts/notifications/) |

Plugin options are configured on each plugin instance. Middleware options such as rate limiting are registered on `AuthBuilder`.

For every field and default, use the [AuthConfig source](https://github.com/cschmatzler/better-auth-rs/blob/main/crates/core/src/config/mod.rs). 

Related upstream topic: [Options](https://www.better-auth.com/docs/reference/options).
