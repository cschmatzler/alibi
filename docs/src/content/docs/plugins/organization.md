---
title: "Organization"
description: "Organizations, invitations, membership, roles, and optional teams."
---

`OrganizationPlugin` manages organizations, invitations, membership, roles, and optional teams.

## Setup

```bash
better-auth-rs generate --plugins organization -o src/auth_schema.rs
```

Apply the generated schema with your migrations. The example uses the configuration and store from [installation](/installation/).

```rust
use crate::auth_schema::AppAuthSchema;
use better_auth::plugins::OrganizationPlugin;
use better_auth::sqlx::SqlxStore;
use better_auth::{AuthConfig, AuthResult, BetterAuth};

async fn build_auth(
    config: AuthConfig,
    store: SqlxStore<AppAuthSchema>,
) -> AuthResult<BetterAuth<AppAuthSchema>> {
    BetterAuth::<AppAuthSchema>::new(config)
        .store(store)
        .plugin(OrganizationPlugin::new())
        .build()
        .await
}
```

## Endpoints and options

Create an organization through `POST /organization/create`, invite members through `/organization/invite-member`, and accept invitations through `/organization/accept-invitation`. Reads include `/organization/list` and `/organization/list-members`.

Organization membership and permissions are checked per operation. Configure roles and policies with `OrganizationConfig`; teams and dynamic role endpoints are conditional on those options. Implement invitation delivery in your application before offering email invitations.

## Frontend

See the official [Organization guide](https://www.better-auth.com/docs/plugins/organization).
