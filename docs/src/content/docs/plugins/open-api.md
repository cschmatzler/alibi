---
title: "OpenAPI"
description: "Inspect your configured authentication API and generate an API reference."
---

`OpenApiPlugin` generates an API reference for the configured authentication endpoints.

## Setup

Use the schema, configuration, and store from [installation](/installation/).

```rust
use crate::auth_schema::AppAuthSchema;
use better_auth::plugins::OpenApiPlugin;
use better_auth::sqlx::SqlxStore;
use better_auth::{AuthConfig, AuthResult, BetterAuth};

async fn build_auth(
    config: AuthConfig,
    store: SqlxStore<AppAuthSchema>,
) -> AuthResult<BetterAuth<AppAuthSchema>> {
    BetterAuth::<AppAuthSchema>::new(config)
        .store(store)
        .plugin(OpenApiPlugin::new())
        .build()
        .await
}
```

## Endpoints and options

The plugin serves JSON at `/open-api/generate-schema` and an interactive reference at `/reference`.

You can also generate the specification directly from the built instance:

```rust
use crate::auth_schema::AppAuthSchema;
use better_auth::BetterAuth;

fn export_openapi(auth: &BetterAuth<AppAuthSchema>) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(&auth.openapi_spec())
}
```

Use `openapi_spec_with_native_extensions()` to include native-only operations. `OpenApiConfig` controls the reference path and presentation.

## Frontend

See the official [OpenAPI guide](https://www.better-auth.com/docs/plugins/open-api).
