---
title: "OpenAPI"
description: "Generate an OpenAPI document and an interactive API reference for your configured auth API."
---

`OpenApiPlugin` describes **your instance's** endpoints — core routes plus whatever plugins you registered, including your own [additional fields](/concepts/field-policies/) on the user model — as an OpenAPI 3.1 document and serves an interactive reference page. Use it to explore the API, generate clients, or diff what you expose.

## Setup

```rust
use crate::auth_schema::AppAuthSchema;
use alibi::plugins::OpenApiPlugin;
use alibi::sqlx::SqlxStore;
use alibi::{AuthConfig, AuthResult, Alibi};

async fn build_auth(
    config: AuthConfig,
    store: SqlxStore<AppAuthSchema>,
) -> AuthResult<Alibi<AppAuthSchema>> {
    Alibi::<AppAuthSchema>::new(config)
        .store(store)
        .plugin(OpenApiPlugin::new())
        .build()
        .await
}
```

## Endpoints

| Method | Path | Result |
| --- | --- | --- |
| `GET` | `/open-api/generate-schema` | The OpenAPI JSON document |
| `GET` | `/reference` | An interactive HTML reference (configurable path) |

```bash
curl http://localhost:3000/api/auth/open-api/generate-schema | jq '.paths | keys | length'
# 141   (with a broad plugin set)
```

The document has one operation per route, request and response schemas, error responses, tags per plugin, and the `bearerAuth` and `apiKeyCookie` security schemes. Models such as `User` and `Session` include your additional fields.

## Generate the document in Rust

Export the spec directly from the built instance — for a CI check or to commit the contract:

```rust
use crate::auth_schema::AppAuthSchema;
use alibi::Alibi;

fn export_openapi(auth: &Alibi<AppAuthSchema>) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(&auth.openapi_spec())
}

fn export_with_native(auth: &Alibi<AppAuthSchema>) -> Result<String, serde_json::Error> {
    // Includes operations that exist only in Alibi.
    serde_json::to_string_pretty(&auth.openapi_spec_with_native_extensions())
}
```

`openapi_spec()` matches what the TypeScript server documents; `openapi_spec_with_native_extensions()` adds Rust-only operations. Server-only operations (those available through `dispatch_endpoint`) are never listed because they are not HTTP routes.

## Configuration

Builder methods on `OpenApiConfig` (use `OpenApiPlugin::with_config`):

| Method | Default | Effect |
| --- | --- | --- |
| `path("/docs")` | `/reference` | Where the HTML reference is served |
| `theme("…")` | provider default | Theme name for the reference UI |
| `nonce("…")` | none | CSP nonce for the reference page's script |
| `disable_default_reference(true)` | `false` | Serve only the JSON; skip the HTML page |
| `include_native_extensions(true)` | `false` | Include Rust-only operations in the served document |

```rust
use alibi::plugins::{OpenApiConfig, OpenApiPlugin};

fn open_api() -> OpenApiPlugin {
    OpenApiPlugin::with_config(
        OpenApiConfig::default()
            .path("/docs")
            .disable_default_reference(false)
            .include_native_extensions(true),
    )
}
```

The native `GET /__test/openapi.json` embedding endpoint is available only when `OpenApiPlugin` is installed. It returns the configured schema without native extensions. Without the plugin, direct HTTP and framework adapters return 404; the Rust `openapi_spec()` methods remain available for in-process use.

## Production

The reference lists every route and its parameters. Disable the plugin or the HTML page in production if you do not want to publish your API surface, or protect the paths at your proxy.

The full list of routes by plugin is also maintained in the [HTTP API reference](/reference/http-api/).

## Frontend

See the official [OpenAPI guide](https://www.better-auth.com/docs/plugins/open-api).
