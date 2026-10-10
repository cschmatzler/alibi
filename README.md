# Alibi

[![CI](https://github.com/cschmatzler/better-auth-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/cschmatzler/better-auth-rs/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![Better Auth compatibility](https://img.shields.io/badge/better--auth-v1.7.7-blue)](https://www.npmjs.com/package/better-auth/v/1.7.7)

Alibi is a Rust implementation of [Better Auth](https://www.better-auth.com/), built to work with its official TypeScript client. Run authentication in your Rust backend while keeping Better Auth's frontend API. Requires Rust 1.99 or newer.

Use email and password, social login, passkeys, two-factor authentication, organizations, and API keys through composable plugins. Store auth data with SQLx or SeaORM, own the generated models and migrations, and mount the server in Axum or Poem.

## Upstream compatibility

The upstream Better Auth API is our compatibility contract. The current target is **`better-auth@1.7.7`**: endpoints, request and response shapes, status and error codes, redirects, cookie attributes, and supported stored data formats.

We verify this contract with a differential suite that runs the official TypeScript client against both the pinned upstream runtime and the Rust implementation, comparing responses and stored state. Rust configuration, callbacks, plugins, and database models use native Rust APIs.

See the [compatibility guide](docs/src/content/docs/reference/compatibility.md) for supported features, known boundaries, and upstream packages outside our scope. Newer upstream behavior becomes part of the contract when we upgrade and verify the target.

## Get started

The example below runs email and password authentication with Axum and SQLite. Add these dependencies to your application:

```toml
[dependencies]
alibi = { version = "0.4.1", features = ["axum"] }
axum = "0.8"
tokio = { version = "1", features = ["full"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
chrono = { version = "0.4", features = ["serde"] }
sqlx = { version = "0.9", default-features = false, features = ["sqlite", "chrono", "json", "derive"] }
```

Commit your application’s `Cargo.lock` for reproducible builds and install the matching `alibi-cli` version.

Generate your auth models:

```bash
cargo install alibi-cli --version 0.4.1 --locked
alibi generate -o src/auth_schema.rs
```

Set the environment variables in your shell:

```bash
export BETTER_AUTH_SECRET="$(openssl rand -base64 32)"
export BETTER_AUTH_URL="http://localhost:3000"
export DATABASE_URL="sqlite://auth.db?mode=rwc"
```

Add this to `src/main.rs`:

```rust
mod auth_schema;

use auth_schema::{AppAuthSchema, run_app_migrations};
use axum::Router;
use alibi::integrations::axum::AxumIntegration;
use alibi::plugins::EmailPasswordPlugin;
use alibi::sqlx::{SqlxPool, SqlxStore};
use alibi::{AuthConfig, Alibi};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = AuthConfig::new(std::env::var("BETTER_AUTH_SECRET")?)
        .base_url(std::env::var("BETTER_AUTH_URL")?);
    let pool = SqlxPool::connect(&std::env::var("DATABASE_URL")?).await?;
    run_app_migrations(&pool).await?;
    let store = SqlxStore::<AppAuthSchema>::new(config.clone(), pool);

    let auth = Arc::new(
        Alibi::<AppAuthSchema>::new(config)
            .store(store)
            .plugin(EmailPasswordPlugin::new().enable_signup(true))
            .build()
            .await?,
    );

    let app = Router::new()
        .nest("/api/auth", auth.clone().axum_router())
        .with_state(auth);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    axum::serve(listener, app).await?;
    Ok(())
}
```

Run `cargo run`, then check the server from another terminal:

```bash
curl http://localhost:3000/api/auth/ok
# {"ok":true}
```

The generated schema belongs to your application. `run_app_migrations` sets up a new local database; use your own versioned migrations as the schema evolves. The default build uses OpenSSL; see [Cargo features](docs/src/content/docs/reference/features.md) for Rustls. Passkeys require the opt-in `passkey` Cargo feature and OpenSSL, independently of the TLS stack.

Continue with the [installation guide](docs/src/content/docs/installation.md), [basic usage](docs/src/content/docs/basic-usage.md), or [SeaORM setup](docs/src/content/docs/databases/seaorm.md). For the frontend, follow Better Auth's official [client setup](https://www.better-auth.com/docs/concepts/client).

## Releases

Rust releases use independent Semantic Versioning. Each release records the exact upstream Better Auth version it targets.

Compatible Rust bug fixes can ship as patch releases without waiting for upstream. Compatible additions use minor releases; breaking changes require major releases. Upstream upgrades are versioned by their effect on Rust users.

For example, Rust `1.0.0` and `1.0.1` could both target Better Auth `1.7.7`, with `1.0.1` fixing a Rust implementation bug. These illustrate the versioning policy. The current release is `0.4.1`.

See the [release policy](docs/src/content/docs/guides/releases.md) for compatibility rules and publication checks.

Alibi `0.4.1` is available on [crates.io](https://crates.io/crates/alibi).

Import the library as `alibi` and run the schema generator with `alibi generate`.

## Documentation

Read the [documentation site](https://alibi.schmatzler.com) or browse the guides in this repository:

- [Plugins](docs/src/content/docs/plugins/index.md) and [social sign-on](docs/src/content/docs/authentication/social-sign-on.md)
- [SQLx](docs/src/content/docs/databases/sqlx.md), [SeaORM](docs/src/content/docs/databases/seaorm.md), and [existing databases](docs/src/content/docs/databases/existing-databases.md)
- [Sessions](docs/src/content/docs/concepts/session-management.md), [security](docs/src/content/docs/concepts/security.md), and [cross-origin applications](docs/src/content/docs/guides/cross-origin.md)
- [HTTP API](docs/src/content/docs/reference/http-api.md), [configuration](docs/src/content/docs/reference/options.md), and [CLI](docs/src/content/docs/reference/cli.md)
- [Server-side calls](docs/src/content/docs/guides/server-side-calls.md) and [writing plugins](docs/src/content/docs/guides/writing-a-plugin.md)

Use the official [Better Auth documentation](https://www.better-auth.com/docs/basic-usage) for frontend usage, matching the upstream version we target.

## Contributing

Development uses [devenv](https://devenv.sh/getting-started/) and direnv:

```bash
direnv allow
cargo nextest run
devenv shell -- ./scripts/check.sh
devenv shell -- ./scripts/compat.sh
```

`cargo nextest run` runs workspace unit, integration, and HTTP end-to-end tests, with SQLx, SeaORM, Axum and Poem enabled for development. It needs no upstream runtime or external database. `check.sh` is the native gate CI runs: formatting, lints, feature builds, every native tier and documentation. `compat.sh` runs the differential suite against the pinned TypeScript server; it is too slow for CI, so run it once before merging. Read [contributing](docs/src/content/docs/guides/development.md) for environment requirements, [tests](tests/README.md) for test tiers and focused commands, and [compatibility testing](tests/compat/README.md) for the differential harness.

To work on the Astro Starlight documentation site:

```bash
bun install
bun run docs:dev
```

Use `bun run docs:check` for diagnostics and `bun run docs:build` for the static build. The [deployment guide](alchemy/README.md) covers hosting.

## License and origins

[MIT](LICENSE), except the passkey verification routines in `alibi::plugins::passkey`, which derive from [webauthn-rs](https://github.com/kanidm/webauthn-rs) and remain MPL-2.0 (see [`LICENSE.md`](crates/plugins/src/plugins/passkey/source/LICENSE.md)). This project continues the work of [better-auth-rs/better-auth-rs](https://github.com/better-auth-rs/better-auth-rs) by AprilNEA. Original copyright notices and contribution history are preserved.
