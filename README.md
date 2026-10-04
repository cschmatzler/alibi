# Better Auth RS

**Better Auth for Rust.** Authentication built around your database, your models, and your stack.

[![CI](https://github.com/cschmatzler/better-auth-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/cschmatzler/better-auth-rs/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![Better Auth compatibility](https://img.shields.io/badge/better--auth-v1.7.6-blue)](https://www.npmjs.com/package/better-auth/v/1.7.6)

Email and password, social login, passkeys, two-factor authentication, organizations, and API keys — composed with Rust plugins. Use SQLx or SeaORM for storage and Axum for routing and typed session extractors.

Inspired by [Better Auth](https://www.better-auth.com/). HTTP compatibility targets `better-auth@1.7.6` and is checked against the official TypeScript runtime and client.

> [!WARNING]
> **Unreleased and under active development.** APIs, wire formats, and schemas may change. Production use is not recommended yet.

## Quick start

Use the project directly from Git.

```toml
[dependencies]
better-auth = { git = "https://github.com/cschmatzler/better-auth-rs", version = "1.0.0-alpha.3", features = ["axum"] }
```

Generate application-owned auth models (SQLx is the default backend):

```bash
cargo install --git https://github.com/cschmatzler/better-auth-rs --locked better-auth-cli
better-auth-rs generate -o src/auth_schema.rs
```

Create your auth instance with the generated schema and a configured store:

```rust
mod auth_schema;

use auth_schema::AppAuthSchema;
use better_auth::plugins::EmailPasswordPlugin;
use better_auth::sqlx::{SqlxPool, SqlxStore};
use better_auth::{AuthConfig, BetterAuth};

async fn build_auth() -> Result<BetterAuth<AppAuthSchema>, Box<dyn std::error::Error>> {
    let config =
        AuthConfig::new(std::env::var("BETTER_AUTH_SECRET")?).base_url("http://localhost:3000");
    let pool = SqlxPool::connect(&std::env::var("DATABASE_URL")?).await?;
    auth_schema::run_app_migrations(&pool).await?;
    let store = SqlxStore::<AppAuthSchema>::new(config.clone(), pool);

    Ok(BetterAuth::<AppAuthSchema>::new(config)
        .store(store)
        .plugin(EmailPasswordPlugin::new().enable_signup(true))
        .build()
        .await?)
}
```

For SeaORM, enable the `seaorm` feature, generate models with `better-auth-rs generate --backend seaorm -o src/auth_schema.rs`, and replace the SQLx connection and store setup with:

```rust
use better_auth::seaorm::{Database, SeaOrmStore};

let database = Database::connect(&std::env::var("DATABASE_URL")?).await?;
auth_schema::run_app_migrations(&database).await?;
let store = SeaOrmStore::<AppAuthSchema>::new(config.clone(), database);
```

The [installation guide](docs/src/content/docs/installation.md) includes all dependencies, environment setup, and a runnable Axum server.

## Documentation

The [backend docs](docs/src/content/docs/introduction.md) follow Better Auth's structure with Rust examples. For the frontend, use the official [client setup](https://www.better-auth.com/docs/concepts/client) and [usage guides](https://www.better-auth.com/docs/basic-usage).

Backend topics:

- [Basic usage](docs/src/content/docs/basic-usage.md)
- [SQLx](docs/src/content/docs/databases/sqlx.md) · [SeaORM](docs/src/content/docs/databases/seaorm.md) · [Existing databases](docs/src/content/docs/guides/existing-databases.md)
- [Sessions](docs/src/content/docs/concepts/session-management.md) · [Secondary storage](docs/src/content/docs/concepts/secondary-storage.md)
- [Plugins](docs/src/content/docs/plugins/index.md) · [Options](docs/src/content/docs/reference/options.md) · [Cargo features](docs/src/content/docs/reference/features.md)
- [Compatibility](docs/src/content/docs/reference/compatibility.md) · [API source](https://github.com/cschmatzler/better-auth-rs/tree/main/src)

Run the Astro Starlight site locally with Node.js 22.12+ and pnpm:

```bash
pnpm install
pnpm docs:dev
```

`pnpm docs:check` validates the site; `pnpm docs:build` produces a static build with search. Read the [live documentation](https://better-auth-rs.schmatzler.com).

Railway deployment uses Alchemy with SOPS and Varlock. See the [deployment guide](alchemy/README.md) for secrets, planning, and deployment commands.

## Development

The repository uses [devenv](https://devenv.sh/getting-started/) and direnv:

```bash
direnv allow
devenv shell -- ./scripts/check.sh
```

See [contributing](docs/src/content/docs/guides/development.md) for environment requirements, [tests](tests/README.md) for test tiers, and [compatibility testing](tests/compat/README.md) for focused checks.

## License

This project is a fork of [better-auth-rs/better-auth-rs](https://github.com/better-auth-rs/better-auth-rs) by AprilNEA, continuing under the [MIT license](LICENSE). Original copyright is retained in the license notice; contribution history is preserved in the fork's git history.

[MIT](LICENSE)
