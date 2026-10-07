---
title: "Cargo features"
description: "Select database engines, framework integrations, the TLS stack and the Redis cache."
---

Choose features on the Git dependency. For SQLite with Rustls and Axum:

```toml
better-auth = { package = "alibi", git = "https://github.com/cschmatzler/better-auth-rs", default-features = false, features = ["axum", "sqlx-sqlite", "rustls"] }
```

| Feature | Default | Enables |
| --- | --- | --- |
| `axum` | no | [Axum](/integrations/axum/): `AxumIntegration`, `CurrentSession`, `OptionalSession` |
| `poem` | no | [Poem](/integrations/poem/): `PoemIntegration`, session extractors |
| `sqlx` | **yes** | [SQLx](/databases/sqlx/) store for SQLite **and** PostgreSQL (`sqlx-sqlite` + `sqlx-postgres`) |
| `sqlx-sqlite` | via `sqlx` | SQLx with SQLite only |
| `sqlx-postgres` | via `sqlx` | SQLx with PostgreSQL only |
| `seaorm` | no | [SeaORM](/databases/seaorm/) store |
| `redis-cache` | no | `RedisAdapter` for [secondary storage](/concepts/secondary-storage/) and shared [rate limits](/concepts/rate-limit/) |
| `native-tls` | **yes** | OpenSSL for outbound HTTP (OAuth, email verification, CAPTCHA, …) and the SQLx/SeaORM PostgreSQL drivers |
| `rustls` | no | Rustls instead of OpenSSL |

## Rules of thumb

- **Pick exactly one TLS feature.** The default is `native-tls`; to use `rustls`, disable default features.
- **Pick the engine you use.** Disabling default features and selecting `sqlx-sqlite` *or* `sqlx-postgres` removes the other engine's code. `SqlxPool::connect` returns a configuration error for a URL whose engine is not compiled in.
- **Frameworks are opt-in.** Without `axum` or `poem`, use `BetterAuth::handle_request` directly ([Other frameworks](/integrations/other-frameworks/)).
- **SeaORM and SQLx are independent.** Enable one or both; each provides its own store, hooks and rate-limit storage.

## Common combinations

```toml
# PostgreSQL + Axum + Rustls (typical production)
better-auth = { package = "alibi", git = "…", default-features = false, features = ["axum", "sqlx-postgres", "rustls"] }

# SeaORM + Poem + Rustls
better-auth = { package = "alibi", git = "…", default-features = false, features = ["poem", "seaorm", "rustls"] }

# Axum + SQLx + Redis-backed sessions and rate limits
better-auth = { package = "alibi", git = "…", features = ["axum", "redis-cache"] }
```

Your own `sqlx` dependency must enable the same engine (`"sqlite"` and/or `"postgres"`) plus `chrono`, `json` and `derive`, because the generated models derive `sqlx::FromRow`.
