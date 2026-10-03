---
title: "Cargo features"
description: "Select database engines, framework integrations, and TLS."
---

Choose features on the Git dependency. For SQLite with Rustls and Axum:

```toml
better-auth = { git = "https://github.com/cschmatzler/better-auth-rs", default-features = false, features = ["axum", "sqlx-sqlite", "rustls"] }
```

| Feature | Description |
|---------|-------------|
| `axum` | Axum web framework integration |
| `sqlx` | SQLx store for SQLite and PostgreSQL (default); `sqlx-sqlite` and `sqlx-postgres` select one engine |
| `seaorm` | SeaORM store |
| `native-tls` / `rustls` | TLS stack for outbound HTTP and for the SQLx and SeaORM PostgreSQL drivers (`native-tls` is default) |
| `redis-cache` | Redis session/cache backend |
