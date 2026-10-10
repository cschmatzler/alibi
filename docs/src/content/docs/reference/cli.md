---
title: "CLI"
description: "alibi generate: create application-owned models, plugin tables and bootstrap migrations."
---

The `alibi` binary generates the Rust source for your auth models. It has one command, `generate`.

## Install

```bash
cargo install alibi-cli --version 0.4.1 --locked
```

## `generate`

```bash
alibi generate [--backend sqlx|seaorm] [--plugins <list>] [--output <file>]
```

| Option | Default | Meaning |
| --- | --- | --- |
| `-b`, `--backend` | `sqlx` | `sqlx` (`sqlx::FromRow` + `AuthEntity` models and `run_app_migrations(&SqlxPool)`) or `seaorm` (`DeriveEntityModel` entities and `run_app_migrations(&DatabaseConnection)`) |
| `-p`, `--plugins` | none | Comma-separated plugin schema names, or `all` |
| `-o`, `--output` | stdout | Write to a file (parent directories are created) |

Examples:

```bash
alibi generate -o src/auth_schema.rs
alibi generate --backend seaorm --plugins organization,two-factor -o src/auth_schema.rs
alibi generate --plugins all > src/auth_schema.rs
```

### What it emits

1. The four core models — `user`, `session`, `account`, `verification` — with the columns of the selected plugins merged in.
2. One additional model per plugin table (two-factor, passkey, API key, JWKS, organization, …).
3. `AppAuthSchema`, a unit struct implementing `AuthSchema` for those models.
4. `run_app_migrations`, which creates every table with `CREATE TABLE IF NOT EXISTS`. The SQLx output contains SQLite and PostgreSQL variants and picks one from the pool's engine.

Regenerate after adding a plugin that needs storage, **review the diff**, and write a real migration — see [Database](/concepts/database/#migrations). `run_app_migrations` creates bare tables without foreign keys or indexes.

### Plugin names

| Name | Adds |
| --- | --- |
| `username` | `users.username`, `users.display_username` |
| `two-factor` | `users.two_factor_enabled`, table `two_factor` |
| `admin` | user `role`, `banned`, `ban_reason`, `ban_expires`, `metadata`; session `impersonated_by` |
| `anonymous` | `users.is_anonymous` |
| `phone-number` | `users.phone_number`, `users.phone_number_verified` |
| `last-login-method` | `users.last_login_method` |
| `device-authorization` | table `device_code` |
| `api-key` | table `api_keys` ([schema](/plugins/api-key/#schema)) |
| `passkey` | table `passkeys` |
| `jwt` | table `jwks` |
| `siwe` | table `wallet_address` |
| `organization` | tables `organization`, `member`, `invitation`; session `active_organization_id` |
| `organization-teams` | tables `team`, `team_member`; session `active_team_id` |
| `organization-dynamic-roles` | table `organization_role` |

An unknown name is rejected, and the error lists the valid ones. `--help` shows the same list.

Plugins that need no storage (bearer, CAPTCHA, magic link, email OTP, one-time token, multi-session, OpenAPI, …) have no generator name.

## Exit status

`0` on success; non-zero for invalid arguments (such as an unknown plugin name) or when the output file or its directory cannot be written.
