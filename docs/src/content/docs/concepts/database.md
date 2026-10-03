---
title: "Database"
description: "Application-owned authentication models and migrations."
---

`AuthSchema` selects the application's user, session, account, and verification models. Your application owns the models and migrations.

## Generate a schema

```bash
better-auth-rs generate -o src/auth_schema.rs
```

The output contains all four models, `AppAuthSchema`, and SQLx migration scaffolding. Include it with `mod auth_schema;` as shown in [installation](/installation/).

| Role | Stores |
| --- | --- |
| User | Identity and profile |
| Session | Credential, expiry, and ownership |
| Account | Password or provider credentials |
| Verification | Time-limited proofs |

## Add plugin fields

```bash
better-auth-rs generate --plugins username,admin,two-factor -o src/auth_schema.rs
```

Review generated changes before replacing an existing schema. New Rust fields still need database migrations.

`run_app_migrations` bootstraps a new SQLx database. `SchemaMigrator::migrate` installs the bundled schema and its ledger; it does not migrate arbitrary application models. Keep your own versioned migration system as the schema evolves.

Continue with [SQLx](/databases/sqlx/), [SeaORM](/databases/seaorm/), or [existing databases](/guides/existing-databases/). [Additional fields](/concepts/field-policies/) control API input and output separately from physical models.
