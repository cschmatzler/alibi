# Better Auth database schemas

These assets come from Better Auth TypeScript 1.7.7, pinned by the compatibility reference server. SQLx and SeaORM bundled migrations and CLI-generated migrations share the same source SQL. `better-auth-1.7.7.json` records field requirements, physical names, defaults, indexes, and references from the upstream schema API.

The probe enables the schema-bearing plugins supported by Alibi, including organization teams and dynamic roles, stored last-login method, OAuth provider, and database rate limiting. OAuth, SSO and rate-limit migrations are separate opt-in groups. Application-specific additional fields are supplied by application migrations.

To regenerate the SQL, schema metadata, and independent database snapshots:

```sh
bun install --cwd tests/compat/reference-server --frozen-lockfile
cd tests/compat/reference-server
BETTER_AUTH_TEST_POSTGRES_URL=postgres://localhost/disposable bun probes/generate-schema-assets.mjs
```

The PostgreSQL probe creates and removes its own temporary schema. SQLite runs in memory. Both snapshots describe databases actually migrated by the pinned TypeScript implementation; the Rust integration tests compare adapter-created databases against those snapshots.

Existing Alibi databases require an explicit data migration to adopt these names and constraints. Bundled migrations reject older migration ledgers rather than modifying existing data automatically.
