# Nullable plugin user fields

This prerequisite preserves the distinction between an unset plugin field and
`false` in storage. Better Auth 1.7.6's admin `banned` and two-factor
`twoFactorEnabled` schema fields are optional. Their `false` defaults belong to
the enabled plugin's input handling. A shared database used by an auth instance
without those plugins can contain SQL `NULL` in both columns. The strict
passwordless configuration scenarios exposed Rust's former unconditional
`NOT NULL DEFAULT FALSE` and entity creation defaults.

`CreateUser` now carries optional `two_factor_enabled` and `banned` values.
The bundled model and generated plugin schema use `Option<bool>`. The familiar
`AuthUser::two_factor_enabled()` and `banned()` methods remain boolean checks;
the new `*_value()` methods retain the actual optional state for projection.
The derive supports both nullable fields and existing custom boolean fields.
Boolean custom entities accept explicit creation values and retain their
existing default when a value is absent. Applications needing an unset state
must use nullable columns and nullable model fields.

Raw storage preserves the supplied fields without initializing disabled
plugins or applying unrelated update policy. The auth builder wraps the shared
adapter with that instance's registered plugin transforms. Admin supplies a
missing `banned: false` and configured default role; two-factor supplies a
missing `twoFactorEnabled: false`. Explicit values remain intact. These
transforms run before application database hooks, including transactional
creation, through both the public store and the auth context. A second auth
instance sharing the adapter retains its own defaults and update policy.
Enabled output projects an existing unset value as JSON `null`; disabled
output omits the plugin's fields. Boolean authorization checks still treat an
unset flag as `false`.

The upgrade keeps existing true/false values. PostgreSQL drops the two columns'
`NOT NULL` and default constraints in one `ALTER TABLE`; this slice compiles
that backend but does not run a live PostgreSQL server. SQLite uses one pinned
connection and one rebuild transaction. It retains ordinary and generated
custom columns, checks, indexes, triggers, views, child foreign keys, hidden
row IDs, and numeric auto-increment sequence state. The rebuild temporarily
changes foreign-key enforcement and legacy rename validation, restores the
original settings on success/error, and closes an interrupted connection
instead of returning changed settings to the pool. Other backends fail
explicitly. SQLite migration inside an existing caller transaction also fails
explicitly because its foreign-key setting cannot safely change there.

Native evidence covers:

- Disabled creation persists `NULL`; an unrelated update retains it; explicit
  true/false creation and updates round-trip through the store.
- Populated upgrade preserves users, accounts, sessions, custom child links,
  generated fields, expression indexes, triggers and an existing view.
- A rejected rebuild leaves the original rows/constraints intact and restores
  foreign-key enforcement.
- Cancellation during the actual database row copy retains the original
  schema and rejects a later invalid foreign-key insert. Removing the
  connection guard demonstrably makes that insert succeed.
- Numeric sequence state, text row IDs, `INTEGER PRIMARY KEY DESC`, composite
  primary keys, `WITHOUT ROWID`, quoted commas, SQL comments, signed defaults,
  named constraints and all five `NOT NULL ON CONFLICT` algorithms survive
  the upgrade. Removing the hidden-row-ID copy demonstrably changes a retained
  ID from 40 to 1.
- A custom boolean entity persists explicit flags and updates through the
  generated model interface without changing its field types.
- Public builder/store and auth-context writes apply registered transforms in
  order; a second instance on the same adapter stays unaffected. Rejected
  transforms leave persisted data unchanged. Real transaction commit and
  forced rollback retain those guarantees.
- Enabled admin/two-factor defaults reach the actual application
  `before_create_user` hook, including inside a transaction. Explicit true
  values survive; raw and disabled creation retain nulls; existing null rows
  stay null after initialization and project as null only when enabled.

The migration was independently reviewed. View rename validation, hidden-row-ID
alias detection and attached conflict clauses were reproduced as failing
database operations before their repairs. No route inventory or comparison
normalization is changed by this prerequisite.

This slice does not add async endpoint-context callbacks, arbitrary schema
mapping, or the other plugins' independent configuration and lifecycle
branches. Additional store interfaces must be explicitly forwarded by the
per-instance wrapper when those capabilities are introduced; JWT's keyring
store remains in its separate prerequisite.
