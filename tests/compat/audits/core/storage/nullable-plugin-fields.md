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

The bundled schema declares both columns nullable without a default. It is
installed by the single squashed auth migration; there is no upgrade path from
earlier bundled shapes.

Native evidence covers:

- Disabled creation persists `NULL`; an unrelated update retains it; explicit
  true/false creation and updates round-trip through the store.
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

No route inventory or comparison normalization is changed by this
prerequisite.

This slice does not add async endpoint-context callbacks, arbitrary schema
mapping, or the other plugins' independent configuration and lifecycle
branches. Additional store interfaces must be explicitly forwarded by the
per-instance wrapper when those capabilities are introduced; JWT's keyring
store remains in its separate prerequisite.
