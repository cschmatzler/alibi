# Canonical target identity (#198)

Better Auth 1.7.6 `plugins/admin/routes.mjs` resolves `findUserById` before
checking `adminUserIds.includes(targetUser.id)`. Rust previously checked the
request selector. Numeric application schemas can resolve `00042` to `42`, so
an ordinary impersonator bypassed the configured-admin restriction.

The production repair uses the resolved entity's `AuthUser::id()` for this
classification. Actor authority, role evaluation, session ownership and public
user projection retain their existing owners. No adapter, shared auth helper,
provider, session persistence or comparator implementation changes.

`tests/integration/plugins/admin_identity.rs` is the public Rust owner. It uses
actual i64 user entities, INTEGER primary keys and native SQLx/SeaORM ID parsing.
Both regressions failed before the repair: actor 1 / selector `00042` returned
200 instead of 403, while the canonical `42` denial passed. Both pass afterward.
The shared scenario also checks ordinary non-admin impersonation, combined
operator/elevated roles, and an elevated-only actor lacking base authority. New
sessions have the canonical target owner and original authenticated actor;
complete physical user/account/peer-session snapshots remain unchanged. The
fixture gives original sessions the configured seven-day lifetime so their
read does not intentionally trigger session refresh.

The standalone pinned reference control is
`reference-server/fixtures/admin-canonical-identity-control.mjs`. Run it with
Bun using the reference project's pinned dependencies. It exercises the same
five authority/selector combinations with Source's genuine serial schema and
records raw responses plus before/after physical user/session/account rows.
It uses the real wall clock, migrations, lookup and session creation, with no
mock adapter or edited Source. It is a focused native control, not a claim of
full differential suite execution.

Research loaded the authentic npm 1.7.6 tarball and verified its SHA-512 against
registry `dist.integrity`; no hardlinked dependency files were modified.
Raw local evidence is retained in `/tmp/issue198-evidence/`: `source.log`,
`source-integrity.txt`, `before.log`, `after.log`, the authentic tarball and
`native.sh`. Tested base: `265867b3e7275e092bbe6c2100f21516410e0d37` (with the
inline manifest build repair). Focused command:

```
cargo test --locked --test integration --no-default-features \
  --features rustls,sqlx,seaorm canonical_admin_identity -- --nocapture
```

The base manifest also rejected the root SQLx dependency's `default-features =
false` override; the workspace declaration now permits it. Explicit backend
feature forwarding remains in the root manifest.

This resolves the demonstrated canonical-identity production defect. Issue
#198 remains open: custom numeric/date/JSON query interactions, alternative
access-control operators, and strict ban-expiry equality/mutation-hook ordering
have not been completed here. No broader acceptance or expiry-clock parity is
claimed. Full sweeps were explicitly excluded. GitHub Actions is disabled;
there are no hosted-check results for this change.
