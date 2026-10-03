# Issue 172: scoped production stateless lifecycle

Reference: published Better Auth **1.7.6**, unchanged. Initial implementation base
`385165ec`; production checkpoints `faf5e241`, `2717c13b`, `136abfd4`, `e890ddec`.
Final rebase target `adb9a9c7` changes admin classification, two-factor numeric
configuration, passkey token-binding validation and fixtures, not these
cache/store/projection paths. No comparator
changes, broad compatibility replay, full devenv test or coverage sweep. Those
historical gates were explicitly superseded by the user. Hosted CI is disabled.

Before this change the public builder required a store and sessions used durable
storage. There was no native no-database provisioning interface or stateless
refreshCache policy. This PR adds actual instance-local user/account/verification
provisioning, session memory fallback, encrypted default caching and envelope-only
renewal. Both actual SQLx and SeaORM stores can retain durable identities while
writing zero session rows; historical SQL session defaults remain stateful.

## Source and raw observations

Read `api/routes/session`, `context/store-capabilities`, `context/create-context`,
`db/adapter-base`, `db/internal-adapter`, and `cookies/index` from the published
package before implementation. `source-integrity.json` records SHA256 hashes of
six installed modules against a fresh published 1.7.6 tarball; all match, including
a final verification after fixture execution. Hardlinked dependencies were never
edited. The fixture invokes real handlers; server-only expiry/refresh controls
remain inside `reference-server/fixtures/stateless-session-evidence.ts`.

`source-profile-0.json` records issuance, custom renewal, cache bypass, trusted
request refresh suppression, logout and captured-cookie replay. Source keeps an
ephemeral session record: bypass succeeds before logout and returns null after;
the captured cache remains usable. `source-profile-1.json` records default JWE,
extra fields, automatic renewal, deferred GET/POST refresh, listing, revocation
and the same replay limitation. Native raw issuance/renewal pairs are retained in
`without-database-issuance.json`, `Sqlx-issuance.json`, `SeaOrm-issuance.json`.

`raw-observations.json` compares raw key sets, configured values, cookie counts
and unchanged renewal payloads. No absence/null, verification scalar, field or
error normalization was added. Generated IDs, credentials and timestamps differ
and remain verbatim in the retained files. Native no-database field sets match
Source, including omitted image and hidden session field exclusion. Native SQL
identity snapshots retain historical nullable image/username defaults; they are
an explicitly different storage/plugin configuration, not a no-database pair.
Native account-cookie defaults in the hybrid SQL configuration also remain
unchanged; the native no-database builder selects Source's enabled default.

## Focused proof

Each new owner exercises observable handlers and/or independent physical SQL
state, not a fake store implementing its own expectations. The actual bundled
adapter owners share setup; no separate inventory or full suite was added.

- `projection-adapters.log`: five owners passed after the omission projection
  change: native no-database credentials/restart and actual SQLx/SeaORM lifecycle
  plus Compact/JWT/JWE, bearer, binding, literal version, retained/retired keys,
  outer cache expiry and embedded expiry boundaries. SQL mode login/read/logout
  still inserts/removes real rows and cannot replay ended durable sessions.
- `custom-model.log`: existing custom-model cache-version owner passed. Created
  callbacks retain the real application model; cached callbacks cannot acquire
  that type or leak its private columns.
- `physical-revocation.log`: two adapter owners passed after the active-selection
  routing fix. Organization/team setters and deferred GET/POST refresh mutate
  ephemeral records without durable session rows. Listing sees both issued
  sessions; revoke-other/all removes memory authority but captured caches replay.
- `explicit-renewal.log`: no-database credential owner passed after adding the
  automatic-renewal and explicit-disabled-policy controls. Extra fields and
  omissions survive automatic renewal, the embedded payload remains immutable,
  restart loses credentials and construction preserves explicit disabled renewal.

Commands use `cargo test --test integration --features seaorm` with only
`storage::stateless::`, `cache_version_retains_actual_custom_models`,
`stateless_ephemeral_mutation_and_deferred_refresh`, or
`without_database_credential_issuance_and_restart` filters as recorded in the
logs. Later checks ran only when their covered production/fixture paths changed.
Initial `cargo check -p better-auth` passed. Inline fixture repairs corrected the
actual plural sessions table, typed field-default values and trusted-hook refresh
control (dispatch correctly rejects caller-injected request extensions).

## Review and bounds

Self-review applied test-audit, wrdn-authz session/JWT guidance and wrdn-data-exfil
serializer guidance. Traced signed-token extraction, token/cache ownership
binding, authenticated decode, embedded/outer expiry/version rejection, cached
projection, typed guards, session listing and ownership-scoped revocation. Cache
renewal clones the complete authenticated views. Cached native UserView can
represent its own typed schema; a database model is never reconstructed. Snapshot
metadata affects output projection only, leaving typed native authority intact.
Hidden fields remain filtered before response/cookie serialization. No additional
permission or data-exposure defect was identified in these scoped paths.

PR374's raw verification output is independently owned. These edits do not touch
wire serialization or provider projection paths and preserve whole retained
UserViews plus omissions; future raw-scalar metadata composes without coercion.
This is a composition review, not a claim of running the pending provider branch.

This is **not full issue 172 closure**. Optional organization/two-factor/passkey/
API-key/device/JWK record storage remains unsupported by the built-in native
no-database store, even where Source's general memory adapter supports it.
Application-backed typed-model handlers require physical model authority or a
cache-aware API. Provider-specific issuance was deliberately not edited/replayed;
ordinary account provisioning uses the existing shared paths. Concurrency and
callback-failure differential coverage is bounded to inspected implementation;
no exhaustive campaign or independent second-agent review was performed. Session
updates avoid resurrecting a record removed while callbacks await, but captured
cookies retain Source's replay limit. The issue stays open with these bounds.

Rebase review: `git range-diff 385165ec..6386bc7a adb9a9c7..01a2ec1c`
reports all five commits unchanged. The actual PR diff was inspected after
rebase; there were no conflicts or affected production interactions. No passing
checks were repeated for those unrelated upstream edits or documentation.
