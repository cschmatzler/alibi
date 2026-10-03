# Issue 232 closure: device cleanup and supported composition

PR #418 reconciles #232 against landed production and retained proof, then repairs
two demonstrated production blockers. Source remains the published Better Auth
1.7.6 tarball. All 465 better-auth files and 350 @better-auth/core files in each
private Bun project matched the archives before execution and after all probes.
No package pins, excluded packages, shared decoders, comparisons or coverage
policy changed. See `published-provenance.json` and `published-final-integrity.json`.

## Production and before controls

The Source multi-session logout hook requires a truthy verified payload. Native
logout expired a valid signature over the empty payload. The guard is local to
logout: list/fallback retain their string semantics, admission still counts every
named proof, and selection/revoke retain their nonempty credential requirement.
The existing repeated-genuine-proof owner now exercises real logout, an independent
standards-aware jar, repeated proof retirement, physical owner-row deletion and
complete unchanged foreign rows. `before-retirement.log` fails precisely on the
unexpected empty-proof expiration; Source passed first. `before-retirement-raw.json.gz`
is a bounded isolated before control with only the new five-line logout guard
removed from the final implementation (all other production/configuration remains
fixed). It expires three proofs including empty. Source and final SQLx/SeaORM raw
receipts expire two genuine named proofs, preserve empty/invalid distractors, remove
the owner session (1 -> 0) and retain the complete foreign state. `capture.py`
independently authenticates the genuine emitted proof before presenting it under
a second name. All raw request/response headers, bodies and physical rows remain
in the compressed receipts; these are disposable local fixture credentials.

The genuine no-database composition initially passed every one of its 104 behavior
assertions, but differed at two raw cookie paths: logout and a subsequent cache
bypass omitted `oauth_state` retirement. See `before-nodb-default.log` and the full
`before-nodb-observations.json.gz`. Published create-context selects cookie OAuth
state when `hasServerSessionStore` sees neither database nor secondary storage.
Native account configuration previously selected Database unconditionally.

`OAuthStateStrategy::Automatic` now resolves exactly once in `AuthBuilder::build`,
before plugin initialization. Builder store provenance distinguishes native noDB
provisioning from an explicitly configured external adapter; secondary storage also
counts as a Source server store. An external SQL user store keeps Database even
with stateless session policy. Explicit Cookie/Database choices survive unchanged,
including Database state in native noDB's ephemeral verification store. Calling
store/store_arc after the noDB constructor reinstates external-store provenance.
Uninitialized low-level contexts retain the documented historical Database fallback
in exhaustive OAuth branches. Initialized builder contexts never retain Automatic.
No global credential decoder or session guard was relaxed. The new public enum
variant requires downstream exhaustive matches to account for Automatic.

## Focused proof and test ownership

The existing genuine-proof owner is the primary HTTP lifecycle boundary. Its
previous scope could not observe falsy logout cleanup. The additional noDB profile
uses actual noDB builders/handlers, not an SQL-backed substitute or invented rows.
It independently validates genuine JWE issuance with JOSE and the published cache
reader, configured 300-second envelopes, creation-order lists, foreign selector
rejection, physical target selection, revoked-current fallback, actual logout,
empty SQL state and Source's bounded replay distinction: the captured authenticated
cache remains readable, but cache bypass and the signed selector cannot restore a
retired session. No new production seam exists solely for tests.

- SQLx: `sqlx-retirement.log` passes 1 owner / 34 assertions;
  `sqlx-nodb.log` passes 1 owner / 104 assertions.
- SeaORM: `seaorm.log` passes those 2 owners / 138 assertions with the actual
  compile-time SeaOrmStore fixture selection.
- `native-default-controls.log`: three OAuth lifecycle owners pass, extending
  the existing physical state/nonce rejection/consumption owner across native
  noDB default and explicit overrides, both actual SQL adapters, and SQL-backed
  stateless policy. `native-arc-control.log` passes the affected SeaORM owner after
  routing its controls through store_arc as well.
- `source-default-controls.json.gz`: actual published noDB handlers establish
  default Cookie, explicit Cookie and explicit Database, physical ephemeral
  verification presence/consumption, and matching logout cookie family. The
  Source-only probe retains its relative error redirect verbatim; the existing
  native redirect owner retains its absolute result. No redirect-normalization
  or cross-runtime redirect claim is introduced by these strategy controls.
- Production Clippy passes (`clippy.log`, plus `clippy-compat.log` for the final
  unresolved-context proxy fallback). Focused TypeScript, lint, formatting and
  diff checks pass. A brace-only fixture lint issue was corrected inline.

Commands use the owned checkout, ports 3132/3232 (3332 for the bounded before
control), and `/tmp/multisession232-target` / `/tmp/multisession232-before-target`:

```sh
devenv shell -- env CARGO_TARGET_DIR=/tmp/multisession232-target cargo build --locked --manifest-path tests/compat/rust-server/Cargo.toml
# SeaORM fixture build adds --features seaorm.
AUTH_BASE_URL_TS=http://localhost:3132 AUTH_BASE_URL_RUST=http://localhost:3232 bun test tests/plugins/multi-session/sessions.test.ts --test-name-pattern 'retire repeated genuine|no-database multiple sessions'
devenv shell -- env CARGO_TARGET_DIR=/tmp/multisession232-target cargo test --locked --test integration --features seaorm,sqlx-sqlite core::oauth_state -- --nocapture
bun run tests/compat/reference-server/fixtures/multiple-session-default-evidence.ts
```

No full sweep, full suite, devenv test, canonical coverage run, browser campaign or
remote CI ran. GitHub Actions is disabled. The historical canonical references
below are reused receipts, not new results claimed for this patch.

## Acceptance reconciliation

1. Raw zero/fractional/negative/NaN/infinite admission, truthiness/default and
   non-eviction are complete in #359. Its safely bounded three-signup table and
   final actual SQLx/SeaORM 52-owner / 3,216-assertion receipts remain recorded in
   the parent audit and `/tmp/232-post-rebase.log`. These passing owners were not
   replayed here.
2. Genuine/repeated/expired/foreign proof authority, token aliases/prefixes,
   inherited/per-token path, HttpOnly, SameSite and age precedence, exact SQL list
   order, preserved active/inactive/expired rows and same-owner cleanup are covered
   by the retained lifecycle/expiry owners and #359. This PR closes the discovered
   falsy logout cleanup gap. #415 separately repairs cache-family attributes/chunks;
   no device-cookie attribute repair was duplicated.
3. Supported composition is established by the retained compact interactions
   (#221 audit), JWT/JWE interaction owners (#349 plus #359's final both-adapter
   receipts), and four existing secondary-storage owners (only, preserve-only,
   combined, preserved). The latter exercise real multi-session list/foreign
   selector rejection, OTT generation/verification/replay and physical cache/SQL
   effects; their passing historical receipts are in
   `/tmp/better-auth-harness-release-gate.log` (lines 15596-15599).
   Compact owners include original anonymous linking, JWT headers, real OTT
   consumption and pending/completed two-factor publication. Existing switch,
   revoke/fallback and logout owners retain complete cache/state observations.
   The noDB selector/order/fallback/logout/replay omission is now proved here,
   and its actual default cleanup blocker is repaired in this same PR.

#232's representative supported configuration/composition acceptance is complete;
no Cartesian product or arbitrary custom schema/provider/runtime matrix is claimed.
The broader session/storage lifecycle, renewal, key rotation and production-domain
work remains with #171-177 as #232 explicitly required, rather than being silently
claimed or duplicated. OTT callback failure #416 and factor corruption #417 remain
separate owners. Their nominal receipts are not replayed for this change.

## Review and integration

Single-worker source/security review traced issued HMAC proof ownership, signed
empty truthiness, duplicate names, current/foreign isolation, adapter deletion,
cache authority versus physical selector authority and replay, Source capability
selection, explicit override precedence and plugin initialization order. Shared
cookie signing, JWT/JWE authenticated decode, list order, eviction limits, raw
observations and exclusion policy remain intact. No nested reviewer was spawned.

Final integration base: `dfd88d21` (#417). Its only incoming files are factor backup
storage, the two-factor owner and its codec evidence. No builder, state strategy,
multi-session, cache decoder, shared cookie helper or affected fixture changed.
The three commits are unchanged by range-diff (`rebase-range-diff.txt`). Passing
adapter checks were not replayed for this unrelated incoming update. The final
post-proof edits are the already checked unresolved-context proxy predicate,
store_arc default control, brace-only Source fixture lint fix and evidence/docs.
Focused formatting, TypeScript, lint, Clippy and `git diff --check` are green.
