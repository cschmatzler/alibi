# Remaining admin acceptance (#198), published Better Auth 1.7.6

This change completes the supported remaining acceptance together with the
already-landed receipts: canonical numeric identity and combined authority in
#389 (`canonical-identity.md`); explicit-field date sorting/paging in #406
(`date-sort/README.md`); public AND/OR access-control constructors and persisted
permission/tenant enforcement in #409
(`../../organization/role-operators220/README.md`). Those observations were reused,
not rerun. HTTP admin permission inputs remain the published array schema;
the alternative operators belong to the public authorization utility.

## Production repairs and owner proof

Both actual SQLite adapters previously sent scalar custom filters to a fixed
built-in projection, yielding empty pages. They now bind configured scalar
columns, and order numeric IDs/application columns physically before common
search/pagination. Seven public query observations per adapter cover numeric
ranges in both directions, configured dates, JSON equality/LIKE, JSON order,
and offset/limit/total. The complete custom numeric/date/JSON values and relevant
public user fields match Source. Created/updated fixture dates are deliberately
equal, so falling back to chronological order cannot accidentally pass the
numeric/JSON sorting checks. Full physical users/accounts/sessions are unchanged.

Admin expiry used `<=` in impersonation and shared session issuance. Both now
use Source's strict `<`. Thirteen observations per actual adapter cover expiry
at the exact millisecond and both adjacent milliseconds; application session
before/after and user-update before/after errors; explicit API errors; ordinary
exceptions; session veto; and a session hook changing the principal. The latter
retains the Source admission order, including its resulting session owner.
The no-database public impersonation and email sign-in paths add six observations
against actual cookie-only sessions and the initialized in-memory identity store.

The executable Source control establishes this order:

- Equality and future expiry deny without running application session hooks.
- Expired ban: user-before, user-after, session-before, session-after.
- A session-before error or veto occurs after the unban has persisted.
- A user-before error leaves every principal/session/account untouched.
- A user-after error retains the unban but creates no session.
- A session-after error retains both the unban and the new session.

Native ordinary database callback errors had returned a JSON 500, while Source
returns an empty 500. A scoped shared conversion now preserves ordinary callback
exceptions at the affected update/creation boundaries, including secondary and
queued session-after completion. Intentional API errors retain their exact body
and status. Native impersonation veto had returned 403; it now produces Source's
500 `FAILED_TO_CREATE_USER`, without discarding the already completed unban.

The existing admission position follows Source: the admin plugin hook runs
first. Session-before principal mutation therefore happens after the ban decision;
the resulting physical session retains the actual hook-selected owner.

## Honest deterministic clocks and raw evidence

The Source fixtures explicitly install a `Date` subclass before auth creation.
Both `new Date()` and `Date.now()` return 1893456000000 milliseconds. The native
process loads `tests/compat/support/realtime-clock.c`, which intercepts only
`CLOCK_REALTIME`; scheduler/deadline monotonic clocks remain real. The owner
asserts the actual native clock has that exact millisecond and zero nanoseconds.
No Source package byte is patched and no observation timestamp is fabricated.
Seeded SQL dates are actual fixture `Date` values serialized as ISO strings,
matching the native TEXT datetime schema; the observed responses remain raw.

Fresh registry integrity matches the 1.7.6 tarball. All 465 installed Better Auth
files were byte-verified against that tarball and given private inodes before
Bun execution. The final verification confirms every published byte remains
identical. Source controls are the three `admin-*-control.mjs` fixtures added
with this change. Original raw before/after observations, baseline failures and
46 complete response pairs are retained as gzip artifacts here.

Pairing compares public custom values, status, error bodies, result order,
pagination, canonical identity, session owner/actor, deterministic datetime
values and hook events. Exclusions remain generated tokens/session IDs,
fixture-specific roles, and schema-specific optional defaults (including the
numeric fixture's custom fields when exercising expiry rather than querying).
No-database generated Source IDs are verified against their actual seeded
principal within that runtime. Full physical/actual-store preservation is
asserted independently, including fields excluded from cross-runtime pairing.
No account credential, peer session, principal, or tenant is inferred from a
successful response alone.

## Targeted execution

Normal owner command:

```sh
cargo test --locked --test integration --features sqlx,seaorm \
  configured_scalar_filters_and_physical_paging -- --nocapture
```

The clock owners are explicitly ignored without the process clock contract:

```sh
cc -shared -fPIC -o /tmp/close198-clock.so \
  tests/compat/support/realtime-clock.c -ldl
BETTER_AUTH_PROOF_CLOCK_MS=1893456000000 \
LD_PRELOAD=/tmp/close198-clock.so \
cargo test --locked --test integration --features sqlx,seaorm \
  strict_expiry -- --ignored --nocapture
```

Focused execution here imported the same owner into a temporary Cargo target,
without compiling or running unrelated integration owners. Build jobs were 2
and the incremental cache was owned. Custom-query proof passes both adapters;
clock/hook proof passes both adapters; no-database proof passes. Original main
fails both custom owners for the intended missing scalar-column match and all
three expiry owners at equality. A fixture bind-count blocker was corrected
inline; that incidental failure is not used as regression proof.

Production Clippy passes with warnings denied except the existing core
`double_must_use` warning, explicitly allowed. Scoped Rust/Source formatting,
Source Oxlint and diff checks pass. Self-review traces authorization before
query evaluation, typed configured-column bindings, preserved sort/paging total,
both strict expiry owners, callback failures at their actual before/after write
boundaries, session cancellation distinguished from intentional API veto,
secondary/transaction after-hook completion, and the no-database memory path.

Actions are disabled. No hosted CI, full suite, sweep, `devenv test`, canonical
coverage gate, broad Postgres proof, or external reviewer result is claimed.
This acceptance uses actual SQLx/SeaORM SQLite; arbitrary JavaScript/custom
adapter behavior and unsupported HTTP operator shapes are not invented.
