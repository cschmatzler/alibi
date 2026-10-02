# Native rate-limit runtime

Pinned Source is Better Auth 1.7.6 `api/rate-limiter/index.mjs`, initialization
and installed plugin declarations. The official v1.7.6 redis-storage source was
also exercised against a real local Redis server; exploratory probes remain
outside this repository.

Production now implements ordered first-match custom rules, asynchronous
request-aware override/disable, first matching installed-plugin policy,
raw floating-point limits, shared rolling memory, shared atomic database quotas,
and custom/shared fixed-window cache storage. Generic backend errors stop HTTP
dispatch; intentional application API errors retain their existing semantics.
All database values and predicates are bound through SeaORM. No request-derived
identifier or query fragment is interpolated. Redis scripts use keys/arguments.

The primary HTTP owner is `tests/core/rate-limit.test.ts`. Before the repair,
Native's exact-path precedence admitted a third signup that Source rejected,
creating its actual user/account/session. Native's missing OTP plugin metadata
returned a 10-second retry where Source required 60. After repair, blocked signup
leaves existing ownership unchanged; another trusted client can create the same
identity. A blocked real OTP remains redeemable by another client exactly once.
The same owner proves asynchronous bypass does not reset the existing quota,
a zero-window decision resets memory consumption instead of bypassing it,
and disabled routes remain readable beyond the inherited budget. Cookies are
verified against their real issued token and HMAC; complete literal attributes,
response bodies, physical state and rejection headers are retained.

Real backend owners exercise independent SQLite/PostgreSQL connection pools and
independent Redis connections under concurrent requests, physical counts,
denial without rolling timestamp changes, expiry/reset and unavailable-backend
failure. Database pruning removes genuinely stale rows while preserving rows
inside a longer installed-plugin window and nonexpiring quotas, even when an
independent process has observed only shorter policies. Per-row issued expiry
protects live dynamic quotas from cross-process cleanup. The backend uses an
opt-in migration
with its own ledger; ordinary auth migrations are unchanged.

Raw custom memory limits admit the first request even for zero/negative maxima;
fractions compare against the integer consumption count. Zero/negative/NaN
windows have no live memory entry, while NaN maxima never exhaust it. Positive
infinite windows produce `X-Retry-After: Infinity`. Global zero/NaN defaults are
separately normalized by initialization. SQLite database custom NaN windows or
maxima admit the initial row, then reject further consumption; memory behavior
is not reused for those database branches. Native database exposes the same
explicit decision for either driver, without relying on PostgreSQL's ordering
of NaN values. Official Redis storage accepts only positive whole-second TTLs;
its rejected attempts increment the real counter and never extend its expiry.

Native safety/ownership choices are explicit: process-local default memory must
be shared deliberately across auth instances, bounded memory fails closed at
capacity instead of evicting active quotas, and application backends must provide
atomic consume/increment rather than a racy read/write fallback. PostgreSQL
proof covers finite configured limits, concurrency, expiry, cleanup and failure;
no claim is made that every exotic JavaScript database-adapter coercion has an
identical driver representation. Broader repository checks run after merge
batches under the authorized workflow; focused owners verify this change.
