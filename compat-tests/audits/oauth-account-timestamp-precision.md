# OAuth account list timestamp precision — Better Auth 1.7.6

This narrow capability follows integrated baseline `1aae9395`. The existing
social scopes owner exposed a genuine production response defect, rather than a
stale seed or startup clock. No comparator, tolerance, inventory, schema,
dependency, lockfile or Source authentication change is included.

## Source and failure

The preserved canonical failure `/tmp/next-social-membership-policy-canonical-bounded.log`
reports Source updatedAt `2026-10-01T06:19:31.459Z` versus Native SDK
`2026-10-01T06:30:01.828Z` while the request takes milliseconds. Source
`better-auth/dist/api/routes/account.mjs` lists actual owned accounts through
session middleware, parses account output, and JSON emits JavaScript Date
millisecond precision. Existing `oauth2/link-account.mjs:208–225` updates fresh
tokens on an already-linked account while deliberately omitting scope; adapter
`get-tables.mjs:270–274` refreshes updatedAt on that write.

Rust's private account-list response had used automatic Chrono RFC3339 strings.
The published client `client/parser.mjs` accepts one through seven fractional
digits and passes their integer value as milliseconds to Date.UTC. Six digits
therefore shift dates; nine digits remain strings. Automatic Chrono formatting
usually emits nine digits but emits six when nanoseconds are divisible by 1000,
which explains the intermittent gate failure.

`/tmp/oauth-scopes-published-parser-proof.log` independently invokes that exact
installed parser: reconstructed `06:19:31.630828Z` becomes exactly the reported
`06:30:01.828Z`. The original raw native fraction was not retained by the failed
gate; this literal is an explanatory reconstruction, not claimed recovered wire.
`/tmp/oauth-scopes-baseline.log` preserves complete fresh public account rows
before and after callback and actual clock: both runtimes create current accounts
and update only the linked Google account's updatedAt. Credentials retain their
signup dates. There is no startup timestamp or clock adjustment involved.

## Production and primary evidence

The private account response now uses the existing core JavaScript-Date serializer
for createdAt and updatedAt. It retains full-precision native DateTime values for
its existing chronological sort, so wire truncation cannot introduce new sorting
ties. Store values, associated model accessors and update behavior remain intact.
The list handler uses the existing session middleware error mapper, converting
only missing/invalid session variants to Source's 401 UNAUTHORIZED / Unauthorized;
genuine application, domain and storage errors propagate unchanged.

The existing `social sign-in preserves previously granted account scopes` owner
uses real signup and the existing private account seed to install exact six-digit
createdAt and nine-digit updatedAt literals into an actual known account. The
optional fixture inputs validate both dates before seeding, use bound fixed-column
SQL, and return timestamps selected from the physical row. The Source auth runtime
and adapter are unmodified. Ordinary seed calls retain their existing behavior.

The official client must return actual Date instances and the correct epoch,
while the captured full raw list arrays must contain exact three-digit UTC dates.
Callback success retains the same linked account ID, creation instant and previous
calendar/drive scopes; updatedAt falls within the actual callback window and equals
the full raw response date. The original credential row, all foreign owned rows,
foreign current session and every actual transport remain observed. A genuine
guest receives the source code/message without acquiring either owner's account.

Meaningful failures are preserved:

- `/tmp/oauth-scopes-dates-before.log`: same staged rows and final date assertions
  with old production fail at the six-digit actual SDK epoch: expected
  1790921971630, received 1790922601828, a 630198 ms shift. No timeout.
- `/tmp/oauth-scopes-final.log`: repaired date assertions pass, but the newly added
  real guest exposes the inherited generic 401 code/message mismatch. The bounded
  existing session mapper repairs that distinct response; no assertion is removed.

The existing native list-account owners retain independent storage/guest contracts;
no redundant private formatter test or production testing seam is added.

## Focused checks and limits

- Published parser probe: `/tmp/oauth-scopes-published-parser-proof.log`.
- Source-self primary: one scenario / 76 assertions,
  `/tmp/oauth-scopes-source-self-final-v2.log`.
- Source/Rust primary: one scenario / 76 assertions,
  `/tmp/oauth-scopes-final-v3.log`.
- Complete OAuth/account-management/generic-OAuth family: 33 scenarios / 1382
  assertions, `/tmp/oauth-scopes-family-final-v3.log`.
- Existing native account-list owners: three tests,
  `/tmp/oauth-scopes-account-native-final-v4.log`.
- Strict API library and fixture Clippy:
  `/tmp/oauth-scopes-production-clippy-final-v4.log` and
  `/tmp/oauth-scopes-fixture-clippy-final-v4.log`.
- TypeScript: `/tmp/oauth-scopes-typecheck-final.log`; workspace and fixture
  formatting and `git diff --check` pass.

After the final SDK run, strict Clippy requested replacing the equivalent full-
precision comparison closure with sort_by_key; this retains the same stable
chronological ordering and is included in the final native/strict checks. The
initial strict diagnostic is retained in the final-v3 Clippy logs. Full gates
and integration remain coordinator-owned. SQLite is the real persisted
runtime proof; arbitrary custom date providers, expanded years, timezone sorting
edge cases, identical stored creation instants and existing repeated seed identity
semantics remain separate boundaries. This capability does not alter account
linking, token storage, provider configuration or granted scopes.
