# Issue 177: completed cookie policy and emission lifecycle

PR #425 completes the supported remaining acceptance against authentic published
Better Auth 1.7.6. The private reference install's 465 better-auth, 350 core and
90 Better Call 1.4.0 published files match registry-integrity-verified tarballs;
every inspected file has one private inode link. No package mutation occurred.
`published-provenance.json` records the final byte and inode verification.

Actual Source/Chromium TLS passes while baseline Native fails both static and
trusted-proxy domain inference (`close177-tls-before.log`). Published omitted or
empty domain means the configured/resolved URL hostname without its port;
explicit domain and default/per-family overrides retain precedence. Localhost
and bracketed IPv6 are raw emission contracts, not claims that browsers accept
those Domain attributes. Inference does not choose a registrable parent domain.
The TLS proof uses two non-loopback hostnames mapped inside Chromium, a bounded
loopback TLS reverse proxy, a task-local certificate and independent standards
jar; it changes no ambient hosts, services or trust store. Browser persistence,
reload, child-subdomain restoration, issuing-origin logout and physical owner
session deletion all succeed on authentic Source and both actual SQL adapters.

CookieAttributes now accepts f64 Max-Age, explicit UTC Expires and Partitioned.
The common fallible serializer retains published attribute order, prefix scope,
nonnegative flooring, negative/NaN omission and emission-time 400-day limits.
Signed zero becomes header zero only; payload truthiness and family TTL choices
remain intact. Domain/path validation is not invented. Max-Age validation occurs
before Expires. Limit failures are scoped CallbackFailure(Internal), yielding an
empty core HTTP 500 with no cookies; global Internal error behavior is unchanged.
SIWE's existing catch instead emits its measured 401 and raw fixed serializer
message. Its unrelated storage errors keep their existing mapping.

The existing signup transaction now renders actual token/preference headers
once before cache emission, returning them to the sole handler. Synthetic
signup duplicates still return no headers. Emission failure rolls back physical
user/account/session rows; ordinary signin has already committed its session and
retains it. No earlier/additional hooks, publication probe, ledger or general
atomicity guarantee is introduced. Mechanical AuthResult propagation preserves
merged #419's factor-local decoder and #420/#421's OAuth/proxy authority, signed
browser preference and configured callback fallback.

Session_data's own override controls its header and envelope independently:
+17 => header17/payload17000ms; zero => header0/compact60000ms; negative => no
Max-Age/payload-1000ms; 0.5 => header0/payload500ms; NaN => no Max-Age/compact60000ms.
JWT/JWE retain their published truthiness fallback of300seconds, rather than
compact's60seconds. Session tokens remain604800 despite default Max-Age99;
embedded session expiry and renewal policy remain unchanged. Factor factory
family overrides win after producer age, without duplicate Max-Age: headers121
and321 from fractional121.9/321.9 coexist with physical challenge600seconds and
trust2592000seconds. Stored proof lifetimes and authenticated factor bytes are
unchanged. Renderer attribute merge applies equally to cache chunks and their
retirement headers, including configured Expires/Partitioned.

## Focused affected proof

| Owner | SQLx | SeaORM | Observable contract |
| --- | --- | --- | --- |
| Serializer/domain | 12 pass | 12 pass | Raw order, prefixes, Expires/Partitioned, exact400-day acceptance, empty500/no headers, signup rollback versus signin commit, URL hostname spelling |
| Cache overrides/chunk attributes | 6 pass | 6 pass | Authenticated payload TTL, independent token TTL,4050-byte capacity, base/canonical chunk precedence, complete scope and physical/logout retirement |
| Factor factory attributes | 1 pass | 1 pass | Real OTP issuance, exact signed-cookie attributes, independent persisted lifetimes and challenge consumption |
| SIWE emission error | 1 pass | 1 pass | Genuine EIP191 signature,401/raw serializer message/no cookies, consumed nonce and retained committed user/account/session |
| Quoted/duplicate/replay | 1 pass | 1 pass | Genuine signed first-cookie admission, quotes, first duplicate rejection, malformed proof rejection, unchanged rows, physical logout and revoked replay denial |
| Actual TLS Chromium/jar | 4 pass | 4 pass | Source/native static and trusted proxy persistence, cross-subdomain reads/reload, logout and physical session deletion |

Complete TLS/serializer raw responses and physical rows are retained in the
corresponding final logs; the nine `seaorm-paired-*.json.gz` files retain complete
Source/Native SDK requests, raw headers/bodies and original physical observations
for the cache/factor/SIWE/quoted owners. SQLx logs record the same independent
assertions against actual SQLxStore. Earlier raw Source measurements and genuine
quoted Native rejection are retained. The intermediate serializer log records
the initial JSON500 objection before scoped error classification was repaired.
The first SeaORM launch raced readiness; the successful isolated final log
supersedes that connection-refused diagnostic. Tests ran sequentially because
fixture resets share each backend. No reset-interfered browser result is counted.

Commands use owned ports4177/4277 and `/tmp/close177-target`:

```sh
devenv shell -- env CARGO_TARGET_DIR=/tmp/close177-target cargo build --manifest-path tests/compat/rust-server/Cargo.toml
# Actual SeaOrmStore selection: add --features seaorm.
AUTH_BASE_URL_TS=http://localhost:4177 AUTH_BASE_URL_RUST=http://localhost:4277 bun test tests/core/session/cookie-serializer.test.ts
# Same env, focused --test-name-pattern for the five override + attributes case,
# factor factory, SIWE serializer and physical first-cookie owners.
devenv shell -- env AUTH_BASE_URL_TS=http://localhost:4177 AUTH_BASE_URL_RUST=http://localhost:4277 bun test browser/cookie-policy.test.ts
```

The test-audit gate retains these real boundary checks: baseline domain/cache/
quoted failures demonstrate production discrepancies, newly expressible
serializer attributes/errors require actual response/storage-stage proof, and
factor/chunk attributes extend existing lifecycle owners at distinct risk.
No test-only production seam, comparison relaxation or inventory was added.

## Full acceptance reconciliation

1. Secure prefixes, HTTPS defaults, configured names/path/ordinary attributes and
remember preference were already completed in #401 (15 actual lifecycle cases
per adapter plus browser receipts in `../secure-cookie-policy-177`). This PR
adds real TLS/non-loopback/trusted proxy inference and the remaining serializer
attributes/limits. Explicit domain/attribute precedence is preserved.
2. Physical token/preference creation, rotation/replacement, expiry/corruption,
scoped deletion and independent jar retirement remain in the physical-session
cookie owner/#401. This PR repairs and proves genuine quoted first-cookie
handling plus duplicate/malformed/revoked replay boundaries.
3. Cache base/chunk capacity, canonical ordering, base precedence, replacement
and stale retirement were completed by #415 (`../cache-cookie-attributes-177`).
The affected attributes case here adds Expires/Partitioned without replaying its
other inventories; compact override proofs establish the remaining payload/header
priority. Retained JWT/JWE interaction and authenticated read receipts establish
supported strategies; no decoder or renewal-policy changes are claimed.
4. Account JWE/DEF, complete payload, malformed/expired/foreign proof rejection,
TTL stages, chunk replacement/base precedence and stale logout cleanup were
completed by #395/#230. Reuse `../../social/oauth-account-cookies.md` and the
retained account230-20261003 evidence directory, whose receipt records merged
`eb94cca5`. The only account changes here are numeric identity-cast removal and
fallible shared rendering; account signer/grant/ownership policy stays with #420.
5. OAuth Cookie and Database state creation/expiry/nonce mismatch/consumption,
raw retirement and saved error callback are retained in OAuth state lifecycle
and `../../social/oauth-state-error-restoration.md`, #418's noDB default receipts,
and #421's `../../../plugins/oauth-proxy/remaining-227`. Signed preference age
omission and account callback authority survive mechanical error propagation.
OAuth proofs are single values; no unsupported chunk-store semantics are added.
6. Multi-session creation/selection/foreign isolation/expiry/retirement, repeated
proof handling and noDB composition were closed by #418/#232. Reuse
`../../../plugins/multi-session/232-closure/README.md`; falsy/invalid distractors
remain while genuine proofs retire, actual owner rows delete and foreign state
survives. A captured valid cache can still be readable while bypass/selector
cannot restore a retired physical session. This is Source's replay limit.
7. Factor challenge/trust creation/rotation/expiry/replay, aliases/first-cookie
handling, scoped physical consumption and error stages were closed by #419;
reuse `../../../plugins/two-factor/installed-json.md` and `trust-ttl.md` plus
retained close202 evidence. This PR changes only emission delegation/Result
propagation and proves the remaining configured factory attributes/lifetime split.

Only session/account data use Source's bounded chunk store; token, OAuth state,
multi-session and factor proofs do not acquire invented chunk families. Cookies
are authenticated capabilities with family-specific expiry/physical authority,
not a universal one-use ledger. Replay/concurrency claims stop at the retained
actual consumption/cleanup boundaries; no stronger universal atomicity is implied.
All three #177 supported acceptance items are reconciled across these receipts.
The user's explicit no-full-sweep instruction supersedes the issue's historical
canonical gate request. No full suite, devenv test, coverage or remote CI ran;
GitHub Actions is disabled.

## Integration and independent review

Source/security self-review covered raw signing bytes, family/default precedence,
serializer stage/order, partial writes, cookie publication, physical ownership,
proxy and factor-local authority. Coordinator independently reviewed production
checkpoint8e9b6862, identified the JSON500 wire objection, accepted scoped fix
90b73109 after actual Source qualification, and reviewed final d8d18179. Its
first-match collision objection is repaired with iter().find followed by
and_then(max_age), preserving prior semantics without indexing. Signed-zero
normalization and unchanged incoming #424 were accepted. Final SHA and static
receipts are recorded in `receipt.json`; approval is coordinator review, not a
fabricated external review or hosted CI.

Actual SQLx proofs used90b73109 plus the focused attribute fixtures; SeaORM
proofs include those fixtures and signed-zero normalization. The final lint-only
cleanup preserves first-match and Result behavior. Rebase onto #424 ffdbdafb was
inspected: additive trusted-provider init/request clone resolution does not change
cookie/domain/proxy/factor owners. Passing adapters were not replayed after that
unrelated rebase or lint-only edits.
