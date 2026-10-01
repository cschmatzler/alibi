# Application JWT keyrings and remaining option boundaries

Issue #209 uses the published Better Auth 1.7.6 runtime. Its primary new owner is
`tests/jwt/keyring.test.ts`; existing managed JWT, numeric-claim, remote-signer,
session, API-key and compact-cache owners remain in place. No oracle code,
comparison allowance, date tolerance, cryptographic admission or earlier
capability requirement is changed.

## Authoring gate and actual boundary

The new owner protects application key-storage callbacks, private key storage,
public JWKS/token transport, custom session claims and the cache/JWT lifecycle.
Credible regressions include a dropped callback input, duplicate or omitted
application reads, ordinary errors exposed as JSON, explicit API errors hidden,
incorrect key selection, signature/key substitution, lost nullable cache fields,
or physical session revocation prematurely overriding a valid ordinary cache.
The custom-cache owner separately catches loss of the real direct-hook clock or
version and accidental propagation of that metadata into nested token middleware.
The server-only owner catches loss of the endpoint path when no HTTP request
exists. Neither contract was visible to the earlier default-cache owner, which
remains intact. These use the actual public callbacks and signing helpers; no
new test-only production seam is needed.

Earlier default-store tests cannot observe an application keyring's requests,
write data or real SQL rows. Earlier compact-cache tests do not exercise JWT
issuance against that keyring. Existing session/API-key owners independently
guard refresh and virtual-principal behavior changed by the cache integration.

Both fixture applications store the production-generated JWK and actual
encrypted/plaintext private key in a separate SQLite application table. Every
lookup is an actual parameterized SQL read, and creation stores the exact
production callback argument. Private controls expose complete public row
metadata and an encryption classification, never private key material. Callback
receipts capture actual request path/method/marker/cookie presence, actual
returned IDs, generated key data and complete received session/user snapshots.
They do not infer expected receipts from the request or supply production
callback ordering. The public SDK reads real HTTP routes; JOSE independently
imports their actual public keys and verifies each successful signature.

The custom payload application specifies `iat: 100` and `exp: 4102444800` as its
actual signing policy. This keeps its large failure table independent of
different runtime execution speeds. Both production implementations receive and
sign these claims. Existing default JWT/session owners retain issuance-clock
and lifetime proof. Numeric-expiration cases use independent compact JWS
verification so an intentionally historical expiration cannot make the
cryptographic positive control fail for an unrelated clock reason.

The custom-cache application encodes the complete callback snapshot with its
actual numeric `updatedAt` converted losslessly to ISO and an explicit
`updatedAtType: "number"` tag. Its subject also depends on the actual version
and clock type. Independent assertions round-trip that clock against the
published compact decoder. Stored, nested and versionless-cache inputs retain
their different field presence. The versionless envelope keeps the actual
issued identity and clock and is reauthenticated with genuine independent
HMAC-SHA256; both published decoding and real HTTP admission verify it. It
claims no server-issued cookie receipt for that application-created envelope.

The concurrency case coordinates two real initial empty reads before either
request can create a key. It delays the second creation until the first public
JWKS response completes. Both production paths still generate, insert and
publish their own real keys. The observed callback sequence, row count, row/key
identity and independent signatures are assertions, not scheduled receipts.

## Repairs

- Public JWT routes and the get-session JWT response hook now map private
  ordinary failures to the existing empty-500 transport. Intentional `Api` and
  `Upstream` errors retain their status, code and message, including API500.
  Trusted signing/keyring APIs retain their ordinary Rust errors.
- A remote discovery URL keeps the local JWKS response empty with status 404
  and Source's application/json header, without invoking signing or storage.
- `JwtSignOptions.resolved_key` consumes the opaque result of
  `resolve_signing_key` in the same managed signing path. OIDC applications can
  inspect its public algorithm before constructing hash claims and sign without
  another keyring read. Private key material remains inaccessible and absent
  from Debug. Remote signers still own key selection.
- Unpinned primary-algorithm selection performs the Source fallback lookup when
  no primary key is live. This is a real second application callback; it can
  fail or return a changed set. It is not a copied counter increment.
- Numeric configured expiration now accepts IEEE754 `f64`, retaining fractional
  values and allowing managed signing to reject nonfinite values at the actual
  JOSE-compatible boundary. Previously `Numeric(i64)` could not represent these
  configurations; that is an API representability limitation, not a runtime
  failure manufactured by a fixture cast.
- Ordinary token issuance uses the existing authenticated cache/store reader.
  Stored users retain configured projection and cached users retain their real
  authenticated public snapshot. A validated API-key virtual session keeps its
  original exact snapshot, without persisted-session null defaults. Completed
  response snapshots still do not authorize token issuance.
- The authenticated compact decoder preserves null presence for exactly the
  eleven recognized optional UserView plugin fields, following its existing
  session-field idiom. It adds only present null fields after HMAC/shape
  validation. It does not merge arbitrary fields into identifiers, roles or
  tokens or change sensitive authoritative-session guards.

- Direct get-session JWT callbacks now receive the authenticated cache
  snapshot's real numeric `updatedAt` and optional version. Metadata is retained
  in request-local typed state after authenticated decoding, and only the
  direct response hook reads it. Token middleware continues to expose its
  completed user/session result. Every stored or virtual read clears cache
  metadata. Missing cache versions remain absent.
- Application keyrings receive `JwtKeyringContext`, separating the actual
  endpoint path from the optional real HTTP request. Server-only signing
  without a Request and verification use `virtual:`; verification with a
  Request retains that request's actual method, path, headers and bytes.
  The fixture no longer constructs a virtual HTTP request.

## Pinned option audit

The installed `types.d.mts`, `index.mjs`, `sign.mjs`, `verify.mjs`, `adapter.mjs`,
`utils.mjs`, `cookie-cache.mjs`, the duration utility and JOSE implementation are
the source of this inventory. Type options and runtime support are distinguished.

| Pinned option or boundary | Proof and current scope |
| --- | --- |
| EdDSA/Ed25519, ES256/P-256, ES512/P-521, PS256 and RS256 | These five are the complete pinned asymmetric type union. Existing official-client algorithm table imports actual JWKS and verifies every algorithm. No ES384/RS384/PS512 support is claimed. |
| RSA `modulusLength`; private encryption on/off | Default 2048-bit RSA remains covered; new external-store owner uses real 3072-bit RSA and checks its modulus, plaintext storage and signatures. EdDSA external rows are actually encrypted. |
| Primary and additional key pairs; kid and algorithm selectors | New owner proves real lazy ES256 provisioning, primary RSA preference, explicit IDs, absent IDs, ID/algorithm mismatch and unconfigured algorithm rejection without extra rows. |
| `resolveSigningKey` and supplied `resolvedKey` | Actual helper resolution followed by signing uses one callback lookup and the same key, not a second resolution. Both ordinary JSON and typed-map signing use the production managed path. |
| `createJwk`; installed legacy rows | Real exported/helper creation writes a new application SQL row with request context; missing alg/crv inherit the configured default for lookup, JWKS and signing. |
| Rotation and grace | Existing default-store owner remains. External-store owner separately expires real rows, mints replacement keys, retains public grace keys, retires public keys, verifies against retained raw rows, refuses expired explicit IDs and preserves foreign state. |
| Corrupt private/public rows and recovery | Public failures keep Source transport; helper verification returns null; exact corrupt rows remain until explicit application deletion. An all-retired set publishes an empty JWKS; an actually empty set creates a fresh key. |
| Custom `getJwks` and `createJwk` | Actual external SQL callbacks receive real public request metadata and complete generated key data. Ordinary, API403 and API500 failures retain rows and foreign users. Empty Vec is the Rust representation of an absent key set. |
| Issuer, audience string/array, subject and payload | Existing explicit-claims and configured-claims owners remain; new complete session snapshot/custom subject table covers email, empty subject and null fallback, wrong audience, ownership and sign-out/replay. |
| Number/Date/duration expiration | New table proves fractional/zero/negative numbers, dates floored to Unix seconds including pre-epoch dates, signed fractional duration rounding, months and 365.25-day years. Actual duration code accepts months despite the pinned type comment saying otherwise. Rust durations are the idiomatic equivalent of valid Source duration strings. NaN/Infinity default options fail managed signing; explicit finite payload expiration wins. |
| Protected header; alg/kid ownership | Complete supplied typ/cty survive while local keys own alg/kid. Critical empty/unknown extensions and unencoded JWT payloads reject; existing strict local-header controls remain. Remote header ownership is proved by the separate #229 owner. |
| `jwksPath`, `disableSettingJwtHeader`, exposed headers | Existing configured path/header and session hook owners retain replacement-path 404, header suppression and ordered exposed-header proof. New external-keyring owner exercises normal get-session headers and callback/API failures in that after-response path. |
| `jwks.remoteUrl` and `jwt.sign` | New public remote-discovery owner proves exact local JWKS refusal and no signer/key-store activity. #229 owns the real application HS256 signer, callback arguments, raw claims, custom results and lack of local key creation. Source verification uses adapter keys; it does not fetch the configured remote URL. No invented JWKS HTTP fetch or KMS integration is claimed. |
| `schema` | Existing adapter/schema projection owners remain. This fixture uses the real default JWT schema plus a separate application key table; it does not claim every possible schema rename. |
| Custom cached payload/subject and server-only context | Complete direct hook metadata, exact version absence on a real authenticated legacy envelope, nested/stored field absence, metadata-dependent subjects and JOSE signatures. Actual Source server-only sign/verify calls omit Request; callback path survives while method/headers stay absent. Verification with the actual HTTP control Request retains its distinct endpoint path. |
| Compact cache + default JWT | Actual published compact decoder, cached versus stored get-session headers, retained ordinary token issuance after physical revocation, explicit bypass and guest/replay rejection, complete nullable user claims and foreign-state guards. |

## Shared dependencies and explicit limits

`sessionCookieCache: true` with the core JWT strategy uses the plugin's managed
asymmetric signer in Source. The native core presently supports compact caching
only. Symmetric/managed JWT and JWE cache formats remain #171; stateless cache
and refresh behavior remain #172. This PR proves compact/default-JWT composition
and does not claim those modes or full raw nonfinite rotation/grace configuration.

The bounded JWT context and compact custom callback inputs are implemented
and covered here. Broader server-only dispatch APIs remain #205; this PR does
not claim the complete shared dispatcher. Managed JWT/JWE cache signer formats
remain #171, and do not block the compact-cache acceptance proved here.

## Validation

Initial Source control passes all four original scenarios; original native
production fails ordinary error transport and the redundant resolved-key read.
An isolated original-production replay also uses the exact final six
representable cases: two pass and four fail, for ordinary errors, the extra
resolved-key read, rejection of a revoked physical session's valid cache and
the remote-discovery Content-Type header.
Its only fixture API adaptations are the absent resolved-key signing option
and the original numeric enum. The numeric option owner is excluded from that
runtime replay because its new floating-point configuration does not compile
against original Numeric(i64); the genuine compiler errors are separate proof.
The original request-context adaptation is superseded by the real optional
request/context API and the new server-only owner. The immediate pre-context
4557260e production replay runs both final new owners: both fail, respectively
for missing updatedAt/version/type and a null endpoint path. Its only fixture
adaptation is the original keyring trait signature; it preserves the actual
optional request and does not fabricate a virtual path. Subsequent actual six-scenario comparisons independently
exposed fallback-read, revoked cached-token and nullable-field failures. The
existing API-key owner caught virtual-session projection drift and was retained
through its repair. Final exact Source/native counts, focused siblings, strict
checks and actual canonical completion are recorded in the PR.

Private controls do not claim public capabilities. Added ledger requirements
must have actual public-route receipts in successful complete comparisons;
all previous requirements remain. No test-only production export or fake crypto
is added. The external `$autoreview` and referenced OpenClaw testing/PR skills
are unavailable; independent coordinator review accompanies executable proof.

Final owner proof before the immutable canonical rerun: Source 9/9 with 1,542
assertions; Source/native JWT, remote, numeric and session owners 36/36 with
3,070 assertions. The two immediate pre-context regressions fail on untouched
4557260e production with 124 assertions and pass after repair with 208. Actual
143-route evidence preserves the rebased main's 2,674 requirements and adds
59 measured public cells, for 2,733. Strict optional workspace/fixture Clippy
and TypeScript checking pass.

The earlier immutable 4557260e canonical ran all required stages up to the full
SDK gate: default 794, feature 845, fixture 2, harness 70, Axum 36, endpoint 3
and inventory 2 passed; SDK 753 passed and 21 failed with 58,342 assertions.
Browser, documentation and coverage stages were unreached. All seven then-new
keyring owners passed. A retained remote undefined-claim owner reported one raw
default-expiration difference; its unchanged focused rerun passed 34 assertions.
That unreproduced failure remains recorded, alongside the independently
reproduced API-key Content-Type baseline and other existing gate failures.
