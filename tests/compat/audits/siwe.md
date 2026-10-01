# SIWE 1.7.6 implementation audit

The reference is the unchanged installed `better-auth@1.7.6` runtime, inspected at
`dist/plugins/siwe/{index,parse-message,schema,client}.mjs` and
`@better-auth/core/dist/utils/email.mjs`. This branch adds the production plugin,
optional EIP-191 verifier, concrete wallet persistence, native integration proof,
and official-client differential scenarios. The coordinator owns full gates,
capability inventory, final locks, and publication.

## Corrected nonce contract

The old upstream audit described nonce aliases as address/chain scoped. The
pinned published runtime instead defines `z.object({}).strict().optional()` for
both aliases, calls `getNonce()` without wallet arguments, and stores
`identifier: siwe:<nonce>`, `value: <nonce>` for 900 seconds. It accepts an absent
body or `{}` and rejects address/chain fields. The differential scenario
`SIWE nonce aliases reject wallet body fields and strict verification prevents
user ownership injection` checks those actual requests and persisted state.
This is an explicit correction to that earlier audit, not an oracle change.

Verification parses the signed address and chain from the original message and
passes them to the application verifier. It consumes the global nonce before
domain, chain, message-time, or signature checks. Rejections after consumption
burn the proof. A controlled asynchronous verifier scenario holds the first
consumer while a second is rejected; only one wallet/account/session is created.
An expired stored nonce is removed and cannot create an identity.

## Application and wire contract

`SiweConfig` requires application-owned `SiweNonceProvider` and `SiweVerifier`
callbacks and a domain. Anonymous mode defaults true. Required-email mode,
custom placeholder domain, and optional `EnsLookup` are supported. Callback
endpoint errors retain their HTTP payload; ordinary callback failures map to the
reference's generic 401 error. Invalid provider nonces produce the documented
500 `SIWE_INVALID_NONCE` response; nonce syntax is 8–250 ASCII alphanumerics.

The verifier receives the exact original message and signature, EIP-55 address,
JavaScript Number chain ID, and typed Cacao. Cacao's domain/audience/issuer use
the configured domain verbatim; the consumed nonce, fixed version `1`,
`caip122` header and `eip191` signature descriptor match upstream. The SDK
observes every callback field, without removing fields from comparisons.

The parser deliberately preserves the runtime's permissive contract: URI,
version and issued-at enforcement belongs to the application verifier. Domain
matching trims/lowercases and removes scheme/path without URL/port
canonicalization. Chain coercion includes hexadecimal and large exponent
numbers; persisted account IDs retain JavaScript decimal formatting. Valid ISO
bounds enforce expiry/not-before; invalid bounds impose no restriction, as in
the reference.

`Eip191Verifier` is an optional real RustCrypto secp256k1 implementation for EOAs.
It uses the original UTF-8 byte length, EIP-55 casing, and 65-byte or EIP-2098
signatures. Its low-S policy is an application-verifier choice; upstream itself
delegates signature policy. A committed independent Noble 2.0.1 signature checks
the Rust implementation. SDK signing and the TypeScript verifier use pinned
Noble; the Rust side uses `k256`/Keccak. The contract-wallet profile performs an
actual local ERC-1271 `eth_call`, validates the signed digest against a public
test owner, and checks wrong owner/chain plus replay. No external credentials or
network chain are required. `reqwest` is added only to the excluded Rust fixture
with JSON and no default features for that local provider request.

Session creation composes with the actual router and admin hooks. A banned
wallet creates no new session. Upstream two-factor hooks do not match
`/siwe/verify`; an enabled owner still signs in with the same wallet identity.
Signed browser preferences affect cookie persistence while the configured
session lifetime remains intact.

## Wallet and email ownership

The store first looks for the exact checksum address/chain pair, then the
adapter's first address match across chains. Repeating a pair rotates the
session without duplicating wallet/account rows. A new chain links a nonprimary
wallet and `siwe` account to the same user. The initial wallet is primary.
Submitted email and session user IDs cannot change an existing wallet's owner.

Anonymous mode ignores submitted email. Required-email registration reserves
`siwe-email-claim-<normalized email>` for 60 seconds. A free reserved email is
used, unverified. A taken/reserved email falls back to the stable wallet
placeholder, never to the existing email user's identity. User creation handles
a concurrent email collision by retrying the placeholder. The owned reservation
is consumed after creation success/failure. ENS occurs before the upstream
creation cleanup block, so ENS failure retains its expiring reservation.
The differential scenarios inspect users, wallets, core accounts, sessions,
proofs, verifier inputs and RPC calls after every transition.

`WalletAddressStore` defaults explicitly fail for unsupported storage. Optional
concrete wallet records preserve custom user schemas without adding another
associated core entity. The appended named migration creates `wallet_address`
with indexed `user_id`, INTEGER-affinity JavaScript Number chain IDs, primary
flag default false, and created timestamp. It intentionally adds no address or
address/chain uniqueness constraint, matching upstream. Provider decoding
retains SQLite integer/real numbers and PostgreSQL integer values.

The generic SeaORM store validates and locks the application-owned user during
wallet insertion. User deletion removes owned wallets in the same transaction;
an application `users` FK is not hardcoded. Canonical stored IDs also scope team
and polymorphic API-key cleanup when caller IDs contain numeric aliases. SQL
proof covers deleted/missing owners, unrelated owners, rollback after a user
DELETE veto, installed-schema upgrades, default-primary persistence, and a
custom numeric-ID schema using `"0001"` to refer to owner `"1"`.

## Focused validation and review

- `cargo nextest run -p better-auth-api siwe`: independent golden Unicode signature and
  signed preference/session-lifetime tests.
- `cargo nextest run -p better-auth-seaorm wallet_`: owner/deletion rollback and
  installed-schema migration/default tests.
- `cargo nextest run --features seaorm2 --test legacy_schema_integration_tests
  numeric_user_schema_cleans_team`: custom numeric ID regression, observed to
  fail before canonical cleanup and pass after it.
- `cargo nextest run --test client_compat_tests siwe_client_compat --run-ignored only
  --no-capture`: official SDK, unchanged reference, exact wire/cookies and
  persisted identity graph across eleven named scenarios (724 assertions).
- Client TypeScript checking and strict production/fixture Clippy.

Test-authoring review gives authoritative wire/state checks to SDK scenarios,
independent cryptographic/cookie-policy proof to native plugin tests, and Rust
migration/custom-schema/transaction contracts to SQL integration tests. No
comparator exceptions, source-grep tests, always-success signature callbacks,
or production test-only switches were added. The held verifier is an ordinary
application callback in the fixture. Authorization review traced strict body
validation, nonce consumption, address recovery, exact/any-chain owner lookup,
email claims, and session creation; no email/user/wallet injection bypass was
found in those paths.

## Remaining integration boundaries

The final integrated canonical gate passed: 238 SDK scenarios / 5,836
assertions, 37 harness tests / 210 assertions, two Chromium tests / 22 assertions,
and 78.65% source line coverage (22,225 / 28,257). The SIWE family contributes
eleven scenarios / 772 assertions. Independent review findings are resolved.
This evidence describes the tested standard profiles, not every upstream option.
Secondary-storage-only verification/session integration, arbitrary model/column
renaming, custom core `validateUserInfo` policy wiring, and arbitrary
engine-specific legacy `Date.parse` strings remain separate boundaries.
Application callbacks can enforce additional EIP-4361 fields, contract-wallet
rules, chain policies and external ENS providers. The fixture proves actual
local callback/provider behavior, not every deployed provider.

Upstream does not wrap user, wallet, account and session creation in one
transaction. This implementation preserves that ordering rather than claiming
rollback of all registration writes on an account/session callback failure.
Independent wallet insertion/deletion integrity is enforced by the store.

Independent integration review reproduced two additional wire boundaries against
actual signed requests. SIWE now rejects a present request body with a missing or
unsupported Content-Type before body validation, nonce generation/consumption,
or verifier calls (415 `UNSUPPORTED_MEDIA_TYPE`, including both nonce aliases).
JSON media type matching is case insensitive and accepts charset parameters.
The signed SDK regression preserves the entire persisted state through twelve
rejections, then consumes the original nonce once with uppercase JSON media type.

For ISO hour 24, every fractional digit must be zero before milliseconds are
truncated. The upstream runtime treats `24:00:00.0000Z` as valid and applies its
future Not Before bound; `24:00:00.0001Z` is invalid and imposes no date bound.
The paired real signature regression proves rejection and successful issuance,
including verifier/persisted state, rather than testing the parser in isolation.

The upstream Better Call allowlist also accepts malformed media types containing
`application/json`. Its decoder can subsequently produce a string or a Bun
ReadableStream instead of JSON (for example `text/plainapplication/json` and
`x-application/json`). Rust's byte-based JSON request representation does not yet
reproduce those runtime-specific structural validation errors. This remains an
explicit wire gap; the standard media-type review fix does not claim otherwise.
