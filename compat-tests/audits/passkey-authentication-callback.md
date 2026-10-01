# Passkey authentication afterVerification

Bounded capability: awaited trusted application callbacks after genuine signed
assertion verification and challenge consumption, before counter/session writes.
Prerequisite 50c1174 preserves the public registration backup/device snapshot
while advancing the genuine opaque credential; this commit adds the callback.

## Pinned contract and production boundary

Installed `@better-auth/passkey` 1.7.6 `dist/index.mjs:453–520` consumes the signed
challenge, checks the ceremony, finds the credential, and invokes
`verifyAuthenticationResponse` with the stored key/counter. A successful result
is supplied to `authentication.afterVerification({ctx,verification,clientData})`.
The awaited callback precedes the counter-only adapter update and session creation.
The original credential lookup's userId remains the session owner, even if the
callback updates the stored row. Source APIError is preserved, including 500;
ordinary exceptions map to 400 AUTHENTICATION_FAILED. The credential lookup is
outside the Source catch and remains outside the new Rust callback classifier.

The public Rust callback receives the actual native AuthenticationResult plus
resolved origin/RP ID, immutable request/config/extensions, and original JsValue
client data. Crypto parsing uses a separate finite JSON clone before callback
execution. Domain/API errors use the existing registration classifier; unexpected
internal errors produce the existing authentication failure. No callback result
or client body chooses a different authenticated owner. The handler captures the
verified owner before callback, reloads the same row afterward to preserve current
public device/backedUp metadata, and updates the genuine verified opaque credential
and counter. Application changes to row owner/name are preserved by the existing
store update. No store/core/entity/schema/migration contract changes.

## Meaningful official-client evidence

All scenarios use the pinned official client and real ES256 software authenticator.
Private fixture policies are immutable server configuration. Callback receipts are
actual awaited database reads after crypto and before storage/session changes;
receipts and fixture counters reset at the real reset-state boundary.

* API 403, API 500 and an ordinary exception retain exact Source wire responses,
  produce no cookies/counter/session writes, and burn the actual challenge; replay
  does not invoke the callback again. Public re-login/list checks the saved counter.
* Successful foreign-client submission cannot change credential owner using body
  userId or nested literal private JSON keys. The callback's stored row identifies
  the original owner, and the issued/current session and persisted counter agree.
* Signed wrong challenge and a valid-DER signature mutation reject before callback;
  their contexts cannot be replayed and both owners' persisted states stay unchanged.
* The trusted mutation callback transfers the actual credential to a preexisting
  foreign user and changes name/device/backedUp. Authentication still issues only
  the original verified owner's session. The foreign user's existing signed cookie
  publicly reads the transferred credential with all application writes preserved;
  its sessions/accounts/user state are unchanged. Original owner lists no credential.

`/tmp/passkey-auth-callback-sdk-before-configured.log`: configured unchanged Rust
production, 1 crypto control passes and 4 intended failures: rejection policies
admit 200 and successful callback receipts are absent.
`/tmp/passkey-auth-mutation-before.log`: callback-capable pre-repair production,
5 controls pass and 1 intended owner mismatch: Rust issues the foreign session.
`/tmp/passkey-auth-mutations-oracle.log`: actual standalone pinned callback mutation
proves original-owner issuance and preservation of application row changes.
`/tmp/passkey-auth-mutation-oracle.log`: full Source-to-Source 6 scenarios /436 asserts.
`/tmp/passkey-auth-callback-family-final.log`: full focused family 17 scenarios /1336
assertions. Existing native passkey 10 tests, API/fixture strict Clippy, and client
TypeScript are recorded in matching `*-final.log` artifacts.

Complete actual serialized verification requests are retained alongside callback
observations. Exact local equality proves the full callback assertion is the
actual issued/submitted input. ClientDataJSON and generated userHandle are decoded
reversibly with exact byte roundtrip checks; every decoded key is retained.
userHandle is the actual random registration options.user.id, not a database userId.
Signatures remain full opaque tokens in submitted and callback observations and
use the existing bijection. All original transport traces and complete responses,
cookies/session tokens/persisted states remain; no comparator changes or digests.
Canonical TraceEntry request bodies record shape; value identity is established by
the additional actual serialized request observation, not claimed from trace shape.

## Explicit limits and setup corrections

No native-only duplicate callback tests were added: the Rust private fixture is an
external public API consumer and the official-client owners prove actual crypto,
callback order/errors, token ownership, persistence and application mutations.
Native tests retained cover distinct existing endpoint/store contracts.

Callback deletion leaves Source's counter update with no row but still creates the
original owner's session; the existing Rust mandatory-row update fails instead.
This deletion/no-row interaction remains unclosed, not masked by the metadata
reload. Captured application stores are outside any adapter transaction; the
callback is not claimed atomic with application side effects. Extensions/native
verifier data beyond the actual signed fixture, arbitrary adapter/hook failures,
and Source session-versus-user lookup exception ordering are not universally proven.
BE false-to-true upgrade and user-presence-only proofs remain separate measured
native verifier policy gaps; no cryptographic retry or policy relaxation was added.

Earlier Source-to-Source attempts with raw generated encodings, an incorrect
userHandle-as-database-user assertion, and a wrong signature status expectation
were fixture setup failures, retained in `*-oracle-before/complete.log` but excluded
from behavior evidence. The initial reference profile omitted the standard username
plugin and produced unrelated user projection drift; configured final before/after
proofs use equivalent profiles. A nonexistent native test-target invocation is
retained in `passkey-auth-callback-native-target-setup.log`; the final proof invokes
the actual `plugins::passkey::tests` native module. No full gate/inventory claim.
