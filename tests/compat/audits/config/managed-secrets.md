# Managed secret versions and rotation

Reference stays pinned to Better Auth 1.7.6. The independent sources are
`dist/context/create-context.mjs`, `dist/crypto/index.mjs`,
`dist/crypto/jwt.mjs`, `dist/cookies/index.mjs`,
`dist/api/routes/account.mjs`, and the email-OTP, two-factor, JWT and OAuth-proxy
plugin owners. The Rust public API is `ManagedSecrets` plus
`AuthConfig::managed_secrets` and `AuthConfig::current_secret`.

| Contract | Official-client owner and actual evidence |
| --- | --- |
| Current writes, retained readers, retirement, explicit legacy input | `tests/config/managed-secrets.test.ts` observes real encrypted email-OTP rows and consumed proofs, old/bare writes, retained/legacy acceptance and retired rejection. Imported Source-encrypted proofs cover the installed parseInt whitespace/sign/prefix semantics, unknown versions, wrong keys, authenticated tampering, missing separators and truncated ciphertext. |
| Factor secret and backup rotation | The same owner enrolls an actual factor, decrypts its persisted secret with the published Source decoder, completes a current-key pending challenge with an old backup, verifies the current-version remaining backup row, and rejects retired readers and backup replay. |
| Signing-cookie invalidation and cache issuance | Old signed primary cookies fail at the rotated runtime. Fresh sign-in emits a current-key compact cache accepted by the official decoder and rejected with the legacy key. Two-factor precedes multi-session in both fixtures; actual primary and multi-session issuance remains in the full traces. |
| OAuth tokens and account JWE renewal | Actual linking followed by social issuance writes account credentials and emits the account JWE. Published decoders prove provider plaintext and old credential versions; each cookie credential is exactly the corresponding physical row ciphertext. Fresh current-key sign-in renews the outer JWE while leaving every account field and credential ciphertext unchanged. The renewed JWE fails with the old key. The user name has 6,000 characters, so the actual compact cache is emitted in multiple chunks. Retained account-cookie reads, foreign owners, expired cookies, tampering and retirement preserve rows; actual provider refresh rewrites access and refresh credentials under version 2. |
| Private JWKS readers | Actual SDK JWT issuance creates encrypted private-key rows. Published JOSE verifies the tokens and public JWKS excludes private material. Retained readers sign with the old key; retirement fails before signing while public JWKS and rows remain unchanged. A controlled server-only `createJwk` call writes a current key and restores signing at the retired runtime. |
| OAuth proxy managed configuration | `tests/config/managed-proxy.test.ts` reuses genuine preview and production SQLite stores and a real HTTP one-use provider with PKCE. Per-origin runtime switching covers old and bare issuance, retained/legacy profile readers, new version-2 profiles, production rejection before provider exchange, and preview retirement before state consumption. Wrong-key, tamper, malformed-version, foreign-origin and authenticated foreign-state controls preserve both stores. Original state and provider-code replay fail after successful completion; foreign users and sessions remain unchanged. |

The production OAuth account owners now use Source's nested session read with
browser-cache reads disabled. That retains physical revocation authority and
Source's actual compact-cache response cookies. The OAuth completed-response
hook renews inherited account cookies whenever an active base or chunked cache
cookie was emitted, while recognizing pending base or chunked account issuance.
The new chunk case failed before this repair because Source emitted the renewed
account JWE and native did not; the native assertion was precisely
`expect(renewedRaw).toBeDefined()`.

## Independent harness controls

`harness/managed-signers.test.ts` starts genuine Source HTTP instances and uses
their official clients. The comparator chooses exactly the declared signing key
for an issuing profile and requires its actual matching issuance receipt; there
is no retained-key search or unsigned fallback. Missing/wrong profiles, altered
HMACs and missing receipts fail. Managed social callback issuance additionally
requires the separately observed real session, user and provider account rows.

`harness/managed-account-cookie.test.ts` obtains the actual Source callback and
renewal JWEs over HTTP and separately observes physical rows. The evidence
container retains the full compact token, protected header, payload and account
row. It authenticates the JWE, declared credential version and independent
provider plaintext. Only the exact accessToken and refreshToken positions admit
randomized ciphertext, and the cookie and row bytes must match exactly. The
Source pre-update account snapshot can precede the adapter's updatedAt only
within the actual issuance/read chronology. Renewal requires the earlier actual
issuance and independently observed unchanged row. Wrong plaintext, versions,
keys, ciphertext/row relationships, receipt removal and invalid chronology fail.
Copied credential ciphertext in unrelated application claims remains literal.

The existing proxy comparison harness also exercises Source-generated managed
envelopes. It selects only the key named by the envelope's declared version,
rejects missing/wrong readers and malformed versions, and preserves writing
version differences. Unverified rejection vectors remain literal in transport:
both runtimes receive the same independently Source-encrypted wrong-key and
tamper inputs. No comparison exception, guard bypass, coverage reduction or
capability weakening is added.

## Upgrade effects and limits

Readers do not rewrite persisted values. Keep old readers until proofs expire
or rows are migrated; refreshing OAuth tokens and consuming backups naturally
write the current version. Dropping an old factor/private-JWKS key can prevent
login or signing. Bare ciphertext needs an explicit legacy key; the ordinary
`AuthConfig.secret` is not an implicit managed reader. Browser HMAC cookies and
verification JWTs use only the current key, so retained encryption readers do
not keep old signing cookies valid. A dedicated OAuth-proxy secret continues
using its existing single-secret behavior; the managed owner omits that option.

Rust deliberately requires a current key of at least 32 bytes, nonempty readers
and versions within JavaScript's safe integer range. Source warns about short
keys and accepts integer Numbers outside that range. These typed configuration
bounds are documented rather than represented as byte-for-byte initialization
parity. Arbitrary two-factor/multi-session ordering remains issue #232, and the
full account-cookie compression/chunk matrix remains issue #230. Session JWE
cache configuration is owned by #171/#349; this change has no dependency on it.

Focused validation: eight managed and existing dedicated-secret proxy owners
pass with 1,498 assertions. The full canonical `scripts/check.sh` gate and
independent review remain required before landing and closing #176.
