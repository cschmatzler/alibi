# Encrypted OAuth persistence — Better Auth 1.7.6

The reference is the pinned published `crypto/index.mjs`, `oauth2/utils.mjs`
and `api/routes/account.mjs`, exercised through the official client, actual
local GitLab token/profile HTTP handlers, both databases and the published
`symmetricEncrypt` / `symmetricDecrypt` functions.

## Implemented contract

When `AccountConfig::encrypt_oauth_tokens` is enabled, truthy access and refresh
tokens are stored as lowercase hexadecimal containing a 24-byte managed nonce
and XChaCha20-Poly1305 ciphertext/tag under SHA-256(secret). Provider ID tokens
remain plaintext in storage and responses. Empty values are retained rather
than encrypted. The common writer serves social OAuth and One Tap; there is no
provider-specific alternative ID-token encryption option.

Reads follow the published ciphertext heuristic: even-length ASCII hexadecimal
is authenticated, nonhexadecimal and odd-length hexadecimal pass through as
plaintext, and an empty token remains empty. Wrong keys, altered authenticated
ciphertext and undersized hexadecimal fail with the exact access-token or
refresh-token 400 code. A still-valid access read does not decrypt an unused
refresh token. Provider/persistence failures are caught at the published stage.
Ownership and account selection precede token decryption; guest token operations
retain the separately reviewed empty 401 behavior and foreign rows cannot be
read or refreshed. ID tokens are never decrypted by these handlers.

## Primary evidence and controls

Two official-client owners cover genuine encrypted login, published decoding of
actual persisted native and Source ciphertext, access reads, refresh rotation,
retained original account identity/scopes/creation time, replay, guest requests,
foreign account rejection and complete unchanged foreign state. Eight real row
imports exercise published ciphertext, uppercase, empty, ordinary plaintext,
odd hexadecimal, corruption, the wrong secret and short even hexadecimal.
A corrupt refresh token stays unused on a valid access read and fails on refresh
without changing any account, user, session or provider receipt.

Both runtime executions import the same ciphertext produced by the published
crypto function. Every original row column remains observed. Random ciphertext
is retained reversibly in an evidence container with its actual byte length and
case, then uses the existing token identity/rotation graph. Independent published
authenticated decryption establishes the format; a self round-trip cannot satisfy
that assertion. No comparator, tolerance or exception list changed.

The original native writer fails these same owners: it encrypts the ID token and
writes incompatible AES/base64. After repairing only ID storage, the owner still
fails the hexadecimal format and published ciphertext import. Logs:
`/tmp/oauth-token-persistence-meaningful-before.log` and
`/tmp/oauth-token-persistence-cipher-meaningful-before.log`.

Source-self and differential final runs each pass 2 scenarios / 306 assertions:
`/tmp/oauth-token-persistence-source-self-final-v2.log` and
`/tmp/oauth-token-persistence-differential-final-v2.log`.
The centrally rebased current-source OAuth, One Tap and account family passes
47 / 3,364: `/tmp/oauth-token-persistence-reviewed-family-current-source.log`.
An earlier family run used a stale Source fixture missing the already-reviewed
fractional account timestamp control and failed that owner (46 pass / 1 fail);
`/tmp/oauth-token-persistence-reviewed-family.log` is retained as a setup failure.

The actual 23 new evidence requirements are drawn from passing records for the
four routes these owners exercise. No existing requirement was removed.
Strict API Clippy, fixture build, client TypeScript, Rust formatting and diff
checks pass. Independent Phone review clears the measured fresh-row Source
interoperability and identifies the installed-row boundary below. The canonical
combined gate remains pending for this capability.

## Explicit installation and integration boundaries

The previous native OAuth writer used HKDF-SHA256 / AES-256-GCM and standard
base64, and also encrypted ID tokens. Its installed rows are incompatible with
this pinned format. They require explicit conversion under the original secret
or provider reauthorization before upgrading. The Source plaintext heuristic
cannot distinguish those old base64 strings from genuine provider plaintext:
this patch neither migrates them nor claims safe automatic upgrades. No live
authentication fallback to the old native algorithm is introduced. A one-way
conversion is being investigated separately with concurrency and row ownership
requirements. This limitation applies to old native encrypted OAuth data, not
existing pinned Source ciphertext.

Managed `$ba$` secret-version envelopes, secret rotation, arbitrary malformed
provider token responses (including empty refreshed ID/refresh token fallback),
automatic expiry refresh extremes, trusted server-only account ownership and
account-info guest behavior are not proved by this slice. Cookie-cache,
stateless/secondary-storage and custom adapter combinations remain separate.
The public configuration default is still encryption disabled; existing default
OAuth and One Tap owners remain in the connected family.
