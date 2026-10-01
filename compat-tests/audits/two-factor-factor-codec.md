# Factor-secret and default backup persistence interoperability

Published Better Auth 1.7.6 stores factor secrets and default backup-code JSON
with `symmetricEncrypt`: SHA-256(secret), XChaCha20-Poly1305, a managed 24-byte
nonce preceding authenticated ciphertext/tag, and hexadecimal encoding. The
previous Rust owner wrote AES-256-GCM with HKDF and base64url. Its own reader
could consume its writes, but the published reader could not consume those
actual persisted rows, and Rust could not import published factor ciphertext.

All new factor-secret and default-backup writes now delegate to the existing
shared `token_crypto` writer. Reads try that authenticated encoding and retain
the previous authenticated AES/HKDF reader for installed Rust data. Both
readers authenticate with the configured secret. Failed authentication never
returns plaintext. No legacy writer, public AES option, schema change, extra
write, migration, dependency, or password-algorithm change was introduced.
Installed legacy secret bytes remain unchanged while backup consumption writes
only the replacement backup field in the new encoding, using the existing
exact-row-ID ciphertext CAS and replay handling.

The owning SDK case reads actual SQLite ciphertext after public enrollment and
regeneration and independently decrypts it with published `symmetricDecrypt`.
It verifies unchanged factor ID and secret across regeneration. An ephemeral
published auth handler and SQLite database produce a real enrolled factor;
its exact ciphertext is imported into the existing test owner's row through a
bounded trusted control, then real public TOTP and backup verification succeed.
Wrong-owner backup verification and replay leave the relevant actual rows
unchanged. No fake encryption receipt or copied producer generates expectations.
The imported published account is separate from the tested account; the control
preserves the tested factor ID/user binding and updates only its two ciphertext
fields. The control exists only in excluded compatibility fixtures, uses bound
SQL parameters or the existing exact-ID store operation, and adds no production
route or serialization exposure.

A native installed-row case uses fixed independently generated WebCrypto
HKDF/AES-GCM vectors for the old format. Those exact vectors first passed the
unchanged old production reader and actual public server-only backup view,
TOTP URI/verification, backup consumption, and replay paths. After the repair,
the same path passes, preserves legacy secret bytes and factor/session owner,
and writes consumed backups in the new encoding. Corrupting an authenticated
legacy secret fails the real route without changing stored backups/session.
Its distinct responsibility is installed Rust compatibility; it does not
repeat the cross-runtime new-write protocol owner.

Meaningful before proof:

- `/tmp/two-factor-factor-codec-sdk-crypto-before.log`: source completes the
  owner case, Rust fails published decryption of its actual AES/base64 row;
  43 sibling scenarios pass. Earlier byte-format failure is also retained in
  `/tmp/two-factor-factor-codec-sdk-before.log`.
- `/tmp/two-factor-factor-codec-native-legacy-before.log`: exact installed-row
  vectors pass the old production route before its writer changes. Vector
  producer/provenance: `/tmp/two-factor-legacy-aes-vectors.ts` and `.log`.

Final focused proof:

- 44 two-factor SDK scenarios / 1,988 assertions pass in
  `/tmp/two-factor-factor-codec-sdk-after.log`.
- 15 native two-factor tests pass in
  `/tmp/two-factor-factor-codec-native-after.log`.
- Client TypeScript and workspace library Clippy (`-D warnings`) pass in
  `/tmp/two-factor-factor-codec-typecheck-final.log` and
  `/tmp/two-factor-factor-codec-clippy-final.log`.
- Workspace and excluded Rust-server formatting and `git diff --check` pass.

Base is combined OTP/passwordless freeze `a2b22e8`. No config generation,
plain/custom backup storage, pending disableSession policy, corruption-error
wire mapping, managed secret-key rotation, date/extreme inputs, comparator,
skips, inventory, coverage, lock, or full canonical gate changes are claimed.
Backup configuration and pending disableSession remain the next separate
capability. The existing OTP <=0 guard matches actual pinned rejection, but
its empty-500 response mapping remains a separately measured bounded follow-up
(`/tmp/two-factor-otp-zero-oracle.ts/.log`). Coordinator independent review is
requested; the skill's external autoreview command is unavailable here.
