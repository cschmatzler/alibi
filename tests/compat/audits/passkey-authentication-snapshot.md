# Passkey authentication counter and public registration snapshots

Pinned Better Auth 1.7.6 `@better-auth/passkey/dist/index.mjs` verifies the signed
assertion, optionally awaits `authentication.afterVerification`, then updates
only `counter`. Registration-time public `deviceType` and `backedUp` remain
unchanged. The Rust verifier's opaque credential still needs its real verified
counter and backup state for subsequent ceremonies; those internal facts must
not replace the source's public snapshots.

This bounded prerequisite changes only the passkey authentication handler's
existing `UpdatePasskeyAuthentication` input: verified opaque credential/counter
remain updated, while public device/backed values come from the actual stored
passkey. There is no new store contract, schema, policy or crypto exemption.

The existing ES256 software authenticator accepts optional BE/BS flags and signs
the resulting complete authenticator data. Its defaults are unchanged. The
actual official-client owner registers an eligible, initially unbacked credential,
signs two backed assertions, verifies both counter increments and real owner
sessions, and reads complete public passkeys and persisted owner/session/account
state. Public snapshots remain multiDevice/false. A foreign user's complete
persisted state and session remain unchanged. The second real signature also
proves the opaque credential remains usable after the first update.

The actual pinned callback oracle `/tmp/passkey-auth-callback-oracle.log` confirms
callback ordering and consumption separately. `/tmp/passkey-auth-flags-oracle.log`
proves the source exposes newly verified BE/BS facts to the callback while
persisting only counter. The primary unchanged Rust failure is
`/tmp/passkey-auth-snapshot-backup-before.log`: the public read wrongly reports
backedUp true after a successfully verified assertion. The same official-client
owner passes source-to-source in `/tmp/passkey-auth-snapshot-oracle-final.log`.

An earlier signed false-to-true BE assertion succeeded upstream but failed Rust
verification before metadata was reached (`/tmp/passkey-auth-snapshot-before.log`).
The pinned library's discoverable authentication disallows an eligibility upgrade.
That measured verifier-policy gap remains explicit; this prerequisite instead
uses initial BE true with a BS false-to-true transition accepted by both verifiers.
No cryptographic check was relaxed to hide the separate gap. UV policies,
authentication extensions, cookie encoding and callback support remain their
separate capability owners.

Final focused evidence:

* `/tmp/passkey-auth-snapshot-family-final.log`: 11 official-client scenarios,
  900 assertions, all pass. Actual complete responses and transport traces stay
  under the unchanged strict comparator.
* `/tmp/passkey-auth-snapshot-oracle-final.log`: genuine source/source snapshot
  owner passes 46 assertions.
* `/tmp/passkey-auth-snapshot-native.log`: existing 10 native passkey owners pass.
* `/tmp/passkey-auth-snapshot-typecheck.log`: TypeScript passes.
* `/tmp/passkey-auth-snapshot-clippy.log` and
  `/tmp/passkey-auth-snapshot-fixture-clippy.log`: strict API and fixture Clippy
  pass.
* Before/current-tree final binaries were built and copied independently;
  `/tmp/passkey-auth-build-baseline.log` and
  `/tmp/passkey-auth-snapshot-build-final.log` preserve provenance.

Coordinator owns inventory, integration, locks and full gates.
