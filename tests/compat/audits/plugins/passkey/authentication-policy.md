# Passkey Source authentication policy with the locked typed verifier

Bounded capability: newly issued authentication ceremonies use Source's actual
per-proof UV/backup policy and current stored counter. This follows snapshot
50c1174 and callback108cd739; no callback contract, schema or store change.

## Actual pinned observations

`@better-auth/passkey`1.7.6 `dist/index.mjs:453–520` supplies only stored credential
ID/key/counter/transports to SimpleWebAuthn, sets requireUserVerification=false,
and looks up that row at verification time. It does not supply historical UV or
backup eligibility. Source's `verifyAuthenticationResponse.js:70–81` compares
clientDataJSON.origin to configured origin as a literal string. Its counter
comparison requires advancement whenever either saved or supplied counter is
positive. `parseBackupFlags.js` rejects BS=true with BE=false; valid signed BE
changes in either direction are accepted. User presence and full signature,
challenge and RP hash verification still apply.

Actual signed ES256 standalone Source probes:
`/tmp/passkey-auth-policy-oracle.log` accepts UV-absent registration/authentication,
UV-present registration followed by UV-absent authentication, BE upgrade, upgrade
with BS=true, BE downgrade, and BS transition. All invoke one real callback, create
one owner session, retain stored public device/backedUp snapshots, and reject
challenge replay. Invalid BS/BE, absent UP, wrong RP/challenge and nonincreasing
counter reject400 without callbacks/writes; bad signature rejects401. Wrong host
and same-host foreign port also reject400 in
`/tmp/passkey-auth-policy-origin-oracle.log`. The independent scripts are in
`/tmp/admin-permission-oracle/passkey-auth-policy.ts` with a real pinned runtime,
SQLite migrations, official client and ES256 proof generator.

## Exact native implementation

Both committed locks actually contain webauthn-rs/core0.5.4. The additionally
installed0.5.5 was initially inspected but is not the build's resolved dependency;
the relevant0.5.4 public APIs and restrictions were checked directly. This commit
adds direct webauthn-rs-core="=0.5.4" and activates existing webauthn-rs
`danger-credential-internals`, without changing versions. Coordinator integration
must add the existing core package to better-auth-api's dependency list in both
locks; worker Cargo-produced mechanical lock changes are excluded from the commit.

The high-level0.5.4 verifier requires UV and historical registration policy;
discoverable authentication disallows eligibility upgrade. Builder Preferred alone
still enforces a Required historical credential policy, and the backup-upgrade
flag alone rejects an upgraded backed-up proof because the check uses old BE.
The new private adapter uses the public WebauthnCore builder and typed Credential
conversion. RP/origin configuration still passes existing high-level validation.
New core origins forbid arbitrary ports/subdomains. A separate safe JsValue parse
compares original client-data origin literally, preventing URL case/default-port
normalization from relaxing Source's string contract.

At issuance, real generated core AuthenticationState is persisted server-side in
new tagged variant `core`; options retain existing Source-compatible browser hints.
At verification, the database-selected credential and originally verified owner
remain authoritative. Checked u32 conversion reads the actual current public row
counter; a disposable typed stored credential synchronizes its counter before
both verification and the genuine-result update. On a separate verifier clone,
registration_policy=Preferred, user_verified=false remove only historical UV
requirements, and backup_eligible is parsed from current original authenticatorData.
The public core AuthenticatorData parser rejects malformed input; explicit UP and
invalid BS/BE checks happen before application callbacks. ID, actual stored COSE
key, transports, and owner are never obtained from proof claims. Current state
set_allowed_credentials selects only this actual database credential. Exactly one
core.authenticate_credential call verifies the original unchanged signed bytes.
There is no private JSON state surgery, cryptographic retry or fabricated result.

The genuine AuthenticationResult still supplies callbacks, opaque credential/counter
updates, original-owner session issuance and existing public metadata preservation.
The current public counter is also synchronized on the persisted temporary typed
credential so a valid decreased counter cannot accidentally re-save stale opaque
history. Failed verification persists none of that temporary normalization.

## Primary official-client owners and failures

Seven new scenarios use real official clients/ES256 proofs. UV-absent, upgraded
backed-up and downgraded proofs each authenticate twice, checking real callback
facts, advancing counters, current session owner, consumed replay and preserved
public metadata. A foreign client's existing sessions/accounts/user remain unchanged.
Independent signed invalid BS/BE, UP, RP, wrong host/port/case origin, wrong challenge
and valid-DER bad signature reject before callbacks and cookie/session/counter
writes. Public re-login/list proves the saved credential survives all failures.
Two actual overlapping issued challenges prove a second proof with the now-current
nonincreasing counter rejects instead of trusting generation's stale snapshot.

A private fixture control updates only actual SQL public counter by exact stored
credential ID. It does not modify opaque credential, key, ID, transports or owner.
Real signed counter increase/decrease cases run between issuance/verification and
check actual public lists, callback stored-row snapshots, owner/foreign full state,
challenge consumption, session counts, and a subsequent valid counter advance.
This catches public-versus-opaque authority, beyond the overlapping ceremony owner.

`/tmp/passkey-source-policy-sdk-before.log`: old callback-capable high-level verifier
fails all5 original owners /406 assertions at genuine UV, backup state, foreign-port
or stale generation-counter boundaries. `/tmp/passkey-source-counter-sdk-before.log`:
new core before counter persistence repair passes6 and fails1 specifically at
saved counter5 instead of verified1. Both use equivalent configured real servers.
`/tmp/passkey-source-counter-oracle-final.log`: actual Source-to-Source7/828.
`/tmp/passkey-source-counter-family-final.log`: final whole passkey family24/2164.
`/tmp/passkey-source-counter-native-final.log`: existing10 distinct native contracts.
Strict API/fixture Clippy, client TypeScript and formatting pass in matching policy/
counter final logs. No extra mirror/native factory-only tests or full gate claim.

Full actual serialized verify requests and callback inputs are retained. Each
callback's complete raw assertion equals its actual submitted request locally;
clientDataJSON and registration userHandle have exact reversible byte checks.
Every decoded field, full signature token, response, canonical transport/cookie,
current session and saved state remains compared using existing identity rules.
No comparator exemptions, hashes, trace suppression or fabricated receipts.
The initial Source-self test incorrectly paired a second callback with the first
request's replay; corrected pairing matches actual full signature then asserts
complete payload equality. That setup-only failed log is excluded from behavior
proof. Initial test TypeScript unknown-state annotations were corrected without
altering retained observations.

## Compatibility and unclosed scope

Old serialized `passkey` and `discoverable` challenge variants remain decoded and
run their unchanged legacy verifier paths until normal expiry/consumption. They
retain Required UV, historical backup constraints, legacy origin policy and stale
generation counters; only newly issued `core` variants use the repaired policy.
No in-place rewrite or migration of pending challenge values is performed. This
compatibility follows unchanged old typed codecs/verification branches; a live
process-upgrade proof of old pending ceremonies is not claimed by these SDK owners.

UV-absent registration remains a separate high-level registration-verifier gap.
Callback deletion/no-row behavior remains the preceding explicit difference.
Custom public-key/transport application mutation versus opaque credential history,
arbitrary extensions/cross-origin/top-origin/client type variations, unusual RP
configurations and concurrent counter updates between the actual verification read
and write are not universally covered. Opaque library backup history may remain
eligible after a downgrade; it no longer imposes Source-absent historical policy,
while current proof facts are genuine and public stored snapshots remain unchanged.
No shared inventory/lock/schema/migration edits or broader plugin claim.
