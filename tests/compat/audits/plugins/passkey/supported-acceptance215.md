# Remaining supported passkey acceptance (#215)

The oracle is the published `@better-auth/passkey` 1.7.6 with
`@simplewebauthn/server` 13.3.3. Published package bytes and existing raw
comparison/exclusions remain unchanged. No new supported attestation format is
invented. Published X.509 Ed25519/PSS certificate-key conversions remain
unsupported; the Ed25519 U2F proof uses an EC attestation certificate. The six certificate formats exercised are packed, FIDO U2F,
Android Key, Apple, TPM and Android SafetyNet. The existing none/self-attestation,
ES256/Ed25519, stage-specific Ed448, algorithm and callback receipts remain
applicable.

New ceremonies opt into a localized, licensed extension of the locked 0.5.4
verifier. Original client JSON and authenticator bytes remain signature inputs.
RP ID, origin, signatures, certificate chains, configured roots, revocation and
SafetyNet CTS checks still establish authority. Source ignores crossOrigin and
extension policy values; native now does so without removing signed bytes.
Registration still requires user presence and uses the actual configured UV
policy. The advertised algorithm list remains the published default, while
Source-supported verification selectors and COSE representations are admitted.
Source malformed/noncanonical map rejection was probed before implementation.

The pinned package's default roots are included with MIT attribution. Test
certificate authorities are explicitly configured in both runtimes; these
fixtures prove validation and rejection, not manufacturer-issued credentials.
The MPL-2.0 upstream extension keeps attribution and license files. The wrapper
source is unchanged. Distinct package names and path dependencies ensure
consumers receive the same credential types, rather than relying on a
non-transitive root Cargo patch. Historical pending state remains readable with
its prior verification policy; the filtered native pending-policy test passed.
Upstream 0.5.4's TPM hash helper rejected every algorithm, so retaining that
legacy rejection does not remove a previously successful ceremony.

`acceptance215.test.ts` owns eleven differential scenarios. Genuine signatures
cover each certificate format, UV-absent enrollment, extensions/crossOrigin,
wrong owner/RP/origin/root/signature, relevant nonce/AAGUID/CTS/time checks,
challenge cookie configuration, denial/fresh retry/replay, enrollment session
creation, authentication counter advancement and full returned fields. Other
owners cover real revoked certificates; schema/name/transport behavior;
SafetyNet signed payload coercion; short RSA exponents with RS384, Ed25519 U2F,
Apple's Source nonce representation and TPM's signed SHA384 name digest.

The publicKey-only owner changes only the persisted public key after challenge
issuance. The old key must fail without counter/session writes; a fresh genuine
assertion signed by the replacement key succeeds. Hidden credential JSON no
longer overrides the current public key. Schema failures preserve the issued
challenge, including omitted registration response (400 VALIDATION_ERROR),
while explicit null retains the separate cryptographic failure path. A real
signed retry of the exact schema-retained registration challenge succeeds.
Transport conversion follows Source's callback-before-join ordering; null,
missing and empty arrays persist the empty string, and legacy conversion is
unchanged.

Existing primary owners are reused, not replayed: registration callbacks for
sessionless resolveUser, callback overrides/errors, name precedence and owner
binding; ceremony lifecycle for expiry/concurrency; authentication callbacks
and algorithm authority; and merged #390 for tokenBinding. See
[registration callbacks](registration-callbacks.md),
[registration policy](registration-policy.md),
[ceremony lifecycle](ceremony-lifecycle.md),
[authentication callbacks](authentication-callback.md),
[authentication policy](authentication-policy.md),
[algorithm authority](algorithm-authority.md) and
[raw-none admission](raw-none-admission.md).

## Physical before and after receipts

[evidence215/before.json](evidence215/before.json) preserves complete bounded
HTTP responses, signed proofs, cookies and physical state against original
production `dfd88d21` on both actual adapters. Real Source certificate enrollment
succeeds where both baselines reject without writes. PublicKey-only replacement
rejects the old key in Source whereas both baselines accept it and write a
counter/session. Real RSA short-exponent, Ed25519 U2F, opaque Apple nonce and TPM
SHA384-name proofs succeed in Source and fail on both baselines; P384 U2F is an
unchanged successful control. Only a controlled fixture route updates the
baseline public key; baseline production was unchanged.

The after artifact retains bounded full original inputs/responses and physical
snapshots from both adapters, including denied signature, publicKey replacement
and the corrected omitted-response schema observation. Full differential
observations and logs are retained in `/tmp/close215-evidence`.

## Validation

Final adapter counts and artifact hashes are recorded alongside the receipts.
Fixture selection is genuine: the default fixture build dispatches auth through
`SqlxStore`; `--features seaorm` dispatches through `SeaOrmStore`. Controlled
fixture inspection uses the existing SQLite interface and does not replace the
production store. Builds use the locked dependency graph and two build jobs.
Scoped API/SQLx/SeaORM library Clippy and client typecheck passed. Independent
bounded production/security review qualified each production checkpoint and
its deltas. Actions are disabled. The user's explicit closure instruction
supersedes the issue's older canonical gate request: no full suite, inventory
sweep or canonical coverage gate was run.

Production checkpoint `675c8b13c35c3eb51adc794e73911ee0486aac0d` completes the
qualified changes on main `0b164296`. SQLx has ten passing owners from
`acceptance-qualified-sqlx.log` and the affected owner's passing final retry in
`acceptance-qualified-transport-sqlx.log` (110 assertions). The passing owners
were not repeated for the unrelated PostgreSQL update. SeaORM's final run has
11 passes, zero failures and 1,486 assertions in
`acceptance-qualified-seaorm.log`. [validation.json](evidence215/validation.json)
records exact build artifact hashes and log hashes.
[after.json](evidence215/after.json) identifies each observation's checkpoint.
[transport-options-before.json](evidence215/transport-options-before.json)
retains the full failing options exchange; its raw comparison failure is also
preserved. [published-integrity.json](evidence215/published-integrity.json)
records fresh published-byte comparisons for all 434 files. Bun dependency
files were not mutated, so shared hardlinked package bytes remain pristine.
