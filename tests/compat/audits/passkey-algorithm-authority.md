# Raw Ed25519 algorithm authority

Pinned Better Auth 1.7.6 / SimpleWebAuthn 13.3.3 admits an OKP key declaring
kty 1, alg -7 and curve 6. Both none registration and packed self-attestation
with a genuine Ed25519 signature succeed; genuine authentication also succeeds.
The pinned `verifyOKP` recognizes the algorithm but chooses Ed25519 from the
curve and imports the real x bytes. The declared -7 tag does not select ES256.
Native Core rejects that pairing before it can construct a typed credential.

Fresh registration states select a bounded raw verifier before Core for exactly
this pairing. The existing curve8 none branch remains intact. Protocol checks
reuse the measured Source CBOR decoder and original ceremony challenge, RP and
current resolved origin. Packed signatures verify original authData concatenated
with the SHA256 of original clientDataJSON, with the real stored Ed25519 x bytes.
No attestation or COSE bytes are changed, and no typed credential is fabricated.
Certificate attestations continue through Core. This capability covers packed
self-attestation algorithm -7 and -8, not every recognized statement algorithm.

The hidden raw codec retains its historical sourceRawNone discriminator so
previous raw rows stay readable; its Rust variant now names raw key storage.
It retains original credential ID, COSE bytes (including algorithm and curve),
AAGUID, transports, counter and backup state. Public row shapes do not change.
New authentication states retain the actual issued challenge separately from
unchanged Core state. Historical states still use their prior Core verifier;
raw authentication is available only under the newly issued raw-capable state.
Raw assertions verify exact stored ID, declared key tags, client ceremony type,
challenge, literal current origin, RP hash, presence, backup flags, current public
counter and original signature bytes before callbacks, counter or session writes.
Curve8 remains unusable for authentication. There is no failed-Core fallback.

The application authentication result is now an explicit Core/Raw authority enum.
Common credential ID/counter/UV/backup accessors remain available. Callers that
need dependency-specific fields must match Core to access the real Core result.
Raw facts can only be constructed inside the passkey verifier. They are not
serialized into a fabricated dependency AuthenticationResult. The common handler
keeps the verified persisted owner through application callbacks and uses the
same counter/session transaction flow. Existing historical typed decoding tests
now inspect the real stored codec directly after removal of a test-only parsing
wrapper.

Seven primary official-client owners cover none/packed with mismatch and ordinary
Ed25519/ES256 controls, including both -7 and -8 packed statement algorithms. They retain all shared SQL passkey columns, complete
registration and authentication callback inputs/facts, actual session receipts,
full transports and reversible original proofs. Registration controls exercise
actual foreign authenticated owner, RP, origin, challenge and packed genuine
wrong/short signatures. Assertions exercise RP, origin, challenge, wrong/short
signatures, equal/stale counters, two genuine counter advances, body foreign-owner
claims and challenge replay. Every rejection preserves whole owner/foreign rows
and user/account/session state and never invokes the authentication callback.
Every success resolves the original stored owner and advances only the counter
in the common public row. Signature control counter 26 avoids unrelated stale
counter rejection. Callback observes counter25/26 before writes and no sessions
or outstanding challenges. No comparator, allowlist, proof exemption or required
coverage is weakened; inventory requirements only add these owners.

Validation evidence (local logs): Source-self six owners / 4668 assertions in
`/tmp/issue214-source-self.log`; differential six / 4668 in
`/tmp/issue214-after.log`. Frozen root baseline plus private JSON charset alignment
has four passing typed siblings and two failing mismatched owners in
`/tmp/issue214-before-final.log`: none genuine admission wrongly returns500;
packed invalid-signature returns500 before reaching Ed25519 verification instead
of Source400. `/tmp/issue214-before-admission.log` omits only the two packed
signature-negative variants temporarily to independently reach genuine packed
admission: both mismatch owners wrongly return500; all four typed siblings pass.
The full final owner is restored. Initial cookie observation setup logs are not
behavioral evidence: Cookie.toJSON adds a local creation timestamp; final
observations retain wire facts and RFC Max-Age precedence as the existing trace
owner does. Full raw HTTP traces remain unchanged.

Other recognized algorithm tags, exotic normalized COSE encodings, certificate
attestations, arbitrary CBOR nesting, duplicate credential admission, trusted
publicKey-only application mutation and historical-state migration semantics
remain outside this measured pairing. Existing audits retain their limits.

Final Source-self seven owners / 5518 assertions pass in
`/tmp/issue214-source-self-final.log`. The existing Native hidden-SQL owner now
also enrolls a genuine mismatched Ed25519 key and authenticates with its real
signature, proving raw ID/key/owner identity and raw discriminator survive the
counter update. It guards Native-only columns unavailable to the SDK observer;
no duplicate SDK admission owner or fabricated Core result is added. Native12/12
pass in `/tmp/issue214-native-tests-final.log`. The initial native scaffold placed
its cookie in the helper query argument and rejected400 before verification;
that setup failure was corrected with the actual request Cookie header.
Production API-lib and fixture strict Clippy, fixture locked build, TypeScript,
format and diff checks pass. The coordinator independently reviewed protocol,
stored-owner authorization and honest Core/Raw authority without finding a
blocker. Canonical devenv gate is queued behind the other passkey issue gate.
