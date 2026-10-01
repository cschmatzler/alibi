# Authenticated OAuth proxy profile evidence

This support-only capability recognizes an explicit, complete observation:

```
oauthProxyProfile: { token, payload }
```

`token` is the exact profile ciphertext delivered in the actual forwarding URL.
`payload` is the entire `JSON.parse(await symmetricDecrypt(...))` result using
the published Better Auth 1.7.6 helper. The scenario supplies its dedicated
fixture secret through the optional fifth `compatScenario` comparison options:
`{oauthProxyProfileSecret: "local-fixture-dedicated-oauth-proxy-secret-32"}`.
Other scenarios receive no proxy secret implicitly. There is no environment
lookup or raw profile-string entropy exception.

The comparator independently authenticates canonical bare hex with the pinned
transitive `@noble/ciphers/chacha.js` XChaCha20-Poly1305 implementation, using the
published SHA256(secret) key, leading 24-byte nonce and trailing 16-byte tag.
Fatal UTF-8 decoding, canonical producer JSON bytes and an exact recursive full
payload copy are required. In particular undefined/nonfinite invented copies
cannot hide behind `JSON.stringify` omission/null conversion. The complete raw
ciphertext retains the existing token bijection, including repeats and rotation.
Managed `$ba$` versioned-secret envelopes and secret rotation are not claimed.
No dependency versions or lockfile entries change.

Authenticated ciphertext is evidence of the complete submitted JSON, not
successful endpoint admission. Actual Source negative inputs `{}`, expired
(timestamp-61000), future (timestamp+11000), and mismatched provider selectors
remain complete comparable rejection evidence. The primary SDK owner separately
asserts actual errors and unchanged persisted state. Only the root numeric
payload timestamp uses the existing relative 1500ms execution-clock allowance;
it does not require that deliberately invalid input fall within the scenario
window. Missing/null/wrong-type timestamps remain literal. Positive producer
clock admission belongs to the owning scenario's actual lifecycle assertions.

Every payload claim is compared. `userInfo` and provider `profile` JSON compare
wholly literally, including their application IDs, tokens and nested arrays.
Other claims reuse the existing state/owner/token/date graph, URL semantics,
literal provider/configuration values and field-presence checks. The producer's
provider-account-to-userInfo-ID relation must agree across observations, including
matching invalid inputs. No schema strips unknown properties.

## Exact callback link

Only the configured local server's exact default or private profile auth paths
ending `/callback/{provider}/oauth-proxy` or the inventoried deprecated
`/oauth-proxy-callback` may relate query `profile` to already authenticated
observed tokens. A malformed/unknown cipher compares literally. The complete
path, provider selector, URL credentials, all duplicate query values, callback
selectors and fragment remain checked. If both authenticated payloads supply a
provider on the provider-specific route, the provider/route match relation must
agree; two genuine provider-mismatch rejection inputs are retained. No provider
selector is invented for the deprecated route. Substituting another observed
valid cipher is detected by the same token identity/rotation graph.

Atoms inside application data, metadata, additional fields and transport shape
observations remain literal. Arbitrary objects named `profile`, unrelated URL
paths and foreign origins do not gain this handling. This is explicit trusted
fixture evidence, not a general inference of successful authentication from a
random encrypted string or application object.

## Meaningful proof

The original real Source-to-Source full OAuth lifecycle driver fails only at
forwarded `location.query.profile.0` in
`/tmp/oauth-proxy-profile-source-self-before.log`. The official paired Source
owners additionally retain the complete atom and fail only on ciphertext and
its numeric timestamp in `/tmp/oauth-proxy-sdk-source-before-atom.log`; all local
endpoint/state assertions pass. The comparator baseline with the new harness
also fails precisely those two fields in
`/tmp/oauth-proxy-comparison-harness-meaningful-before.log`.

Two fresh complete public Source OAuth lifecycles, including real provider HTTP
and original full forwarded URLs/public decrypted payloads, pass the supported
comparison in `/tmp/oauth-proxy-comparison-source-driver-final.log`. Four primary
harness owners independently protect published encryption/decryption and secret
admission; literal provider JSON/claims/ordered arrays/expiry/state/URL selectors;
byte/copy/tamper/key/rotation/application-shape integrity; and complete matching
malformed/expired/future/provider-mismatch rejection inputs. Signed semantic
mutations and authenticated payload copies cannot pass solely on ciphertext
shape. No production export, pause hook or fake authentication response is used.
The Source application fixture and public endpoint assertions remain owned by
the OAuth proxy capability author.

Final focused results are recorded after final checks below. The earlier root
relative-path setup command and absent reference dependencies remain nonpassing
setup artifacts. Only ignored local dependency installation/linking was needed;
no source factory, inventory, comparison allowlist, date tolerance, coverage rule,
lock or full gate changes belong to this support capability. External test-audit
autoreview commands are unavailable; coordinator independent review and the full
canonical integration gate remain required.

Final: all 51 harness tests / 564 assertions pass in
`/tmp/oauth-proxy-comparison-harness-final-v2.log` (four new owners / 73
assertions). Client TypeScript passes in
`/tmp/oauth-proxy-comparison-typecheck-final-v2.log`. The final fresh complete
Source lifecycle driver passes in
`/tmp/oauth-proxy-comparison-source-driver-final-v2.log`. Formatting/diff checks
pass. Compact-cache support remains a separate frozen dependency, carried here
as 346ca00f (equivalent to 42c436f0), for coordinator deduplication.
