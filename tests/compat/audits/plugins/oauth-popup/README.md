# OAuth popup: issue #132

Production implements the published Better Auth **1.7.6** popup protocol. The
private restored npm release supplies `plugins/oauth-popup/{index,client,constants}`;
module/tarball hashes and inode link counts are in [receipt.json](receipt.json).
No published files, comparator, exception list, account-cookie flow, OAuth proxy,
or state codec were changed. The shared OAuth edit only widens the existing start
handler's module visibility so the GET route reuses actual state issuance.

`OAuthPopupPlugin` validates the resolved request configuration's trusted origins
and all three redirects, signs a 600-second opener origin/nonce marker, and uses
existing ten-minute OAuth storage. Callback delivery keeps actual state/account/
session handling and original response headers, including Location and the
bearer token/exposure headers. Its inert JSON escapes `<`, U+2028 and U+2029;
the exact published script has CSP hash
`sha256-tIo2K8VBC9SnhvdZ+9GsGkQoZm+jm/JcxL+d+i8b8KQ=`. Recipient, nonce, signed
session-cookie token, redirect and provider error remain actual callback values.

## Focused proof

One primary HTTP/Chromium owner runs with the actual SQLx and SeaORM stores:
**one scenario / 232 assertions per adapter**, including each real Source run.
The native fixture uses the exported Rust plugin and public AuthBuilder/store
interfaces; it does not replace authentication or session persistence with mocks.
The local HTTP provider validates PKCE, exact redirect URI and one-use grants.
The published generic OAuth provider is installed on Source; its configured local
provider follows the shared Rust provider/callback path on Rust.

The owner protects genuine trust refusals, unknown providers, three redirect
refusals with hostile nonce/HTML strings, exact completion HTML/script/CSP,
reserved additional state fields, signed marker attributes, ten-minute stored
state, actual account/user/session ownership, foreign unauthenticated clients,
signed bearer lookup, consumed-state replay with and without the original marker,
expired stored state, tampered state and marker, and escaped provider error
completion. Marker tampering leaves a valid ordinary callback and session creation
in effect; it does **not** impose a new authentication or replay ledger.

Actual Chromium runs the official popup client. Its sandbox blocks `window.open`;
a real popup is closed while the provider awaits approval; real cross-origin and
wrong-nonce messages are rejected until timeout. A real cross-origin embedded app
completes generic-provider popup sign-in, stores the signed token, sends the bearer
header, reads the correct session and clears storage on sign-out. Abandoned flows
retain their pending OAuth state, matching Source.

The source/Rust raw pairs retain response bodies/headers, provider receipts and
all observed core user/account/session/verification rows. Independent assertions
bind random state IDs, verifier/challenge, signed marker, returned token and
physical session ownership. Deterministic app-origin error HTML/payloads and the
traced real endpoint response compare directly through the unchanged comparator.
Random token/ID/clock bytes and complete database dumps remain in the raw pairs;
they are not asserted byte-equal across independent processes. No comparator
paths or fields are masked, excluded or relaxed.

Self-review found and fixed discarded callback Location/bearer headers. Actual
pre-fix raw responses under `/tmp/popup132-evidence/sqlx` lack those headers;
Source emitted them. The retained final owner asserts both headers against the
actual completion payload. Authorization/data-exfil review traced trust checks,
state admission, exact opener delivery, fixed provider destinations and physical
session ownership; no unresolved finding remains in the changed paths.

Focused API strict Clippy, client/reference type checks, formatting/lint and
`git diff --check` pass. GitHub Actions is disabled (`enabled=false`), and the PR
has no hosted checks. No full compatibility/devenv-test/coverage/browser suite,
mutation campaign or unrelated provider replay was run.

## Rebase and bounds

Frozen proof used base `9220de08` and head
`e84ee2f8c42bfc77306df4a2b88f658c577210e5`. Rebase onto `27424d9f` (#397)
resolved only the fixture router merge chain, retaining both cookie proxy and
popup registrations. The popup production, fixture and owner files are byte-identical
before/after rebase; the invariance diff is empty. Main only widened cookie-state
helper visibility and changed proxy paths outside this database-state popup proof.
A second rebase onto `45646568` includes #395 account-cookie compression/chunks
and #399 configured legacy-token conversion. It retained both public plugin
exports at their shared insertion point. Account cookies are disabled in this
popup fixture; conversion is a separate configured path. The final popup
invariance diff is again empty, and both fixture registrations and exports were
reviewed against current main.

The retained range/registration diffs were reviewed; no rebuild or adapter replay
was performed for the integration-only rebase or these documentation changes.

This is scoped popup acceptance, not full Better Auth compatibility. Proof uses
one local non-OIDC provider, database OAuth state, normal and embedded Chromium,
and the official generic provider composition. It does not establish every live
provider, browser, cookie/stateless/managed-key configuration, OIDC discovery or
ID-token nonce option; those remain their existing owners, including #188.
The completion hook recognizes `/callback/` and `/oauth2/callback/`; the official
popup/generic flow exercised here uses `/callback/local`.


Reproduce this owner with the existing selected-path runner (one adapter at a
time, with the matching `BETTER_AUTH_COMPAT_BACKEND=sqlx` or `seaorm`):

```sh
devenv shell -- env BETTER_AUTH_COMPAT_BACKEND=sqlx   CARGO_TARGET_DIR=/tmp/popup-owner-target   bash tests/compat/client-tests/run-against-both.sh   tests/plugins/oauth-popup/popup.test.ts
```

The retained runs instead launched the built adapter artifacts on owned ports
41310/41320 and invoked only this Bun owner. Chromium was the Nix-provided browser;
no other browser scenario was selected. Interactive T3 preview was opened first,
but localhost/environment-port navigation returned browser-client failures. The
automated owner still ran genuine Chromium, with the official client bundled
from the restored pinned package. The failed preview is not claimed as browser
proof.

Nonempty unified/range diffs are stored as lossless `.gz` records because their
blank context lines contain significant diff-format whitespace. Original raw
SHA-256 digests are in the receipt; empty invariance diffs stay uncompressed.
