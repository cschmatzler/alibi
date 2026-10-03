# Two-factor passwordless credential policy

Published Better Auth 1.7.6 `utils/password.mjs` defines `shouldRequirePassword`
from the configured allowance and the truthiness of the credential account's
stored password. The two-factor parent option controls enable/disable;
`totpOptions.allowPasswordless` and `backupCodeOptions.allowPasswordless` use
nullish inheritance from the parent, preserving an explicit false override.
Endpoint schemas make passwords optional from configuration before checking
the authenticated user's credential state. Null remains an invalid string.

This API exposes the equivalent global bool and optional child bools. The four
password-bearing DTOs use Option<String> after the route schema validates them.
The approved crate-private `parse_body_with_fields` accepts the bounded,
immutable route-specific schema; existing `parse_body` delegates its unchanged
FIELDS to it. The shared safe JsValue decoder retains exact undefined/null/type
errors and does not round-trip arbitrary JSON through ordinary Value decoding.

Passwordless social-only users, and users retaining an empty-hash credential
row, can omit a password. A supplied wrong or overlong password is ignored only
in that no-truthy-hash branch. Mixed social/credential owners with a nonempty
hash still require and verify the actual password. Required verification also
uses the existing EmailPasswordConfig maximum in UTF-16 units and its actual
configured native hasher, preserving the password utility's maximum check.
No new core configuration, store, schema, migration or public callback seam is
introduced. Custom-store query side-effect ordering is not claimed in this
bounded credential classification implementation.

Four official-client scenarios own real lifecycle and SQLite state:

- A social-only account completes TOTP enrollment with no password and a real
  generated code. URI retrieval ignores a supplied overlong password, backup
  regeneration retires old codes, and a separately authenticated factor owner
  cannot consume the regenerated owner code. The owner consumes it, disables
  without a password, rotates the browser token and leaves one persisted owner
  session with no factor row.
- Mixed social/credential accounts reject missing, wrong and overlong passwords
  before any factor or session mutation. A real correct password enrolls and
  establishes TOTP; subsequent missing-password URI/regeneration and empty-
  password disable all fail while the established owner state remains unchanged.
- Explicit false children under a true parent retain required schemas and cannot
  authenticate a now-social-only owner with an obsolete password. Explicit true
  children under a false parent permit real URI and backup operations while
  disable still requires its schema and a genuine credential password. Explicit
  null returns the exact validation error before mutation.
- A retained credential row with an empty hash and a separate social account
  demonstrates hash truthiness rather than account presence. Explicit null is
  rejected with no factor creation, a supplied wrong password is ignored for
  enrollment and disable, and a real TOTP transition establishes the owner.

Fixtures reuse the preceding policy family's real isolated profile construction.
Existing controls add a genuine social account and remove the credential row.
A bounded additional control writes an installed empty credential hash and
reads actual provider/owner/hash-presence state. It does not supply passwordless
classification or fabricate callback success. Public response fields and error
objects remain in observations; only dynamic TOTP URIs and individual backup
strings receive the same local redaction pattern as existing factor scenarios,
after exact URI preservation and real code consumption assertions.

The SDK cases fail against the pre-fix owner after the pinned TS phase succeeds:
social-only enable returns Rust400 missing password, mixed missing passwords
produce the wrong error, and explicit null/child schema behavior diverges.
Evidence: `/tmp/two-factor-passwordless-before.log`. The four repaired cases
pass /152 assertions (`/tmp/two-factor-passwordless-sdk-corrected.log`). All
22 two-factor sibling scenarios /782 assertions pass
(`/tmp/two-factor-passwordless-sdk-family-final.log`).

One native actual-route test independently owns the Rust custom hasher interface
and configured maximum. A prefixing provider delegates to real pinned Scrypt,
so substituting the default verifier rejects the valid password. It receives
the actual persisted hash and original passwords, rejects a valid-length wrong
password, and receives no call for a UTF-16-overlong password under a configured
maximum. The factor and current token remain untouched by those denials. It
fails against the exact frozen234eccc owner with Invalid password at correct
enrollment (`/tmp/two-factor-passwordless-native-provider-before.log`), and
passes after (`/tmp/two-factor-passwordless-native-provider-after.log`). This
native callback boundary is distinct from the built-in-provider SDK proof.

Ten native API tests pass (`/tmp/two-factor-passwordless-native-final.log`),
TypeScript passes (`/tmp/two-factor-passwordless-typecheck-final.log`), and
workspace library Clippy with seaorm, formatting and diff checks pass.

Wider account schema follow-up: while preparing distinct child profiles, the
pinned SQLite runtime accepted repeated providerId/accountId on different
users, whereas the bundled Rust account unique index rejected the second
account. Evidence is `/tmp/two-factor-passwordless-after.log`; fixture account
identities now include profile and owner explicitly. That preexisting account
constraint gap remains outside this selected two-factor capability.

The capability depends locally on frozen234eccc and its corrected storage chain.
The coordinator must retain the already selected disable endpoint's authoritative
session, source write order, trust cleanup and preserved session fields when
forward-merging the new config parameter and optional-password DTO. Those
earlier disable changes are absent from this dependency base and are not
replaced by this patch. Skip-enrollment hook rejection ordering is a separately
identified policy repair; OTP options and backup disableSession remain separate
capabilities. No inventory, comparator, coverage, dependency or lock changes.
