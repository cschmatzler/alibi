# Pending two-factor session-create cancellation

This correction depends on typed session-create cancellation 1655472 and the
earlier enrollment ordering/response corrections 9a35025 and 59aa753. Published
Better Auth 1.7.6 `plugins/two-factor/verify-two-factor.mjs` valid() consumes the
pending challenge before creating the session. When an actual create hook
returns false, its adapter returns null and valid() raises HTTP 500 with
code FAILED_TO_CREATE_SESSION and message `failed to create session`.
Application hook exceptions retain their declared status and message. This
differs from the empty 500 on authenticated enrollment cancellation.

Only pending finalization maps SessionIssueError::Auth with the exact typed
SessionCreationCancelled variant to that documented upstream error. Other
errors retain the existing conversion, including genuine Forbidden exceptions
with the exact cancellation message. Store defaults, authenticated routes,
other CRUD cancellation and other plugins remain unchanged. No global status
or message classification is added.

Six official-client scenarios independently own TOTP, delivered OTP and real
backup completion with either cancellation or a same-message application 403.
Equivalent profile lifecycle hooks run only at public verification paths;
signup, enrollment and the first password step execute normally. Each owner
enrolls a real secret/backups and persists verified true, then signs out and
begins a real pending challenge. Incorrect credentials and a guest's correct
code cannot complete or mutate the owner's challenge. A separate owner retains
its actual session and whole user/account/session state throughout.

After a correct factor reaches the rejecting create hook, the tests read the
actual factor and verification rows. Both errors consume the challenge, reset
the account budget to zero, and create no session or trust-device record.
TOTP and backup consume the shared attempt row; OTP consumes its own code but
retains the source's unused shared attempt row at zero. Factor secret/verified
state remain unchanged; backup completion changes the encrypted generation.
Replaying the consumed challenge fails. A renewed backup challenge rejects the
used code and reaches the hook only with another real unused backup, proving
consumption persists despite the session failure. The trusted fixture only
reads actual rows, or seeds the existing fractional account counter, and
reports storage errors rather than manufacturing absence.

The primary HTTP regression fails against the frozen pre-fix owner: all three
cancellation cases return 403 instead of the exact JSON 500, while all three
genuine Forbidden controls pass
(`/tmp/two-factor-pending-cancel-sdk-before.log`). All six cases / 256 assertions
pass afterward (`/tmp/two-factor-pending-cancel-sdk-after.log`). The ordinary
SDK responses and transport remain compared without exceptions. Private
generated challenge identifiers are used to query the real consumed rows;
their dynamic values are not returned as cross-runtime observations.

The existing native hook/transaction tests already own semantic cancellation,
unchanged default 403, propagation and rollback. Per-factor copies at another
layer would duplicate the stronger HTTP persistence proof, so this correction
adds no redundant native test or test-only production seam. Existing native
two-factor tests are rerun as regression checks. The coordinator owns canonical
gates, inventory and independent review; no schema, dependency, lock, coverage,
timeout, comparator or shared inventory changes occur here.

Final focused validation: twenty-seven distinct SDK scenarios / 972 assertions
pass (`/tmp/two-factor-pending-cancel-sdk-family-final.log`), including the six
pending cancellation/control scenarios / 268 assertions. Ten native tests
(`/tmp/two-factor-pending-cancel-native-final.log`), client TypeScript and
workspace library Clippy with seaorm2 pass. Formatting and diff checks pass.
