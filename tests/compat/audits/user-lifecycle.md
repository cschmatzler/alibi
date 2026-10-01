# Configured verification, mailbox changes and account deletion

Issue #186 uses the installed, unmodified Better Auth 1.7.6 application as its
oracle. The production owners are `api/routes/email-verification.mjs`,
`api/routes/update-user.mjs`, `api/routes/session.mjs`, cookie writers and the
actual internal SQLite adapter. The lifecycle fixture registers real public
configuration, callbacks and cryptography on both servers. Its private controls
read complete persisted rows, choose application callback errors, alter the
actual stored session clock, and hold an actual deletion callback for concurrency.
They do not supply authentication, callback receipt/order or deletion admission.

## Stage contracts

* Signup delivery uses `sendOnSignUp ?? requireEmailVerification`; sign-in
  delivery additionally requires verification and explicit send-on-sign-in.
  Delivery observes the real original HTTP method, full URL and application
  marker. Native exposes the original URL on `RequestHookContext` while keeping
  the logical routing path, original body, trust policy and request metadata.
* Ordinary verification calls before/after hooks around the stored update, then
  resolves an automatic sign-in session. Already verified mailboxes skip hooks
  and session resolution. Existing sessions retain their original snapshot with
  only the verification flag changed; absent/foreign sessions create a genuine
  owner session. A rejected after-hook leaves the stored update without issuing
  a session cookie or cache snapshot.
* Mailbox change conceals occupied addresses with the same success shape. The
  missing-delivery guard runs before lookup. Verified old-mail confirmation
  issues a configured new-mail proof without changing rows. New-mail completion
  creates any missing session before updating the mailbox and invoking the
  after-hook, then publishes the selected original session projection. A failed
  after-hook leaves that new physical session and updated mailbox but publishes
  no cookie. An old session for another mailbox cannot complete either stage.
* Unverified promotion updates the mailbox and publishes its old session
  projection before optional delivery. Its ordinary new-mail proof uses the
  configured expiry; with automatic sign-in disabled, verification updates SQL
  while the already issued cache snapshot remains unverified. A configured
  promotion without delivery still succeeds. Same-mail errors retain Source's
  message-only wire shape.
* Deletion checks a truthy password using the initialized maximum and actual
  configured hasher before a body proof. Callback sender configuration selects
  proof issuance before freshness. Tokens use a real CSPRNG and the 32-character
  lowercase-alphanumeric alphabet. Zero configured expiry falls back to 24 hours;
  negative expiry produces a genuinely expired delivered proof. Pending delivery
  retains sessions and cookies even when the notification callback rejects.
* Deletion consumes the actual stored proof atomically before expiry/owner
  admission and before the application hook. Wrong owners and failed before-hooks
  consume the proof without deleting rows. A held before-hook leaves no reusable
  proof; concurrent replay rejects while the first request completes once.
  Success removes only the owner's user, accounts and every session. After-hook
  errors propagate after those writes. Direct deletion and GET callback responses
  clear browser cookies, including after-hook failures.
* Source's body-token deletion invokes the callback as a nested endpoint and
  discards its response headers. Native preserves this observed distinction on
  both success and after-hook errors; the completed database deletion still
  makes the old session unusable. Missing or stale lifecycle HTTP authority uses
  `UNAUTHORIZED`/`Unauthorized`, while trusted storage/application errors retain
  their own error types. Stale update-user authority clears the actual browser
  cookies; missing cookies do not cause an issuance or callback.

## Independent observations

The official SDK owners retain every user/account/session/verification field and
actual application receipt. Foreign rows are compared byte-for-byte within each
runtime before differential comparison. Secret hashes and prefixed proof
identifiers are presented as lossless typed entropy witnesses: the entire actual
hash, salt and key remain observable, and proof prefix/token/owner reconstruct the
original SQL tuple. Actual password verification delegates to each public crypto
implementation; no fixture substitutes a successful comparison.

Every issued email JWT retains its original bytes and its signature is checked
independently with Node HMAC before decoding the actual claims and configured
lifetime. Every cache cookie is retained separately, including two writes during
promotion. Its atom preserves the original signed token, exact parsed envelope,
raw Set-Cookie header, observed clock and actual public Source decoder result.
The unchanged shared comparator validates canonical bytes, HMAC, configured
expiry and the complete authenticated decoded copy. No Source implementation,
comparator, transport allowance or coverage floor changes are included.

Error response bodies are parsed as JSON independently, preserving all fields;
this avoids treating object property serialization order as a behavioral change.
Raw HTTP traces retain complete body types, fields, headers and cookie effects.
Source date controls use the actual adapter's Date binding instead of incorrectly
writing numeric milliseconds directly into its SQL representation. Supplied
absolute timestamps and every resulting stored date remain in the observations.
Signup/sign-in notification proofs are deliberately separated by an observed
NumericDate second so deterministic JWT equality cannot depend on a wall-clock
boundary crossed by only one server.

## Regression and validation record

The genuine pre-repair server at parent `7eeeee5f` failed the initial three owners
for the intended differences: occupied mailbox 422 versus 200, incomplete full
before-delete user receipt, and swallowed after-delete error (200 versus 400).
The preserved log is `/tmp/issue186-three-owners-before-valid.log`.
Additional actual owner runs then exposed eager verification session/cache
callbacks, promotion cache/delivery order, missing HTTP `UNAUTHORIZED` shape,
stale-cookie cleanup, and the body-token nested response-header distinction.
Each failed result is retained before its corresponding repair.

The final focused matrix passes all 40 owners and 1,960 assertions with real
Source/native HTTP servers (`/tmp/issue186-40-owner.log`, terminal exit 0).
Client TypeScript and optional-feature workspace Clippy pass before the final
bounded body-token cookie repair; final exact-head checks remain required.

The concurrency owner was also run with only the original get/check/delete
consumption algorithm restored, while retaining the real configured application
and actual callback gate. Source completed its full concurrent flow, then Native
failed at the held callback because the actual stored proof remained reusable
(31 assertions, `/tmp/issue186-original-consumption-before-valid.log`). This is
an isolated regression check of the original algorithm, not a claim that the
complete old tree implemented the newly configured sender API. Final production
source was restored before commit. The earlier archived-binary launch with a
missing execute permission was a setup failure and provides no regression proof.
The completed owner count, final parent rebase, canonical/native/coverage result,
and independent review will be appended after those commands finish. This audit
does not claim that an earlier focused result is a complete canonical pass.

The existing native success setup now configures the genuine public development
email provider required by its claimed delivery capability. The existing cookie
unit test imports its real public helper directly instead of depending on a
removed production-only import. No duplicate private-core tests or production
exports used only by tests were added.
