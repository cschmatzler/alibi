# Pending two-factor verification snapshots

Better Auth and its official client stay pinned to 1.7.6. Issue #200 is owned by
`tests/two-factor/pending-lookup.test.ts`: actual enrollment and sign-in issue the
signed pending cookie, factor secret, backup codes, and zeroed attempt row.
The expired cases explicitly send the issued zero-Max-Age cookie after the
browser jar drops it; they do not fail accidentally at cookie admission.

The published `plugins/two-factor/verify-two-factor.mjs` calls
`findVerificationValue`, then reads the user from the returned snapshot. The
internal adapter selects the latest `createdAt` row without filtering expiry,
then optionally performs global expired-row cleanup. That cleanup must finish
before user lookup, and does not invalidate the snapshot already returned.
Consumption subsequently validates expiry atomically. The native pending-state
resolver now calls the existing shared `authentication_helpers::find_verification`
that already implements that contract. Signed-cookie admission, ordinary session
precedence, authoritative user lookup, and later attempt/challenge consumption
remain in their existing owners. There is no new production seam.

The table covers TOTP, delivered OTP and issued backup codes, with default and
disabled cleanup, for expired challenges, missing snapshot users, and a newest
installed expired duplicate referring to a missing user above an older live row.
An unrelated expired verification makes cleanup observable. Missing cookies and
wrong signatures reject before any lookup or cleanup and preserve all physical
rows. Browser expiry has the same unchanged-state control. The test observes
actual successful SQL through public Kysely plugins and SeaORM metrics; both
fixtures delegate to the real adapters, and do not supply fabricated receipts.

Default cleanup removes expired rows before the user read; disabled cleanup
retains them. Missing users fail before any credential or budget consumption.
The expired TOTP/backup cases reach expired attempt consumption without changing
factor credentials. OTP delivery can use the expired snapshot: default cleanup
then leaves no challenge for verification; with cleanup disabled, OTP verification
consumes the OTP, resets the factor failure count, and fails when the expired
challenge is consumed. Complete verification and factor rows, counters, locks,
secret bytes, all backup codes, owner/foreign users, accounts, and sessions are
observed and compared. Sibling sessions remain physically present.

A newest expired duplicate must be returned even though cleanup deletes it;
using the older live owner would wrongly consume a real backup code. With default
cleanup, replay can legitimately resolve the remaining older live row. With
cleanup disabled the missing-user duplicate remains until explicitly restored;
subsequent replay follows the real retained older generation. These outcomes are
preserved rather than normalized to a universal replay rejection. Successful
recovery uses actual positive-lifetime sign-in or restoration of the installed
verification row, never deletion of factor credentials through another guard.

Original raw SDK and transport traces remain intact. State projections preserve
all row columns; existing identity envelopes relate random identifiers, ciphertext,
backup codes and user IDs across runtimes. Independent byte assertions protect
credential preservation. The comparator, schemas, locks, and pinned packages are
unchanged. Existing lifetime/trust tests own serialization and trusted-device
rotation; this test owns pending lookup snapshots and observable cleanup order.
Generic adapter-hook integration and trusted-device duplicate lookup are separate
capabilities, not claims of this bounded fix.

Before repair, the exact final owner failed 15 of 18 cases: expired rows skipped
global cleanup/user lookup, missing-user default cases skipped cleanup, and the
newest expired row was filtered before selection (including real backup-code
loss). The three disabled-cleanup missing-user controls passed. Final source
oracle: 18 scenarios / 1,820 assertions (`/tmp/issue200-exact-oracle.log`). Final
unchanged resolver proof: `/tmp/issue200-exact-before.log`. Restored repair plus
selected lifetime/trust and cancellation siblings: 39 scenarios / 4,472 assertions
(`/tmp/issue200-exact-after.log`). Both production and excluded-fixture strict
Clippy, client TypeScript, formatting and assurance inventory pass. Root
coordinates canonical gates and independently reviewed the production change,
complete owner, both fixtures, and this audit with no finding. The external
autoreview executable named by test-audit is unavailable here.
