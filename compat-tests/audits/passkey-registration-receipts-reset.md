# Registration fixture receipt reset

The actual application registration resolver/after-verification callbacks record
receipts in a fixture-owned array/Vec. The database reset omitted these receipts.
After a scenario failed before reading its receipts, a later legitimate scenario
observed an old resolver receipt. This is a fixture defect, not an authentication
production defect.

The distinct owner uses the official client to create/sign out a real user,
obtains an application-signed enrollment proof and actual registration options,
then calls the existing reset boundary. Before repair, the actual completed
resolver receipt remains: `/tmp/passkey-registration-receipts-reset-before.log`.
The repair adds only actual receipt-array clearing to both application fixtures'
existing reset boundary. It neither generates expected receipts nor changes the
authentication library or clears the array when a callback runs. Existing exact
callback-input and receipt assertions remain intact.

Reset runs between completed public scenarios. These registration fixtures own no
detached callback tasks or held callback gates: the actual resolver and
registration callback are awaited by their public endpoints before the fixture
reset is sent. Reset does not claim to drain arbitrary concurrent application
registration requests that the scenario has left outstanding.

Source-to-Source five focused owners pass 582 assertions in
`/tmp/passkey-registration-source-oracle-fixed.log`, including the reset owner.
Rust-to-Rust reset passes 14 assertions in
`/tmp/passkey-registration-receipts-reset-rust-self.log`. Actual dual-runtime reset
and registration owners pass the same 582 assertions in
`/tmp/passkey-registration-source-sdk-final.log`. The whole passkey family passes
29 / 2746 in `/tmp/passkey-registration-source-family-final.log`. Required client
TypeScript and fixture strict Clippy pass separately. Optional standalone reference
strict checking finds the same preexisting Auth generic-map variance at line132 on
both frozen1f parent and this tree; `/tmp/passkey-registration-source-reference-
fixture-baseline.log` and `...fixture-typecheck.log` retain that diagnostic without
suppression. The reference project has no tsconfig and current gate checks the
client project. Runtime Source and all callback owners pass.

No production seam, comparator change, inventory/lock change or full gate belongs
to this prerequisite. Coordinator owns canonical integration.
