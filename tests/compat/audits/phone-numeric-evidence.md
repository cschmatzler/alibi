# Bounded phone numeric evidence

The integrated admin gate exposed a test scheduling defect in the existing
numeric-phone signup scenario. It executes 17 successful scrypt signups against
each runtime, collision signups and failed logins, and additional schema flows.
Bun's default five-second deadline expired under concurrent compilation load.
The timed-out async function then continued after the next serial scenario's
database reset, so its previously occupied number incorrectly appeared available.
`/tmp/admin-selected-canonical.log` records the deadline and subsequent late
collision assertion. This was a fixture lifecycle failure, not an admin change.

Split the independent numeric ownership cases into three serial scenarios. All
17 original raw literals and expected exact SQLite text values remain. Rounded
integer and both infinity collisions stay with the successful owner's group.
Every original wire, stored account/session, owner-preservation, rejected-login,
disabled-plugin and unconsumed-schema-proof assertion remains; the final group
owns the disabled/overflow schema controls once. Each group has a fresh reset and
uses its own complete transport/identity graph. The original scenario name
continues to own rounded uniqueness. Inventory requires all three names for
signup and get-session success and state evidence.

The default five-second deadline, comparator, empty exception list and source
coverage floor are unchanged. Independent family review is clear: all 17 samples and each collision owner
remain covered exactly once. The focused phone suite passes 13 scenarios and
1,058 assertions, exactly the previous family assertion count, with the default
deadline intact (`/tmp/phone-numeric-split-focused.log`). Client TypeScript and
diff checks pass. The final canonical gate passes: 264 SDK scenarios / 7,568 assertions,
37 harness tests / 210 assertions, two Chromium tests / 22 assertions and
79.30% source lines (23,849 / 30,076). Log:
`/tmp/phone-numeric-evidence-reviewed-canonical.log`.
