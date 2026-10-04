# OTT composition timing

The existing composed owner and aged-session owner fail on immutable baseline
`30c912a0e808baef91535a963a9cb820683c58e2` against both actual SQLx and
feature-enabled SeaORM. The official npm Better Auth 1.7.6 files were checked
byte for byte against the registry tarballs; installed packages use private
inodes. `raw-proof.tar.gz` retains complete paired observations and traces,
logs, provenance, private-inode receipts, and the measured facts in `proof.json`.

At composed traces 4 and 19, Source produces the identical EdDSA token because
both calls occur in the same `iat` second. Native crosses a second between those
calls. The payload user and subject remain the original upgraded owner. This
is a time-dependent fixture expectation, not a production identity or ordering
gap. Configure the existing public JWT payload callback with the complete user
and an explicit `iat` from its persisted creation time. The original signer,
public key, owner payload, subject and lifetime remain independently checked.
The original enrollment URI must still identify the upgraded owner.

The aged-session table previously grouped six independent refresh policies in
one scenario. Password-hash latency accumulates in the native run, exceeding the
comparison window on the last cases. Each case still issues a genuine token
with a 180000ms lifetime and transfers its original persisted session. Register
each existing policy as its own scenario with its own execution window. Keep
all pending timestamps and the actual expiry write, refresh bounds, browser
cookies, original token binding and consumption/removal assertions.

Authoring gate: these are changes to the existing primary OTT owners, not new
parallel proof. They guard real owner publication and refresh policy; credible
regressions include publishing a foreign user, overriding explicit `iat`, or
refreshing a disabled session. Prior #169 default owner and #416 callback and
composition receipts remain intact. Production exports, test-only production
seams, comparison rules and exclusions are unchanged.

Repair base: `5e97381835dd9f5d15b2bbad1153e799efa00262` (fixture-lifetime repair).
Validated code head: `43088f146e54c1143620ba5e5ec86f734a9aba75`.
Both actual adapter focused runs pass 17 cases / 670 assertions, including the
existing callback failure, consumption, replay, foreign-state and hook owners.
Clippy passes for the fixture server with both default and SeaORM features;
focused formatting, TypeScript checking and diff whitespace checks pass.
Existing TypeScript lint findings remain with native-gate owner #432.
The archive includes full baseline and final paired states, logs, package
provenance and private-inode receipts. Coordinator exact-head review remains
required before merge.

Independent coordinator review approved exact head
`0b86c03258f0a93a60968eb68a389942621720ef` on 2026-10-04 and authorized
ready/squash merge. Reviewer inspected complete Source/native callbacks,
all six policy cases, concrete baseline measurements, and both 17/670 receipts.
Incoming main `7513f934d713645ef3d3da9205836c1ccc548fb1` (#432) changed
only braces/declaration formatting in the overlapping files. Rebase preserved
all requests, assertions, timestamps and callback semantics. Minimal range-diff
qualification: first commit differs only in context adding the incoming closing
brace before the retained TOTP identity assertion; the two later commits are
identical. No unrelated proof rerun was needed under that authorization.
