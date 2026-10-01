# Bounded redirect observations

The frozen 591-scenario run passed 590 scenarios and failed the final case in
the 24-request redirect matrix. The actual recorded session timestamp was
2.533 seconds later in Native than Source after fourteen password hashes and
whole-owner/foreign-state reads. The existing 1.5-second comparison tolerance
correctly rejected this timing difference. Its complete failure is retained in
`/tmp/next-anonymous-encryption-canonical.log`; it is not counted as a passing
gate or a new behavioral parity claim.

Four bounded scenarios now partition the same twelve callback inputs, three
per owner, and still run every value through both actual email and username
sign-in methods. The original scenario name remains required for both routes.
No input, success/rejection expectation, current-session token relationship,
prior-session preservation check, foreign state check, complete returned value,
raw transport observation, comparison rule or tolerance is removed. Each owner
starts with genuine fresh users, rather than comparing a timestamp after the
entire sequence of unrelated callback variants.

The Source-self and differential whole-origin file each pass six scenarios and
544 assertions, including the untouched canonical-origin and real ES256 proof
owners (`/tmp/core-redirect-observation-source-self.log` and
`/tmp/core-redirect-observation-differential.log`). Client TypeScript and diff
checks pass. Twenty actual measured requirements enforce the added bounded
owners, with every earlier requirement retained. Production code is unchanged.
Independent review and the next canonical integrated gate remain pending.
