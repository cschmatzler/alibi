# Required primary-route evidence repair

The pinned reference remains Better Auth 1.7.6. The integrated 601-scenario
SDK run passed all 43,802 assertions, then failed the capability-evidence gate.
That failure is retained in `/tmp/wrapup-reviewed-canonical.log`; it was not a
complete canonical pass or a new coverage measurement. No requirement is removed
or relaxed to accept it.

The organization membership-policy owners already exercised organization
creation, raw organization reads, role promotion and member removal with actual
stored snapshots. Their state-route declarations now identify those real
operations. Additional guest requests use a real owned organization ID and the
same configured read profile, without a session. Both read endpoints reject
before policy callbacks and preserve every organization/member/invitation/team
row and all three principals' complete user/account/session state.

That primary flow exposed a production wire defect: Source returns 401
`UNAUTHORIZED` / `Unauthorized`, while Native returned
`AUTHENTICATION_REQUIRED` / `Authentication required`. Only list-members and
get-full-organization now use the existing organization session guard that maps
missing sessions to the Source error and preserves other errors. This guard
also composes with the separate cache-aware session work.

The staged-expiry owner now submits its actual expired invitation through the
official organization client without a session, then retains its original
authenticated recipient and foreign-user attempts. Source's unauthenticated
request returns 401; the authenticated expired lookups remain 400
`INVITATION_NOT_FOUND`. Complete hook receipts, invitation/member/team/session
state and all three principals remain unchanged. This does not replace the
expiry check with an unrelated invalid request.

The existing real ES256 origin matrix is retained. For both registration and
authentication, a valid signed proof is first submitted with a foreign HTTP
Origin. Both runtimes return 403 `INVALID_ORIGIN`, retain the exact issued
challenge, and preserve passkeys and both principals. The same proof then
succeeds with the allowed Origin, after which its replay fails. The existing
wrong signed-proof-origin cases still consume their challenges and reject.

Before the wire fix, the focused differential run passed 33 of 34 owners and
failed on both complete guest error bodies. After the fix, all 34 owners and
3,744 assertions pass in `/tmp/inflight-evidence-root-focused-after.log`.
Client TypeScript and the locked fixture build pass. Independent review and the
next complete integrated canonical gate remain required before publication.
OAuth declaration/flow repairs are independently owned in a separate slice.
