# Anonymous transfer after verified login methods

This dependent slice extends the five-owner anonymous lifecycle evidence in
`anonymous-authentication.md`. Its seven new owners invoke actual pinned 1.7.6
magic-link, email OTP sign-in, email OTP verification, signed email verification,
phone verification, One Tap and passkey endpoints. It does not add another
login algorithm or change request authority.

## Signed-email original snapshot repair

Pinned `better-auth/dist/api/routes/email-verification.mjs` updates the stored
user at line 295, then `setSessionCookie` publishes the original lookup user
with only `emailVerified: true` at lines 302–307. Thus anonymous transfer sees
the earlier `updatedAt`, while an authoritative session read sees the updated
stored row. A blanket assertion that callback user equals current user is
incorrect; Source itself fails that assertion. That setup error is preserved
in `/tmp/anonymous-methods-source-strengthened.log` and is not a native failure.

The corrected Source original-object control passes all seven owners in
`/tmp/anonymous-methods-source-strengthened-corrected.log` (468 assertions).
The corresponding pre-repair Native proof has six passes and one intended
failure at the callback's original `updatedAt` in
`/tmp/anonymous-methods-sdk-original-verification-before.log`. It fails on the
actual stored later timestamp, not endpoint absence or an unrelated guard.

Private `CompletedSession` now has an optional user-view projection, default
None. The private producer can add it only to an already-recorded genuine
completion when original raw owner, recorded raw owner and projected owner IDs
agree, and the actual issued session token agrees with the recorded token.
It preserves both recorded raw models. Anonymous consumption checks the owner
ID again. There is no public constructor, client field or response-body
authority, and public dispatch still replaces caller request extensions.

Only signed email verification's newly issued session path supplies this view,
after successful issuance: the original lookup view plus its verification flag.
Current-user/session authorization, session-create hooks and stored update
results are unchanged. Existing-session renewal and email-change stages are
separate snapshot boundaries, not claims of this new producer.

## Real method and persistence owners

`tests/core/anonymous-methods.test.ts` shares setup but owns one scenario per
distinct verified login branch. Actual application delivery callbacks produce
mailbox URLs/tokens, OTPs and phone codes. Real One Tap RS256 and software ES256
passkey proofs use the existing local-key/cryptographic factories. The only
new One Tap export is a private fixture transport constructor reused by the
anonymous profile; no production test seam was added.

Every owner records the actual foreign account, original anonymous session,
preparation, issuance, rejected proof, unchanged stored user/account/session
rows after rejection, successful result, replay, current session, full transfer
receipt, complete stored final rows and deleted anonymous state. Foreign state
must remain byte-equivalent within each runtime. Callback anonymous pair equals
the actual original pair; the new owner is tied to the authenticated current
session and, where pre-enrolled, the independent original credential owner.
Passkey storage confirms its genuine counter reaches two after the rejected
signed wrong challenge and later successful signed assertion.

Replay follows each measured Source contract. OTP and magic-link consumption
reject replay; a consumed passkey challenge returns CHALLENGE_NOT_FOUND. Signed
email verification and Google ID tokens can be reused, but never transfer the
already-deleted anonymous user again. No new general replay restriction is
invented for reusable proofs.

Each actual delivery field is retained. Random OTP/code values are represented
reversibly as `{ token: actualValue }` using the existing token graph, and local
unwrapping asserts exact submitted bytes. Passkey client data and user handle
are reversibly decoded with exact original-byte round trips; the signature uses
the same existing token graph. Full actual primary transports remain canonical.
No comparator, trace exemption, digest or observation field suppression was
introduced. Receipt reset clears only real application counters/events/outboxes
after completed requests; these callbacks have no outstanding asynchronous
receipt work beyond the awaited endpoint completion.

## Evidence and bounds

- `/tmp/anonymous-methods-source-strengthened-corrected.log`: Source self seven / 468.
- `/tmp/anonymous-methods-sdk-snapshot-final.log`: Source versus Native seven / 468.
- `/tmp/anonymous-methods-core-verification-family-final.log`: 51 core and email-verification owners / 1846.
- `/tmp/anonymous-methods-email-verification-native-final.log`: all 46 existing native email-verification tests.
- `/tmp/anonymous-methods-production-clippy-final.log`: strict workspace libraries.
- `/tmp/anonymous-methods-fixture-clippy-final.log`: strict fixture.
- `/tmp/anonymous-methods-client-typecheck.log` and
  `/tmp/anonymous-methods-reference-typecheck.log`: TypeScript.
- `/tmp/anonymous-methods-original-snapshot-build.log`: current fixture binary.

The original five owners and their before proofs remain unchanged. General
`validateUserInfo`, custom physical user-column callback projection, ordinary
exception wire behavior, alternate configurations and cookie-cache behavior
remain bounded as documented by that slice. This view override does not alter
the raw model supplied to cache-version callbacks or the cache payload producer.
Source's signed-email pre-update cache projection needs its own composition
contract; no synthetic raw model is supplied here. Cache publication must still
complete before publishing a completed session, as agreed with its owner.
No dependencies, locks, schema, inventory or full gate changed.
