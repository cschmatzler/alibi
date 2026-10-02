# Verification storage, identifier and cleanup modes (issue #174)

The initial read-only audit completed while issue #135 was frozen. That issue ordinarily merged at `2984354a0433235d69859f50fc73091a9fecc129`, with an exact reviewed-tree match. This isolated issue starts from that real main commit; the following findings/design are discovery, not passing implementation evidence.

Authority is installed Better Auth 1.7.6 `dist/db/internal-adapter.mjs`, `dist/db/verification-token-storage.mjs`, `@better-auth/core/dist/types/init-options.d.mts`, `dist/db/with-hooks.mjs`, `dist/state.mjs`, and the actual OTP, magic-link, one-time-token and password consumers. The issue acceptance additionally covers wrong operation/mailbox/user, replay, concurrent consumers, cancellation and failed writes.

## Existing strongest owners

- SeaORM `verification_tests.rs`: expired latest invalidates live siblings, expected-value mismatch preserves latest, bounded cleanup snapshots versus unrestricted expired deletion with before-hook veto, identifier-wide deletion with one hook snapshot, consume hooks and commit order, expected-generation CAS, independent SQLite pools racing consume/reserve/update, real committed snapshots and UUID schema reservation. Extend only for distinct new risk.
- SDK `passwordless/email-otp-config.test.ts`: real default/disabled cleanup, plugin hashed/encrypted/reusable OTP configuration. These establish plugin value codecs, not global identifier policy.
- SDK `passwordless/email-otp.test.ts`: operation/mailbox/attempts/expiry, exact one-winner actual server race, reset/change and replay.
- SDK magic-link: real issuance, origin guard before consumption, expiry/replay, disabled signup and hashed plugin codec. Native custom generator/hash/concurrent owner already exists.
- SDK one-time-token: actual persisted original session transfer, expiry/revocation, newest expired generation invalidating older live siblings, hashed plugin codec and server/header generation. Native concurrency owner already exists.
- SDK OAuth rejection: actual browser callback replay with whole owner/foreign snapshots. It does not establish Source atomic OAuth consumption.
- Issue 135 full expired-reset owner completes physical/delivery/rejection/replay/hash/callback/foreign observations before comparing raw proof length.

## Authoritative semantics

Global `storeIdentifier` is plain, SHA-256/base64url without padding, or async custom hash. A default/override map chooses the first matching prefix in Object.entries order: integer keys in numeric order, then other keys in insertion order. This transformation runs after each plugin's own token/OTP representation. Reads and consumes try transformed identifier first, then plain legacy fallback; an existing expired transformed generation remains the winning consumed generation and cannot resurrect a live plain row. Explicit delete/update operate only on the transformed identifier. SQL newest lookup is createdAt descending with limit 1, snapshots before global expiry cleanup, and returns the selected expired snapshot even after cleanup removed it.

Source secondary storage defaults verification to cache-only unless storeInDatabase is true. Read returns truthy safely parsed cache data first without full verification-schema hydration; actual safeJSONParse recursively revives valid ISO-Z strings as Date instances. It tries transformed cache then legacy plain cache, then SQL only when configured. Cache hits and cache-only misses do not invoke global SQL cleanup or backfill SQL. TTL floors remaining seconds and omits writes when nonpositive.

Create ordering is before hooks, optional DB write, cache write, after hooks. Cache failure leaves committed DB data and suppresses after hooks. The cache key comes from the logical identifier transformed before trusted hook mutations; the cached value retains the actual admitted mutation. Secondary-only creation does not invent an adapter-generated primary ID. Update writes cache before DB/update hooks, so a failed DB update can leave an updated cache entry. Delete removes cache before DB/delete hooks, so a DB veto can leave SQL data after cache removal. Database consume commits actual one-row deletion plus unrestricted sibling invalidation before deleting both transformed/plain cache keys. Secondary-only consume uses atomic getAndDelete and bypasses DB delete hooks. Consume hydration rejects parse failures and invalid/nonfinite expiry; it does not validate every remaining field, so missing-field behavior must be measured or explicitly bounded rather than assigned a safe fallback. Reservation remains SHA-256/base64url of `reserve:<logical identifier>` as its primary-key gate and explicitly rejects cache-only storage.

Source OAuth state uses 32 characters from a-z/A-Z/0-9/-/_ and the raw state as DB identifier. Its actual DB callback reads, parses, checks embedded/state cookie correlation, expires the state cookie, then deletes by identifier; it is not the atomic consume helper. Native currently uses UUID state, an oauth: prefix and selected-row deletion. Measure real concurrency instead of inventing Source atomic behavior; repair identifier-wide deletion at the actual guards.

Source password reset request explicitly calls generateId(24), including missing-user timing simulation. Native currently uses a 32-character simple UUID. The shared Source generateId(size) defaults falsy size to 32 and samples a-z/A-Z/0-9. Keep other callers' actual alphabets: magic link 32 letters, default OTT32, numeric OTP. Do not change database entity primary-ID policy indiscriminately.

## Bounded implementation/evidence design

Keep low-level raw typed SQL adapter contracts. Add a genuine initialized verification service with typed ordered identifier policy and optional secondary backend, preserving every actual consumer's Source operation ordering. Existing VerificationView is a DB projection with mandatory ID; cache-only Source snapshots require honest optional real IDs rather than fabricated S::Verification models. A simple wrapper around hookful create_verification then cache.set is insufficient because it would run after hooks too early. Preserve trusted transaction registration/after-commit behavior and explicit unsupported custom-adapter operations.

Keep secondary sessions outside this lane. Configure actual Source session.storeSessionInDatabase as needed to isolate verification storage, and record any unestablished session-cache interaction honestly.

One primary actual server-API storage-mode/identifier matrix should retain whole SQL/cache observations and actual lifecycle receipts for create/find/update/delete/consume/reserve, plain fallback, TTL, mutation, malformed cache, cancellation and failed writes. Extend existing consumer owners with real configured profiles for scope/mailbox/user/foreign isolation, attempts, issuance replacement, expiry/replay and concurrent consumers. Use genuine SQL/cache primitives and exact full outcomes, not fake admission or 404/compiler-before evidence. Preserve current comparator, Source package, thresholds and exclusions. Reuse the credible existing reset-length before observation.

## Existing issue 135 before artifacts

`/tmp/issue-135-before-length.json` and `/tmp/issue-135-before-length.ts` use old Native a6326641 production unchanged (fixture-only missing-API adaptation) versus actual Source. Both real reset requests succeed; each delivered token equals its physical reset-password: identifier suffix and proof value equals the owned user's ID. Source length24 versus old Native32; both full snapshots contain two actual users/accounts/sessions and one verification. `/tmp/issue-135-frozen-standalone16.log` and `/tmp/issue-135-frozen-composed16.log` preserve the complete final lifecycle with the length comparison performed only at the final observation.

## Authoring gate and concrete adapter risks

The primary server-API owner will protect observable configured identifier/storage behavior, whole verification SQL/cache state and actual hook/publication order. Current native production lacks initialized global modes; the credible before proof must show real wrong physical/cache admission rather than an unavailable route or compiler error. Existing plugin-specific value-codec and atomic physical-storage owners do not exercise global transforms or the secondary-only/mixed publication phases. The new initialized service, genuine raw consumed snapshot and publication phase are needed by real production consumers/custom adapters, without fixture-only hooks or fabricated original models.

An expired transformed row must remain the winning consumed generation and block a live plain fallback. Current raw adapter live-consume filters expiry before returning, so it cannot by itself distinguish an absent generation from a deleted expired winner. A raw atomic consumed-snapshot operation is required; existing live-consume contracts remain available and keep their expiry filter. Independently constructed SeaORM pools remain the race authority.

Creation must retain before-hook mutations, commit its physical row when configured, publish the actual admitted snapshot to cache, then invoke after hooks. A cache failure leaves that committed row and suppresses after hooks. A secondary-only snapshot has no invented adapter ID or physical model. New snapshot lifecycle hooks may bridge the old model callback only when a genuine original model exists. Raw cached find preserves truthy JSON and the actual recursive ISO-Z date reviver without full schema hydration; consume performs the separate actual Source expiry hydration. Explicit unsupported custom-store modes must fail closed rather than imitate these phases.

The new `VerificationStore` creation, raw-consumption, identifier-update and logical-reservation methods require genuine adapter overrides; their defaults deliberately return `NotImplemented`. Creation publication is part of the adapter contract, between its before-hook/physical-write phase and after-hook phase, so a generic call to the old hookful creation method cannot safely supply it. The transaction override must publish before commit and defer after hooks until a successful commit. SeaORM implements these phases directly. The repository's private in-memory store implements the same operations using its real locked state (it has no database hooks); its existing transaction wrapper delegates without claiming rollback. Existing application store wrappers forward these operations to their actual SeaORM adapters. Third-party stores must implement the documented operations before using verification consumers through the initialized service.

Rust string inputs represent Unicode scalar values; isolated UTF-16 surrogate inputs are outside this public typed configuration. Arbitrary cached string object-spread currently supports scalar text, not isolated surrogate fields or astral code-unit keys; this bounded malformed-cache behavior is not claimed as complete JavaScript object-spread parity.

## Concrete implementation checkpoint

The initial production candidate c530c86b adds the initialized service and real SeaORM operations. A fixture-only before checkout keeps 4bcd25c3 production and lockfiles unchanged: `/tmp/issue174-before-storage.json` records genuine Source/native OTP issuance with real delivery, SQL/cache proof and foreign credential hashes. Source stores hashed identifiers or cache-only values; old Native stores plaintext logical mailbox identifiers in SQL in both configured modes. Four observations reach the intended public SDK issuance path, not a missing route or wrong-origin denial.

`/tmp/issue174-c530-before.json` records eight real follow-up observations on unchanged c530 production: Source hashed/custom two-factor wrong-code retry recreates the logical identifier and accepts the original correct code; old Native double-hashes its consumed stored identifier and returns OTP_HAS_EXPIRED with a still-live physical proof. Source retries an actual one-time create-hook failure and delivers the same generated OTP; old Native returns500 with no delivery or row. Source identifier update refreshes updatedAt; old Native retains its supplied2021 value. All captured foreign user/account/session fields remain exactly unchanged, and genuine stored credential hashes verify independently. Initial driver import/origin setup failures are retained as infrastructure/fixture failures and are not before evidence.

The physical expiry snapshot retains its genuine DateTime when a retry core needs to recreate the original nanosecond deadline. Wire/cache Dates still use JavaScript milliseconds. The existing email-OTP and phone exact-deadline native owners both passed after this correction; the preceding793-owner run retained their two failures honestly. Source OAuth state uses generateRandomString, whose alphabet includes -/_; the earlier alphanumeric inference from generateId was corrected by the actual SDK state receipt and installed random generator. State-read failures now retain Source's302/internal_server_error response without clearing or consuming state.

The actual shared secondary backend is retained in `/tmp/issue174-backend-*.json`, including unrelated session keys and every raw cache operation. Comparable fixture receipts are explicitly a verification:* projection; no wrong verification namespace or transformed/plain verification key is filtered. Concurrent consume observations retain every actual response and compare the complete operation multiset because cross-request scheduling order is unspecified; the raw backend sequence remains captured. The physical cache-delete failure owner exposed Source's independent Promise.all invalidation of both keys; Native now starts both invalidations even if one fails, after actual SQL retirement and after-delete hooks.

Additional configured consumer profiles use public fractional OTP/magic lifetimes300.5s and OTT180.5s. Separate cache-default/mixed-default profiles keep literal default300s/300s/180s diagnostics. Every default publication is checked against its real admitted expiry and actual before-create/backend.set execution interval; raw TTL differences remain visible. No clock, Source package, comparer, threshold or exclusion has been changed. The initial broad consumer logs contain fixture entropy projection corrections, default-floor timing observations and startup health failures; none is presented as a passing final gate.

An actual unchanged Source-versus-Source default-duration counterfactual is retained in `/tmp/issue174-default-source-counterfactual-30.log`: attempt1 fails both default owners solely at six TTL aliases while all128 independent publication-floor assertions pass. The two prior Source-versus-Source owners passed once; this bounded counterfactual stops at the first reproduced failure rather than retrying until green. Root assigned a separate, narrowly bound producer-publication comparer prerequisite; this issue does not change the comparer.

The immutable bd7 feature-native run stopped after143 passes because the
existing anonymous OAuth context owner still expected the pre-repair
`please_restart_the_process` for an expired embedded state payload. Installed
Source `state.mjs`141–143 emits `state_mismatch` after clearing and retiring the
state. The existing four global OAuth owners now execute that real expired
payload branch with future physical expiry, genuine issued state/cookie, full
retirement and unchanged users/accounts/sessions/foreign rows. The actual
Source/native run passed hashed/custom/mixed; cache completed all behavior
assertions but retained seven literal600-second TTL aliases. Across the four
owners1106 assertions executed. A separate actual Source-source run retained
three mixed600-second aliases at expiredAfter/expiryBefore/expiryIssued
cacheEvents.6.ttl; those are not claimed to reproduce the distinct seven
Source/native alias paths. Both logs are retained as
`/tmp/issue174-embedded-expiry-owner-real.log` and
`/tmp/issue174-source-source-oauth600.log`. The sibling assertion correction
changes only the exact Source-backed error text. The paused845 run leaves701
unreached tests; no broad pass claim is made.

The later fixture adaptation emits the exact publication observer protocol
owned separately by issue302. It changes no174 comparer or production policy.
Actual incoming HTTP middleware records request start/body/cookie; genuine
before-create callbacks record the candidate, real successful cache writes
record raw JSON/TTL/storage deadline and clocks, after-create callbacks record
the admitted snapshot, and actual sender callbacks record delivery. Full
shared-backend diagnostics additionally retain raw serialized values for every
key, including unrelated Source session entries. The original four-field
cache-set projections receive the complete actual set receipt only when every
existing projected field matches it; every original value remains present.

Native Axum dispatch intentionally runs authentication in a supervised worker,
so an outer fixture task-local did not reach callbacks. Two retained initial
seven-owner diagnostics therefore included a missing Native observer; those
are fixture observation failures, not production before proofs. The repaired
fixture uses the existing public immutable request hook context inside the
actual callbacks and matches exactly one live original HTTP frame by method,
full path, body and cookie. Ambiguous/missing matches receive no receipt. There
is no injected header, fabricated request, production capture seam or change
to supervised dispatch. Temporary diagnostic logs were removed.

The actual Source/native seven-owner physical-context diagnostic completed all
1402 assertions; hashed/custom OAuth owners pass, while the five cache/default
owners retain raw comparer differences until the separate302 prerequisite is
integrated. Both actual runtimes emit all three default publication receipts.
The terminal log is `/tmp/issue174-publication-physical-context-diagnostic.log`.
Native fixture builds and client TypeScript pass. These observations are not
claimed as a green full53 gate. Final immutable composed checks remain pending.

## Final composed implementation and focused proof

The current implementation is composed onto actual prerequisite main
`70b541b54615ffc8fca5c3e66de83ea7bfc6f662` (ordinary merged PR303). It retains
all prior cookie/CAPTCHA, physical ledger recovery, policy, provider and signed
SIWE month/timezone fixes. The moved date parser preserves the latter's
function bodies. Issue174 changes no comparer, Source package, coverage floor
or exclusion.

The exact3aaf composed53-owner run completed50/53 with4,476 assertions. Its
three cache OAuth owners retained real publication admission failures. The
complete original paired HTTP/publication/backend artifact
`/tmp/issue174-oauth-admission-pair.json` disproved the initial relative-URL
hypothesis: both request and stored callbackURL are the same relative value.
Source issued the actual signed `state.HMAC` cookie, whereas old Native issued
an HS256 JWT with600-second claims. The prerequisite correctly refused that
wrong wire format. Commitb135 reuses the existing constant-time HMAC cookie
sign/verify helpers and removes the obsolete JWT state-cookie claims. The
physical cookie remains300 seconds; physical verification and embedded expiry
remain600 seconds. Signature/correlation checks still precede cookie clearing,
identifier-wide retirement and embedded expiry checks; encrypted cookie
strategy is unchanged. There is no legacy JWT fallback or admission waiver.

The exactb135 run completed51/53 with4,476 assertions. Its two remaining
failures were only `verificationPublications.1.request.headers.cookie`: the
existing session-cookie comparer recognizes actual email sign-in/signup
issuance, but not an OAuth302 cookie issuance followed by getSession. The
owner retains the original complete OAuth callback/getSession/replay flow and
its physical session. It then uses the existing public server-only setPassword
operation through the named `set-password-default` fixture and the actual
physical signed cookie, verifies the canonical owned credential and real
scrypt hash, captures both actual configured hash callbacks and complete
physical state, and signs the same principal in through the official email
SDK. The newly issued email session supplies the supported cookie issuer
receipt for the authenticated OAuth embedded-expiry phase. The original OAuth
session remains physical and unchanged/unrevoked. Every original sibling,
expiry, wrong-cookie, replay, retirement and foreign-state assertion remains.
This does not claim that the comparer now supports OAuth302 session issuance.

The first added callback-receipt run retained accumulated callback events from
previous fixture runs. The existing normal-mode control resets those actual
receipts. Configuring that control through its server-api alias then retained
four real private control media-type differences (Source charset=utf-8 versus
Native application/json); its established `/__test/set-password` control route
has the same actual charset on both runtimes and is used by the existing
setPassword owners. The setup now uses that existing control route; the actual
set operation still uses `/__test/server-api/set-password`. No response field,
header or callback was dropped and no fixture implementation was changed.

`/tmp/issue174-final53-canonical-control.log` is terminal53/53,4,848 assertions,
with unchanged Source/comparer and full shared-backend diagnostics. The prior
logs are retained as `/tmp/issue174-b135-final53.log`,
`/tmp/issue174-same-owner-final53.log`,
`/tmp/issue174-final53-with-callbacks.log` and
`/tmp/issue174-final53-callback-reset.log` with their actual scopes/outcomes.
The actual expired reset/OTP compromised-password owner also passes1/1 with180
assertions in `/tmp/issue174-b135-expired-reset.log`, repairing the measured
Source24/oldNative32 proof length while retaining the complete password-policy,
physical proof, expiry, consumption, callback, replay and foreign observations.
Client TypeScript passes.

Capability publication adds138 cells only from passing measured global
verification consumer scenarios on their eleven actual SDK routes. Every
existing parent declaration remains required; auxiliary foreign signup,
credential setup and trusted fixture operations add no capability cells.
Full immutable canonical, strict documentation/browser and clean complete
production coverage results will be recorded after their terminal outcomes.

## Final composition and terminal verification

The original frozen head5f0 completed the full SDK phase with1,511/1,513
owners and106,354 assertions. All issue174 owners passed. Two retained
failures compare wall-clock timestamps: organization trusted-role diagnostics
contain ten session expiry values (including the foreign session), and factor
skip-verification diagnostics contain six challenge timestamps. The respective
Source/native requests occurred several seconds apart; durations agree.
This is not a full canonical pass or an independently reproduced unchanged
parent pair. Later canonical documentation and coverage phases were not reached.
`/tmp/issue174-5f0-final-canonical.log` retains the complete diagnostics.

The original six-family collection passed four families and failed two:
JWT captured an undefined expiry observation, and user-management's Source
server failed startup with EADDRINUSE before its owners ran. Its SDK collection
exit was100, despite the independently measured33,198/43,172 (76.897063%) line
coverage clearing75%. This is not successful complete SDK coverage. Its log
is `/tmp/issue174-5f0-final-coverage.log`. Separate strict docs and actual
Chromium completed successfully in `/tmp/issue174-5f0-docs-browser.log`.

Root composed the implementation with merged dispatcher main
`d9497b908329d5af2b6927328e326967b4e616ae`, producing frozen code/support head
`edda005a4dc780ded0e8293de9f9f35e70e15540`. Both profile registries remain.
The dispatcher's shared one-time-token consumption now uses the initialized
verification service and its retained value, so both physical HTTP and server
API callers honor these storage policies. Durable coverage selects the existing
core SDK family alongside all seven prerequisite families. The75% floor and
exclusions remain unchanged. No Source or comparer changes were introduced.

At edda, default794/794 and optional846/846 native tests pass, as do both strict
all-target Clippy matrices, rustls checking, fixture strict lint/build, both
format checks and client TypeScript. Actual core SDK owners pass207/207 with
16,430 assertions; dispatcher owners pass27/27 with3,966 assertions. Separate
strict workspace documentation and actual Chromium pass. Logs are
`/tmp/issue174-root-compose-checks.log`,
`/tmp/issue174-root-default-clippy.log`,
`/tmp/issue174-root-composed-sdk.log` and
`/tmp/issue174-root-docs-browser.log`. These are composed gates, not a claim
that the entire composed canonical SDK suite was rerun or passed.

Fresh instrumented collection at edda passes846/846 native tests and all eight
actual SDK families, terminal exit0. Complete production line coverage is
35,909/44,690 (80.351309%), exceeding the unchanged75% requirement. LCOV has228
source paths and zero duplicate paths. Its preserved file is
`/tmp/issue174-root-complete.lcov.info`, SHA256
`6c8ef95a954a4216506bb21bee3a0beef4456b6a6cd648a1e23d6f521ecea50c`;
`/tmp/issue174-root-complete-coverage.log` records every family and floor result.
The collector retains SDK status independently of coverage reporting, rather
than concealing a failed collection behind a successful floor.

Independent composed capability inventory confirms5,519 parent cells retained,
138 measured additions,5,657 total, zero removals and zero duplicate cells.
Only this audit changes after frozen edda verification. Original wrong-wire,
setup and timestamp failures remain recorded; no broad timing normalization,
stack override, dependency patch or hook bypass was used.
