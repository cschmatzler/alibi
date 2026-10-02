# Ordinary compact-cache guards and publication interactions

Reference: installed, unchanged Better Auth 1.7.6. This extends the existing
13 passing compact owners; their authenticated atoms, raw cookies, SQL rows,
version callbacks and failure controls remain the primary evidence for the
codec. JWT/JWE strategies, stateless or secondary storage, rotation and cookie
attributes remain #171–177.

## Read-only consumer classification before guard changes

`getSessionFromCtx` catches only the nested get-session error, forwards its
successful cookie headers and uses its complete returned snapshot. An ordinary
stateful read can retain genuinely signed cached authority after physical
revocation. `getAuthoritativeSessionFromCtx` clears prior middleware authority
and forces `disableCookieCache: true`; sensitive admission must re-read storage.
Fresh middleware uses the ordinary read and then checks the original creation
time. None of these contracts permit an unverified token or foreign-bound cache.

| Consumer | Installed Source authority | Migration boundary |
| --- | --- | --- |
| get-session, account list/unlink, anonymous resolution | Ordinary; unlink adds freshness | Existing compact owners retained |
| JWT `/token` and direct response header | Ordinary; header uses actual hook snapshot | Already implemented by #209; composition evidence only |
| email verification/send and signed mailbox callback | Ordinary optional read; signed claim owner still validated | #186 existing supported snapshots retained; composition evidence |
| update-user | Ordinary session middleware | Cache read plus updated-user publication |
| update-session | Ordinary, followed by actual row update; missing stateful row rejects | Preserve failed-update rejection and cookies |
| list-sessions | Ordinary plus freshness; result reads real active rows | Cache-aware freshness guard |
| revoke-session(s)/other-sessions, change-password/email, delete-user, set-password | Sensitive physical | Preserve authoritative guard |
| ordinary organization routes, extensions and optional invitation/member reads | Ordinary; memberships/resources remain physically scoped | Remaining core and optional guards |
| admin RBAC/get-user | Authoritative, even after virtual middleware | Preserve physical admission; reject virtual masking |
| admin stop-impersonating | Ordinary current projection; original administrator row remains physical and owner-bound | Cache current identity only |
| API-key get/list/delete | Ordinary session middleware; key/config ownership remains physical | Cache-aware owning identity |
| API-key create/update | Explicit `disableCookieCache: true`; an already established virtual context survives this option | Force the stateful cache bypass while retaining genuine virtual middleware and nested cookie emission |
| passkey list/update/delete | Ordinary plus resource ownership | Cache-aware owning identity |
| passkey registration | Ordinary plus freshness when required; optional resolution uses ordinary read | No invented user model or registration claim |
| passkey authenticate options | Optional ordinary user for credential selection | No authentication admission from options |
| two-factor enable, TOTP URI, backup generation | Ordinary; password/factor checks still run | Cache-aware identity |
| two-factor verify/send factor | Optional ordinary session, otherwise genuine pending proof | Cache-aware session branch; pending stays physical |
| two-factor disable | Sensitive physical | Preserve authoritative guard |
| multiple-session list/switch | Signed browser selector plus actual selected rows | Selected target never authorized solely by cache |
| multiple-session revoke | Ordinary current session; signed target selector and real deletion | Cache current identity; publish genuine next selected row |
| one-time-token generation | Ordinary session middleware | Cached projection may mint proof; proof verification still resolves physical session |
| device claim/approve/deny | Ordinary optional/required read; real claimed device owner still scoped | Cache identity only |
| phone verification update | Ordinary read after genuine OTP consumption | Cache identity; physical user update and callback retained |
| email-OTP verify-email/change-email | Sensitive physical middleware | Preserve physical; sign-in verification optional ordinary branch audited separately |
| OAuth link-social | Ordinary session middleware | Existing raw profile/account owner admission retained |
| OAuth access/refresh/account-info | Explicit stateful physical `resolveUserId` | Preserve physical token authority |

The public native `require_session` API remains physical. Cached identities use
the existing `AuthenticatedUser::Cached(UserView)` and `SessionView`, never a
constructed application database model. A completed cookie publication is an
observation for subsequent hooks, not an authentication source.

## Authoring contract and retained before evidence

New owners extend the existing compact fixture and scenario family. They protect
the public HTTP guard authority, real row mutation/foreign isolation and ordered
cookie publication of actual plugin compositions. Credible regressions are the
current physical-only ordinary guards, cache-only sensitive admission, missing
multi-session cache replacement, or a downstream hook resurrecting scrubbed
pending-two-factor authority. Existing codec owners cannot reach those plugin
branches. Controls invoke genuine configured application callbacks and stores;
they never supply an admission, receipt or successful auth response.

The merged #186 before artifacts already prove the first gap:
`/tmp/issue186-source-cache-authority.json` and
`/tmp/issue186-native-cache-authority.json` retain genuine signup token/cache
bytes, independent HMAC and owner/token-binding validation, empty revoked SQL
session tables, full retained user/account rows, and wrong-signature/corrupt
cache controls. Source update-user writes with the valid revoked cache; Native
rejects. Broader migration proof will use the actual new immutable fixture
configuration with unchanged pre-fix production before repairing owners.

## Implemented boundaries and focused proof

Successful ordinary reads are retained only within the genuine dispatch, bound
to its actual configuration and database instances, complete headers and
virtual-session snapshot. Changed credentials cause
a fresh read. Sensitive authoritative reads clear this ordinary result before
reading physical storage. Public dispatch still scrubs caller extensions; a
completed cookie-publication snapshot is separate from this authenticated read.
Negative reads and callback errors are never memoized.

Pending password two-factor login now creates the genuine transient session and
awaits its version policy as Source does, then deletes the real session and
discards publication before returning the challenge. Verification uses the
effective one-day browser session configuration before creation. Multi-session
selection/fallback and one-time-token verification publish the actual parsed
selected views. Device bearer redemption creates its real session without
browser-cache publication. Update-user can retain a validated cached projection
after adapter user deletion without restoring any database row; other storage
errors still propagate.

Trusted anonymous linking receives the newly issued session's configured adapter
fields, including fields hidden from public output. Public/cache projections
remain filtered. Existing-session email verification renews the chosen cached
projection rather than replacing callback inputs with later database rows. This
does not claim arbitrary raw user extensions or the wider custom-schema support
tracked in #184.

All 29 compact owners passed together: `/tmp/issue221-all-owners2.log`, terminal
exit 0, 1,702 assertions. This retains all 13 original owners and adds 16 genuine
HTTP interaction/guard owners. Full configured user/session/account rows and
foreign rows remain in the observations. Password hashes are independently
verified against the actual password before retaining their bytes; API-key rows
are checked against SHA-256 of the actual issued key. Cache atoms retain their
raw cookies, full envelope, HMAC, decoded fields and token/owner relationships.
Signed-email delivery retains its complete real JWT and independently checks
HMAC, email and lifetime; the existing JWT comparator compares its claims.
An initial duplicate bare decoded claim observation crossed a second boundary
(`/tmp/issue221-all-owners.log`, 28/29, iat/exp only); the duplicate was removed
while every delivered JWT byte and claim remained in the existing evidence atom.

Retained intended wrong-implementation evidence:

- `/tmp/issue221-before-ordinary-owner3.log`: five Source halves passed; the
  unchanged native physical guards rejected valid revoked cache (261 assertions).
- `/tmp/issue221-interaction-before2.log`: Source halves passed; Native lacked
  pending issuance receipt, selected cache replacement and cached factor enable
  (173 assertions).
- `/tmp/issue221-expanded-before-owner.log`: ordinary organization/device Source
  halves passed while Native rejected; composed repaired owners also retained
  their receipts (416 assertions).
- `/tmp/issue221-final-before-owner.log`: exact expanded fixture against unchanged
  107b5c2b production; Source phone update succeeded, admin virtual admission
  denied and deleted-user update retained its projection. Native failed those
  exact contracts (153 assertions; final-fixture build exit 0).
- `/tmp/issue221-remaining-owner2.log`: actual device bearer redemption emitted
  a Native-only browser cache; actual deleted-user update returned 404; nested
  API-key creation missed Source cache emission.
- `/tmp/issue221-composition-owner2.log` and
  `/tmp/issue221-composition-repair-owner.log`: original trusted anonymous session
  sentinel and successful signed-email callback receipt differed. The latter
  also retained the overbroad application-schema projection before narrowing it
  to the actually configured session view.
- `/tmp/issue221-established-composition-owner2.log`: successful signed-email
  callback still received a physical private sentinel absent from Source's
  chosen cached projection; Native 1/2, Source halves passed.
- `/tmp/issue221-ott-before-owner.log`: actual consumed proof returned the real
  stored session but lacked Source's cache cookie. Repaired combined owners
  passed `/tmp/issue221-final-composition-owner.log` (3/3, 288 assertions).

The broader canonical, strict, docs/browser and clean coverage results will be
recorded on the final composed immutable head. The 75% floor, production
exclusions, Source package and shared comparator remain unchanged.


## Bounded native test audit and reader isolation

Candidate: `new_session_hook_replaces_same_user_cookie_and_respects_browser_limit`
(`crates/api/src/plugins/multi_session/tests.rs`, previously line 336). It could
check direct hook deletion, selector publication and counting invalid names, but
manufactured a successful response/cookie after direct session creation without
the completed session publication that the real public dispatch owns. The
production hook remains called by BetterAuth's completed-response pipeline;
there is no support seam or production code to delete. History: 38abf5c3 added
signed multiple sessions, 9e9bfcac added application field policies, f20fb531
applied strict tooling. The stronger remaining primary is the real SDK owner
`multiple sessions rotate same-user login and honor configured browser account
limit`, which retains same-user rotation, replay denial, real SQL rows, foreign
accounts and sign-out. Its invalid named-cookie capacity control is extended at
the genuine sign-in HTTP boundary before retiring the obsolete direct-hook unit.
Risk: accidentally dropping invalid-signature cookie capacity counting; focused
validation is that SDK owner plus all multiple-session/compact siblings and the
native matrices. The first immutable canonical run is retained at
`/tmp/issue221-canonical-first.log`: both strict matrices and optional build
passed; native stopped with 434 passes/1 obsolete-unit failure (435/794 run,
33 skipped,359 unrun), terminal exit100.

The public native reader owner
`successful_cached_reader_does_not_cross_auth_configuration_or_database` protects
nested trusted application contexts reusing the real request/extensions. It uses
genuine HTTP signup cookies, first and repeated successful public reads, then
checks a different secret with the same store and a different SQLite store with
the same configuration. The store case forces the actual physical lookup; no
pointer equality is asserted by the test. Existing SDK owners cannot reach this
native host API boundary. No production-only-for-test seam is added. On unchanged
bd503 production both second readers wrongly succeeded:
`/tmp/issue221-context-before.log`, terminal101, denial results `[false,false]`.
The repaired owner passed `/tmp/issue221-context-after.log`, terminal0. Successful
reads retain actual configuration/database Arcs and require both instance
identities before reuse; sensitive clearing still leaves no retained read.


The native callback error identity owner
`configured_backup_callback_errors_preserve_factor_user_and_current_session`
remains valuable: native 400/403 typed callback errors and unchanged complete
factor/user/session rows are distinct from the SDK happy-path cipher contract.
The immutable 5639 canonical stopped there after 556 passes
(`/tmp/issue221-canonical-final2.log`, exit100); a complete default native audit
confirmed it was the sole failure (792/793 pass, `/tmp/issue221-native-stale-audit.log`,
exit100). It reused one request/extensions across enrollment and regeneration
after changing the physical user's enabled flag. The ordinary retained snapshot
correctly preserved the previous logical operation, so regeneration never reached
the callback. The second operation now starts a real fresh AuthRequest with the
same actual signed cookie/body, while every error, receipt and rollback assertion
remains intact. No production seam or error-contract adjustment was needed.
