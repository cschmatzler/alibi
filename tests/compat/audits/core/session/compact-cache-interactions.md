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

The broader canonical, strict, docs/browser and clean coverage results are
recorded below with their immutable heads. The 75% floor, production
exclusions, Source package and shared comparator remain unchanged.


## Bounded native test audit and reader isolation

Candidate: `new_session_hook_replaces_same_user_cookie_and_respects_browser_limit`
(`crates/api/src/plugins/multi_session/mod.rs`, previously line 336). It could
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


## Full canonical regression classification and bounded repair

Frozen 46d00c6b on fa883 passed both strict matrices, optional feature build,
793/793 default native,845/845 optional native,2/2 fixture,71/71 harness and
alignment checks. Full SDK terminated with1119/1136 pass,17 fail,78948 assertions
(`/tmp/issue221-canonical-final3.log`, exit100). Ten existing organization guest
owners and three admin guest owners exposed a real regression: generic ordinary
middleware error normalization ran before route-specific null-session responses.
Organization common resolution now retains its missing-session error for those
existing handlers; has-permission still uses its actual Source generic middleware
response. Admin stop-impersonating retains Source's empty401. Cached authority and
sensitive physical admission are unchanged. The existing owners are retained
without changing their Source expectations.

The other four failures were one organization observation7 timestamp/lifetime
alias, one remote JWT default-expiration observation, one raw API-key metadata
transport comparison and one raw multiple-session cookie comparison. These
clock failures are recorded exactly, without claiming a same-count parent rerun.
All13 original compact owners and15/16 new owners passed; the remaining new
admin owner passed its admission/SQL/hash controls and failed only metadata type.

Actual byte artifacts are retained at
`/tmp/issue221-source-raw-observation.json` and
`/tmp/issue221-native-raw-observation.json`; the real probe passed
`/tmp/issue221-raw-observation2.log`, exit0. Source's adapter decoded SQL JSON text
`null` to JSON null while the native physical model retained the original string.
Both fixtures now retain the actual stored metadata column and its typed JSON
value, without dropping any other key field or changing production. The Source
raw read binds the actual issued row ID as a SQL parameter; malformed native JSON
fails the observation rather than being replaced. The initial probe outside the
Devenv environment failed to load libssl before either parity half ran
(`/tmp/issue221-raw-observation.log`); it is not native parity evidence.

The actual invalid-capacity cookie payload and signature bytes matched and were
independently verified with HMAC-SHA256; both actual follow-up get-session reads
admitted only the issued owner/token. Raw strings differed only in attribute
ordering and Native's additional Expires alongside the same Max-Age. The SDK
capacity owner now independently verifies the HMAC, retains the complete signed
pair and performs the real follow-up read; all attributes remain in the existing
unchanged structured transport observer, which follows RFC6265 Max-Age
precedence. The full raw headers remain in the byte artifacts. Wider cookie
attribute parity remains171–177; no shared comparator was changed.

## Final immutable validation and capability retention

The complete canonical run on `3cd713008f02d395f88d6fec6af457370b32053a`,
based on Figma main `ff2cfec8`, terminated with exit 100:
`/tmp/issue221-final-canonical.log`. Both strict matrices, optional rustls build,
793/793 default native, 845/845 optional native, 2/2 fixture, 71/71 harness and
alignment 36/3/2 passed. Full SDK passed 1264/1265 owners with 83,614 assertions.
All 29 compact owners, all 3 Multi owners, every repaired organization/admin guest
owner and all 3 generated seed 12648430 profiles passed. The requested generated
owners also independently passed `/tmp/issue221-generated-guard.log`, exit 0.

The sole full SDK failure was `organization fixed membership policies retain
falsy defaults and raw Number admission without read callbacks`: observation 6
before/after session `expiresAt`, observation 7 member/response `createdAt` and
before/after session `expiresAt`, six timestamp/lifetime aliases. The unchanged
Facebook parent `83b57b1c` (tree identical to main 6803cbef) reproduced those exact
six paths in `/tmp/issue221-parent-organization.log`, exit 1,1/2 pass, 600 assertions.
The other owner, `organization addition trusted role patches are unvalidated and
before versus after errors retain exact writes`, failed four timestamp aliases
in the earlier 9b767 affected run but passed both unchanged parent attempts. Its
unchanged 9b767 focused retry retained only two member timestamp aliases; these
are not claimed as reproduced parent failures. That owner passed the full 3cd713
run and both later composed affected runs. Every failed and passing attempt is
retained; no comparator tolerance or test expectation was changed.

Clean actual coverage on 3cd713 passed `/tmp/issue221-final-clean-coverage.log`,
exit 0: 31,574/40,756=77.470802%, with all 845 native and all five existing SDK
coverage groups passing. The report has 210 Source paths and no duplicate logical
workspace file. Every workspace path belongs to the current checkout. Its six
inline standard TLS lines (three covered) also appear identically in the Figma
parent report; there is no added instrumented dependency surface. The genuine
five HTTP fixture runtime profiles are each1,387,760 bytes; the actual fixture
object is included in LLVM export. Runtime coverage includes cache/runtime 496/538,
auth 544/725,Apple 73/92 and Figma 79/100. Saved report:
`/tmp/issue221-final-clean-lcov.info`. The floor remains 75% with the original
exclusions and complete workspace selection.

The earlier 9b767 report 32059/41358 is explicitly rejected as clean proof because
it duplicated three logical files across cached 183/256/current paths. It and
a real runtime profile remain saved in `/tmp/issue221-9b767-lcov.info` and
`/tmp/issue221-9b767-runtime.profraw`. The unsupported `MBX_DISABLED` spelling
was corrected to `MBX_DISABLE=1`, documented by the installed 1.21.0 version's
[upstream troubleshooting guide](https://github.com/jdx/mr-boxington/blob/v1.21.0/docs/troubleshooting.md#bypass-mbx-for-one-command).
The first corrected attempt stopped at read-only cached dependency hardlinks
(`/tmp/issue221-figma-clean-coverage.log`, exit 101); its owned coverage directory
was archived rather than chmodding shared cache files. The successful clean run
used a fresh target and both explicit coverage target environment variables.

Real composed 32-owner collection passed 1,914 assertions in
`/tmp/issue221-composed-evidence.log`, exit 0. Its 16 new owners contribute 113
measured requirements across 32 relevant routes. Unrelated signup, organization
creation, device-code and JWKS setup traces were excluded from these additions.
All 4472 Figma-parent requirements remain; subsequent Hugging Face composition
retains all 4704 parent requirements plus the same 113, totaling 4817. No route or
implemented/upstream declaration was removed or altered.

Final composition `cc5aff553a6595e5b74a3314f45b0e102bd61a79` onto actual
Hugging Face main `4efe6df4` has no own production/test change by range-diff.
`/tmp/issue221-hf-composed-checks.log` and
`/tmp/issue221-hf-fixture-build.log` terminated 0: both strict matrices, rustls,
formatting, TS types, 845/845 native including the public two-context reader
regression, warning-free docs and Chromium 2/2 passed. Real affected SDK collection
`/tmp/issue221-hf-focused.log` terminated 1:225/226 pass, 17,620 assertions. All 32
compact/Multi, all 47 Hugging Face and all repaired guest owners passed. Only the
same six organization membership timestamp aliases remained. Coverage and the
full canonical are reported on their earlier exact 3cd713 head, rather than
misstated as having run on the later composed provider parent.

The standalone strict metadata gate remains red:
`/tmp/issue221-full-capability-check.log` and
`/tmp/issue221-hf-capability-check.log`, exit 1. Read-only aggregation of the exact
Figma-parent 4472 requirements against the full 3cd713 evidence and the merged
Hugging Face parent's actual full evidence found the identical 115 missing
requirements in both, with zero final-only or parent-only differences
(`/tmp/issue221-capability-baseline-comparison.json`). These include inherited
manual transition/category declarations beyond the two clock-owner cells.
Every new 113 requirement is supported by actual passing owner evidence. No old
artifact was injected, valuable test removed, or inherited declaration relaxed
to conceal this failure. Correcting those inherited classifications/transitions
will be a separate issue/PR with actual strongest owner traces.
