# LINE provider (issue #149)

Authority is the unchanged installed Better Auth1.7.6 LINE public factory,
LineUserInfo/LineIdTokenPayload/LineOptions and real helpers. Application uses
that factory; local endpoints redirect only its fixed HTTP destinations.

Authorization uses access.line.me/oauth2/v2.1/authorize with ordered duplicate
preserving openid/profile/email, configured/requested scopes, PKCE, loginHint
and trusted application endpoint/redirect overrides. Code/refresh use secret-post
or public forms at api.line.me/oauth2/v2.1/token; client_key is code-only.

Direct ID-token verification delegates to real form POST /oauth2/v2.1/verify:
id_token,client_id and truthy supplied nonce. Error/no data rejects; returned aud
must strictly equal the client ID, and a truthy returned nonce must strictly
equal the supplied nonce. There is no factory-local JWKS/signature/issuer/age
policy; those checks belong to the actual remote verifier. getUserInfo decodes
an available compact JWT payload without a second verification; failed decode
falls back to bearer GET /oauth2/v2.1/userinfo. Browser code-exchange ID tokens
use that same decode path. Preserve the actual factory distinction rather than
inventing local verification or dropping the remote verification receipt.

Raw original profile.sub owns identity independently of mapper.id. User name
uses truthy name or empty string, email/picture map from profile, verified-email
is false unless mapped. Original profile is retained; existing account-info is
retrieval without new identity admission. No remote logout is supplied.

Authoring gate: actual factory/client/HTTP owners protect LINE's delegated proof,
strict returned client/nonce binding, decode versus fallback, supported loginHint
and raw identity/default scopes. Existing local-JWKS and no-verifier providers
cannot exercise those contracts. Retain full HTTP/PKCE/mapper/physical/foreign
rows, state/replay and rotation/local logout. No private predicate tests or
production seam used only by tests. Advanced discovery, malformed complex field
projection and asynchronous hook composition remain #181/#184/#188/#193.

Initial API and real fixture all-target strict Clippy, formatting and TypeScript
pass. The first script/owner attempts retain their exact outcomes: two bounded
production lint corrections, a TypeScript inferred-record field mistake and an
incorrect SDK error type stopped before runtime; the first actual70 collection
passed58 with12failures. Its five browser failures were incorrect expectations
of space-separated persisted scopes (actual Source joins with commas); six direct
account-info failures were actual ACCESS_TOKEN_NOT_FOUND because no access token
was supplied. A per-half token issuance second also caused an expired JWT lifetime
comparison; the real signer now uses one actual module issuance time, as the
existing credential owner does, with no clock substitution or comparator change.
These are recorded as fixture/oracle findings, not product regressions.

The corrected real70-owner collection /tmp/issue149-corrected70-real-owner2.log
terminates1:69pass/1fail,2,450assertions. All delegated remote proof cases,
cryptographic signature/issuer/audience/expiry denials, strict returned-audience
and returned-nonce controls (including truthy nonstring values with absent caller
nonce), false nonce admission, actual PKCE/grants, decode/fallback distinctions,
raw-subject mapping and foreign isolation pass. Remote proof uses actual JOSE
verification on Source's real HTTP service and independently HMAC-verifies native
remote credentials; the factory itself delegates and binds the response.

The sole retained owner failure is observation.info.data.user.id in the mapped
signed direct account-info case: Source returns the mapper-added ID, while the
pre-existing Native AccountInfoUser response type retains only name/email/image/
emailVerified. Full observations remain; no field or assertion is dropped. This
additional output-projection contract is being independently audited against184,
not repaired with a provider-specific serializer workaround. Default and public
account-info behavior, mapped physical identity and original raw-subject binding
pass. The mapped owner's failed artifact supplies no capability evidence.

Actual unchanged40bf31b2 production with genuine fixture registration and the old
public generic constructor fails default authorization for exactly missing
openid/profile/email before requested scopes, /tmp/issue149-generic-before-owner.log,
exit1/28assertions. Source passes first; Native replaces defaults. Production
and application Cargo.lock are unchanged. The genuine remote service's HMAC
fixture dependency/lock entry is test support, not a patched dependency.

Preserve all5,189 parent requirements and append257 actual passing trace cells
from68owners, totaling5,446. The raw captures are retained. Independent review
and final broad gates remain pending. No Source/comparer edit or hook bypass.


Independent factory/fixtures/shared-owner review found no security or admission
blocker. It confirmed the genuine mapped-ID failure is shared output-presence
support: blindly adding an ID would regress ordinary LINE, whose published
getter omits ID until a mapper adds it. A provider-name flag or dropped field is
not an acceptable repair. The full failing owner remains assigned to184.
Final frozen code is composed on the tested Kick stack over actual signed-header
main2bf51a60 (including147/221/135). It preserves all5,339 stack-parent requirements
plus the257 measured passing LINE cells,5,596total, and all parent fixture
profiles. The own production/test hunks are unchanged across this composition.

Final broad proof was captured on immutable bfab5de67feab7346f0ef5cdcb6481d4b9d8b3bd:
canonical scripts/check.sh terminates100 at the full SDK alignment stage,
1,491/1,496 owners and93,772assertions. Both workspace strict Clippy configurations,
rustls check, both formatting checks, native default793/793 and optional845/845,
fixture2/2, TypeScript, harness72/825 and alignment inventories36/3/2 pass first.
The five retained full SDK failures are two existing organization timestamp
owners, the LINE mapped-ID projection above, four JWT keyring creation/expiry
aliases, and verification reset proof length24versus32 (#174). No full-pass claim
is made. The organization role-addition observation4/12 alias combination has
no claimed exact parent counterproof; the other membership/keyring findings
have separately recorded exact owner controls. No failing owner was removed.

Fresh scoped MBX_DISABLE=1 clean coverage completes all native845 tests and all
five SDK groups without fail-fast:639/640 owners,23,504assertions,4/5 groups pass;
the OAuth group retains the same mapped-ID projection failure and the overall
coverage script exits100. Its separate unchanged-floor report passes:
32,091/41,558 lines=77.21978921026036%,215 logical SF records,zero duplicate paths.
Native fixtures are genuinely included, with unchanged75%floor and exclusions.
Warning-free workspace documentation and actual Chromium flows pass2/22.
Logs: /tmp/issue149-final-canonical.log, /tmp/issue149-clean-coverage.log,
/tmp/issue149-clean-coverage-report.log and /tmp/issue149-docs-browser.log.

After all jobs became terminal, compose the unchanged own production/test
hunks on actual main4bcd25c3084ac16b39c96b8dc42804f80dc21900.
Frozen a0903d84ee2c578443ce22bf06f21318de1ff9d2 passes both formatting checks,
TypeScript, full harness73/903 and rebuilt real LINE owner collection69/70,
2,450assertions; only the same mapped-ID projection remains.
/tmp/issue149-main288-composed-checks.log terminates1 honestly.
All5,339 actual main evidence cells are preserved, plus257 freshly measured
cells from68passing LINE owners=5,596. Every added cell is independently checked
against the frozen passing artifacts, and the failing mapper-added-ID owner
supplies no committed evidence. No Source/comparer edits, compatibility shims,
timestamp tolerance, dependency patches, policy bypasses or hook bypasses.

Current-main recovery preserves the historical checkpoints above. Rebased from
6d994b48 onto actual main f48d546eb81b058afa32e67a7cc7c0068348e7e8; moved
LINE's scenario and Source/native fixtures into the established social/fixtures
layout without a registration exemption. The shared #184 mapped-public-output
contract now captures mapper-added ID independently of original profile.sub;
ordinary LINE still omits ID from account-info. The mapper uses the same
public_profile(true) owner contract as sibling providers, with initialized
additional fields retained. Existing factory, SDK, comparator and pin unchanged.

Recovery typecheck passes. First native fixture Clippy stops at the moved
fixture's pub(super) visibility; update to the established pub(crate) scope.
The two independently started actual Source fixtures pass all 70 complete LINE
scenarios and 2,450 assertions. Current harness passes all 86 negative-control
tests and 2,314 assertions, including live Source publication/cookie controls.
Log: /tmp/pr289-source-self-harness.log. Source-self creates no Rust capability
evidence. Full Source/native and canonical gate proof are still pending.

The recovered actual Source/native owner collection completes 70/70 with 2,450
assertions at checkpoint 77b295b24ff69bd2b4cc68b543655671c273c486 over f48d546e
(/tmp/pr289-focused70.log). Rebase onto current managed-secret main
74309f369bc6d7b600af02332190dd4edb04eec6 retains both managed and LINE
registration. Fresh actual Source/native capture again passes all 70/70 and
2,450 assertions (/tmp/pr289-current70-evidence.log), including ordinary
account-info omission and mapper-added ID without changing raw account identity.

The unchanged current harness measures 370 raw LINE trace cells. Independently
check every committed LINE cell against the fresh captures and preserve all
5,742 current-main requirements. Retain the existing 257 LINE owner cells and
append the five actual account-info/sign-in cells from the repaired mapped owner:
262 LINE cells from 69 required owners, 6,004 total requirements. Setup signup
and session-read traces do not receive new claims; existing owners cover those
contracts. No fields, assertions, owner scenarios or full captures are dropped.

Authorization/data-exfil review traces original-subject resolution before
sign-in/link writes and the authenticated account resolver before reads/refresh.
Trusted application configuration alone supplies HTTP endpoint overrides. The
real delegated verifier checks signature, issuer, expiry and nonce; the LINE
factory binds its returned audience/nonce and retains Source's separate trusted
code-grant decode behavior. No review blocker found. The canonical current-main
scripts/check.sh gate and its clean instrumented coverage remain pending.

The first current-main canonical invocation on frozen 1302eb24 terminates 1
at TypeScript formatting after both workspace strict Clippy configurations and
the rustls build pass. The prior formatting command ran from the repository
root and missed tests/compat/.oxfmtrc.json. Apply the canonical compatibility
formatter to LINE's scenario only after that invocation is terminal; the full
294-file formatting check passes. No production, assertion or comparator change.
Exact log: /tmp/pr289-canonical-check.log; repair: /tmp/pr289-format-repair.log.
Restart the complete scripts/check.sh directly on the repaired frozen tree.

The next canonical invocation on 1beb9c46 terminates 1 at the subsequent
TypeScript lint stage: the preserved old LINE scenario/Source fixture used
multi-variable declarations and multiline unbraced controls. Repair those two
files only, with no assertion, registration, policy or dependency changes.
Whole-project canonical format:check, lint and typecheck run together and all
pass (/tmp/pr289-all-client-statics.log). The repaired scenario also passes
70/70 genuine Source-self owners with the same 2,450 assertions
(/tmp/pr289-source-self-final-style.log). Second early-stop log:
/tmp/pr289-canonical-final.log. Restart the full gate on this validated style.

After the T3 update, the complete gate on 5d9fb40b is interrupted by SIGTERM
while the SDK browser fixture compiles; preserve /tmp/pr289-canonical-complete.log.
A fresh unchanged canonical invocation with isolated /tmp/better-auth-pr289-target
terminates 100 at the full SDK stage: 1,713/1,714 scenarios and 119,478 assertions.
All 70 LINE owners pass; the sole failure is the current-main remote-JWT null
application-signer owner, with four literal exp differences. Both strict Clippy
configurations, rustls, format/lint/typecheck, native 788/788 and optional 841/841,
fixture 2/2, doctests, route inventory, harness 89/2,367 and Chromium 2/22 pass
first. Exact log: /tmp/pr289-resumed-canonical.log. The script stops before
its documentation and coverage stages. An auxiliary warning-free documentation
run passes; its coverage compile is deliberately interrupted before SDK work
while the shared owner is investigated (/tmp/pr289-resumed-docs-coverage.log).
Neither interrupted nor partial invocation supplies a canonical-pass claim.

Actual unchanged pinned signJWT uses its 15-minute default for exp:null with
nullish iat, retaining iat:null. Independently authenticated complete request,
original signed response and callback receipts reproduce a one-second expiry
difference three times with Source/Source and three with Source/native;
explicit iat:100 controls produce exact exp:1000. Windows use actual HTTP start
and finish times; no clock is substituted. Complete original proof remains at
/tmp/pr289-null-exact-receipts.json. The exact unchanged owner repeats naturally
12/12 Source-self and 10/12 Source/native; two native failures have the same
four exp paths (/tmp/pr289-null-owner-repeat-results.json). Delaying only the
second actual sign request across a natural second boundary makes the unchanged
Source-self owner fail 3/3 with those four paths and 20 assertions per run:
/tmp/pr289-null-source-self-boundary-{0,1,2}.log. Full original HTTP input,
signed output and callback capture: /tmp/pr289-null-source-self-boundary-receipts.json.
This is executable Source-self before proof, not a product mismatch or a
provider-specific exemption.

The reviewed repair preserves every original token, exp, iat and callback field.
A private transport receipt binds the exact observed raw-profile POST sign input,
null exp/iat, signing overrides and header to the original signed response and
request interval. Independent HMAC verification retains the real HS256 signer
and key policy. The full signed claims must equal the exact projected input and
actual observer callback, including original ownKeys/header/options; proof copies
must reference the original token. Only four complete producer-bound observation
paths can admit the exact request-derived 900-second default. Unrelated claims,
explicit caller expiry, other profiles and all other comparison paths remain
literal. Production, installed Source, fixtures, dependency pins, main evidence
requirements and coverage scripts/floors are unchanged.

The new comparator owner uses the actual installed public signJWT and real
application signing callback over HTTP, rather than a fixture supplying expiry.
It first requires the four before-drift paths, then passes 33 assertions while
rejecting coherent re-signed wrong expiry/outside-window claims, literal explicit
expiry even at a coincidental signing epoch, changed iat/profile, altered copies,
foreign signing keys/headers, missing receipts and unrelated application data.
Authoring gate: this distinct owner protects comparator admission and original
publication integrity, which LINE or JWT SDK success alone cannot enforce; it
adds no production seam. Before failure: /tmp/pr289-null-harness-before.log.
After proof: /tmp/pr289-null-harness-after.log and /tmp/pr289-null-focused-pass.log.
The first formatting/typecheck iterations retain their terminal outcomes at
/tmp/pr289-null-statics.log, /tmp/pr289-null-statics-repair.log and
/tmp/pr289-null-statics-final.log; final format/lint/typecheck passes at
/tmp/pr289-null-statics-pass.log. No source or test is edited during a running
Bun scenario collection.

Focused complete harness now passes 90/90 and 2,400 assertions. The exact natural
boundary Source-self owner passes 3/3 with retained raw signed outputs:
/tmp/pr289-null-source-self-after-boundary-{0,1,2}.log. Actual Source/native
combined LINE and remote-JWT owners pass 85/85 with 2,908 assertions
(/tmp/pr289-null-line-native-proof.log); another twelve Source-self and twelve
Source/native exact-null runs all pass (/tmp/pr289-null-after-owner-repeat-results.json).
Independent requirement recount preserves all 5,742 parent entries, including
four existing parent duplicates, plus 262 actual LINE additions: 6,004 entries,
6,000 distinct triples. Every addition is independently backed by the retained
370 raw LINE trace cells (/tmp/pr289-independent-requirement-recount.json).
The complete unchanged canonical gate is still required after this repair.

The genuinely detached unchanged canonical gate on e137195c terminates 100:
/tmp/pr289-post-repair-canonical.log and its atomic .exit marker. Static gates,
default native 788/788, optional native 841/841, fixture 2/2, doctests,
route inventory, harness 90/2,400, Chromium 2/22, full SDK 1,714/1,714
with 119,478 assertions, all four process-environment suites and documentation
pass. Coverage native 841/841 passes, but instrumented core stops at 1,022 pass,
one fail and 50,418 assertions: the existing dispatch media/syntax owner has
physical session expiresAt drift of 2.15 seconds. Six remaining instrumented SDK
groups do not run after fail-fast. This is not a complete canonical pass.

Independent pinned LINE factory review finds a concrete public-profile gap:
default name/picture retain numeric JSON values, explicit null picture remains
null, absent picture is omitted, and null/absent name becomes the empty string.
Native default publication had used the typed persistence projection. Extend the
existing nine raw-profile mapping owners, preserving their original SQL/session
assertions, to exercise the genuine owned SDK account-info endpoint. Each also
checks foreign denial without remote traffic or writes, exact public user/raw
profile/account shape, literal bearer GET receipt, complete unchanged physical
state and foreign authority. Before production repair, actual Source/native
has six pass and three fail with 480 assertions: numeric name is stringified,
null image is omitted and numeric image is stringified. Exact proof:
/tmp/pr289-default-publication-native-before.log. Two actual Source servers pass
all nine with 504 assertions:
/tmp/pr289-default-publication-source-self-before.log.

LINE now supplies default public JSON through the existing user_output channel,
as its mapped profile already does. This preserves raw name/email/picture types
and explicit nulls, Source's truthy-name fallback and false emailVerified. Typed
persistence conversion, mapper behavior and original raw account subject remain
unchanged. Authoring gate: the existing mapping owners are the strongest genuine
SDK boundary for this distinct publication regression; physical typed storage
alone could not catch it, and no test-only production seam is added. No scenario
is duplicated or original assertion/capture removed. Initial strict formatting
failure is retained at /tmp/pr289-default-publication-native-build.log; canonical
format plus fixture build passes in native-build2.log.

The repeated dispatch coverage failure is independently reproduced with actual
Source servers through the existing dispatch profile, genuine SDK signup and
get-session, multipart and form password sign-ins, authenticated original HMAC
cookies and the real narrow SQL observer. Delaying the real second-runtime media
request makes the original comparator fail only two physical expiry paths, with
32 assertions: /tmp/pr289-dispatch-clock-before.log. Complete original transport,
signed cookies, immutable SQL bodies/digests and actual request windows remain
outside the checkout at /tmp/pr289-dispatch-clock-original-receipts.json. Installed
Source's default session policy is seven days; dispatch inherits that policy
without a session override. Each actual stored expiry minus exactly 604800000
milliseconds independently falls inside its authentic issuing request interval.

The shared comparator repair adds only dispatch-default beside org-member-addition
in the existing narrow seven-day producer allowlist. Exact signed token/user,
signature, both complete SQL observations, owner and request-window guards remain
required. The global 1,500 ms fallback is unchanged. The actual Source clock owner
protects this distinct narrow-observer admission contract while every existing
synthetic canary control remains. Its coherent wrong-lifetime, foreign token and
owner SQL counterfactuals plus invalid signature, foreign profile, missing SQL
observation and tampered digest each require denial at the exact physical expiry
path. It adds no production or observer seam and no fixed artifact-file write.
Focused actual owner passes 39 assertions; combined unchanged canary plus owner
passes 8/8 and 164 assertions. Logs: /tmp/pr289-dispatch-clock-final-focused.log
and /tmp/pr289-dispatch-clock-after2.log. Earlier typecheck iterations retain
terminal results in dispatch-clock-after.log. Right-runtime real delay includes
the measured left issuance offset to preserve actual greater-than-1,500 ms drift
under load rather than supplying fabricated timestamps.

After both repairs, actual Source/native and Source/self LINE collections each
pass all 70 scenarios and 2,720 assertions:
/tmp/pr289-default-publication-line-native-after.log and
/tmp/pr289-default-publication-line-self-after.log. Full harness passes 91/91
with 2,439 assertions (/tmp/pr289-default-publication-harness-after.log).
Canonical TypeScript format/lint/typecheck and Rust fixture strict Clippy/fmt
pass (/tmp/pr289-default-publication-statics.log,
/tmp/pr289-dispatch-clock-final-focused.log,
/tmp/pr289-default-publication-rust-static.log). No source or test is edited
while a Bun collection runs.

Only 27 actually measured GET account-info success/rejection/state cells from
those nine retained mapping owners are newly claimed. Independent recount now
preserves all 5,742 parent entries and four original duplicates, plus 289 LINE
additions from the same 69 required owners: 6,031 entries and 6,027 distinct triples.
Every LINE addition is backed by 397 raw measured cells, retained at
/tmp/pr289-default-publication-measured-cells.json; full requirement recount is
/tmp/pr289-default-publication-independent-recount.json. The latest complete
LINE evidence/oracle captures are preserved outside canonical cleanup in
/tmp/pr289-default-publication-preserved-artifacts. A fresh unchanged complete
canonical gate is required after freezing these repairs and integrating any
independently reviewed shared clock fix from the concurrent open-PR batch.
