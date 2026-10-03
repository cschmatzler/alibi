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
