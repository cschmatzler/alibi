# Figma provider (issue #145)

Read-only authority: the installed unchanged Better Auth 1.7.6 public Figma
factory, declared FigmaProfile/FigmaOptions, authorization/code/refresh helpers
and OAuth Basic credential encoder. Actual application registration must call
that factory and redirect only its fixed remote HTTP destinations.

The factory requires client ID, client secret and a PKCE verifier, defaults to
current_user:read and www.figma.com/oauth, preserves configured/requested scope
order and duplicates, omits loginHint, and uses trusted authorize/redirect
configuration. Both code exchange and refresh target api.figma.com/v1/oauth/token
with form-encoded client credentials in HTTP Basic, not body credentials.
client_key belongs only in code exchange. Profile retrieval is bearer GET at
api.figma.com/v1/me; raw id owns account admission while handle/email/img_url map
the public user and verified-email defaults false. A mapper receives the original
profile. This factory supplies no ID-token verifier/JWKS/issuer/remote logout.

Authoring gate: the real public SDK owner protects missing factory defaults,
Basic code/refresh protocol, bearer GET, raw id binding and Figma field mapping.
Generic and Dropbox POST owners cannot exercise this actual initialization.
Configured factory modes extend one table; complete observed HTTP forms, real
SQL rows, foreign principals, callback replay, token rotation and local sign-out
remain in snapshots. Explicit account linking and existing account-info are
separate public operations. Controls return remote responses and observe actual
HTTP; they never fabricate successful admission or physical writes. No new
production seam exists only for tests. Unsupported general callback/projection,
malformed complex transport and advanced policies remain #181/#184/#188/#193.

The initial program passes strict API/fixture all-target Clippy and build. A
copied unsupported access-type case failed TypeScript checking and was removed
before owner execution. The corrected actual program passed 38/39 owners, with
1,394 assertions (`/tmp/issue145-corrected-real-owner.log`, terminal exit 1). Its
remaining Source-side linking expectation was wrong: default Figma unverified
email correctly returns unable_to_link_account, preserving the existing owner.
The linking owner now retains that denial, configured mapped verified admission
and mapped missing raw-id rejection. Source/comparer and production stay unchanged.

The expanded real program passes all 40 owners, 1,482 assertions
(`/tmp/issue145-expanded40-real-owner.log`, terminal exit 0). Its code/refresh
owners retain complete Basic headers with no body credentials, real PKCE
verifier/digest, original mapper input, account/user/session rows, foreign denial
before HTTP, replay, rotation and local sign-out. Explicit linking keeps default
unverified denial distinct from mapped verified admission and missing raw-id
denial; changed-profile account-info retains retrieval without re-admission.

The isolated actual fa8837ec parent uses unchanged production and the exact real
Source and HTTP fixture, adapting only the unavailable constructor to the old
public generic provider. It compiles, then the Source default authorization owner
passes while Native replaces current_user:read with requested scopes instead of
preserving all three ordered entries (`/tmp/issue145-generic-before-owner.log`,
28 assertions, terminal exit 1). The production/lockfile diff from fa883 is empty.
There is no missing constructor/404 or fabricated admission as before evidence.
Independent production review against the installed Figma factory and Basic
helpers found no concrete authorization, ownership or protocol concern.

Final immutable program head 568ff991cd1fb7a260c608b1aeaa5ea8de02a869 is
composed on actual main 6803cbef. The rebase preserves all Facebook providers,
profiles and evidence; Figma production and owners match the independently
reviewed program. The final audit-only commit does not change executable inputs.

The canonical `devenv shell -- bash scripts/check.sh` run exits 100
(`/tmp/issue145-main144-final-canonical.log`): default and optional strict Clippy,
Rustls check, both format checks, all 794 default and 845 optional native tests,
fixture tests, TypeScript and 71 harness tests pass. Actual full SDK run passes
1,244/1,249 owners with 82,244 assertions, including all 40 Figma owners. The five
remaining failures are two organization clock comparisons and three generated
seed12648430 snapshot22 UNAUTHORIZED/AUTHENTICATION_REQUIRED comparisons owned
by #221. The role-addition failure is exactly observation5 member.createdAt in
its after receipt and result body. The membership-policy failure is exactly
observation7 snapshot.members7 and response createdAt plus usersBefore/usersAfter
session3 expiresAt. These are outside Figma; no claim is made that every clock
path has an independently failing parent proof. The full canonical run is not green.

Warning-free docs and both genuine Chromium browser owners pass, 22 assertions
(`/tmp/issue145-main144-docs-browser.log`, exit 0). A separate clean instrumented
run passes all 845 native tests and completes all five SDK groups with
--no-fail-fast; four groups pass and the JWT group fails existing keyring clock
comparisons (`/tmp/issue145-main144-clean-coverage.log`, exit 100). Eighteen
createdAt/expiresAt aliases in legacy, manual and recovered keyring events and
physical keys differ by approximately 2.7 seconds. This failure remains recorded,
without an exact before counterfactual for all eighteen paths. The complete
unchanged report then passes the existing 75% floor at 31,284/40,535 native lines
(77.177748%; `/tmp/issue145-main144-coverage-report.log`, exit 0). A passing floor
is distinct from the nonzero instrumented SDK suite; no repeat-until-green claim.

All 4,285 parent capability cells retain their original order. Append 187 Figma
cells from 38 actual successful Source/native scenarios; every new cell is
verified against the final canonical evidence directory. Foreign setup and
misleading success labels on redirected negative callbacks are excluded. No
Source/comparer edit, dependency patch, lint suppression or hook bypass.
