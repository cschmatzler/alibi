# Kick provider (issue #148)

Authority is the unchanged installed Better Auth1.7.6 Kick public factory,
KickProfile/KickOptions and actual authorization/code/refresh helpers. Its
application must register the real public factory; transport redirects only
fixed remote destinations and returns their responses without inventing rows.

Authorization uses id.kick.com/oauth/authorize with ordered duplicate-preserving
user:read before application/requested scopes, PKCE, ignored loginHint and trusted
application authorization/redirect overrides. Code/refresh use secret-post or
public forms at id.kick.com/oauth/token; client_key is code-only. Bearer GET at
api.kick.com/public/v1/users returns an envelope; the factory selects its first
data profile, uses raw user_id for account identity, and maps name/email/
profile_picture with verified-email false unless mapper overrides it. Mapper
receives the selected original profile, independently of account-subject logic.
There is no built-in ID-token verifier, JWKS/issuer/nonce policy or remote logout.

Authoring gate: one actual factory/client table owns Kick defaults, public/secret
forms, selected-first-profile response and raw user_id admission; generic and
nested Kakao owners cannot exercise that public initialization and envelope.
Retain actual full HTTP forms, PKCE digest, original mapper profile and complete
physical rows, foreign identities, state/replay, refresh/rotation and local
logout. Linking and account retrieval retain distinct operation contracts.
No private predicate tests or production exports used only by tests are added.
Complex malformed projections/async callbacks/advanced policies remain bounded
by #181/#184/#188/#193 instead of claiming arbitrary JavaScript emulation.

Strict API/fixture all-target Clippy and formatting passed. An initial script
failed to generate the new SDK owner and returned127 after strict TypeScript;
that log is retained and does not claim an executed owner. The corrected program
passes all40 actual Source/native owners with1,582assertions
(/tmp/issue148-corrected-real-owner.log,exit0). Every remote profile envelope
contains a second valid unselected profile, so success and missing-first-subject
controls prove first-only selection rather than fallback. All full receipts,
raw mapper input, physical and foreign rows, verified mapping/linking policies,
replay/rotation and local logout remain observed.

Independent factory/helpers/production/fixture review found no blocker. Preserve
all4,991 parent cells and append only actual passing Kick trace constraints.
The unchanged actual32b702f8 parent, with only the genuine fixture and its old
public generic constructor, compiles and fails default authorization for the
intended missing user:read default before requested scopes. Source passes first;
Native replaces the default (/tmp/issue148-generic-before-owner.log,28assertions,
exit1). Production and both lockfile diffs are empty. Independent review already
confirms the actual first-profile boundary and original identity binding.
No Source/comparer edit or hook bypass.

## Immutable final evidence

Code head4e27416638adbf7f9875fe41975c8083500f8d9c and its documentation-only
publication40bf31b21f3dbffa06c91626f3dd05d58927c199 share the measured program.
The complete canonical /tmp/issue148-final-canonical.log terminated100: both
strict matrices, rustls, formatting,794default/845optional native,2fixture,
TypeScript,71harness/754assertions and alignment36/3/2 passed. Full SDK passed
1389/1394 with87,582assertions in797.91seconds. All40 Kick owners passed.

Five unrelated failures remain recorded. Organization trusted-role observation5
after receipt/result member.createdAt differed by3.342seconds; these two exact
paths are not claimed as reproduced on an unchanged parent. Membership
observation6 before/after sessions.3.expiresAt and observation7 member/response
createdAt plus before/after sessions.3.expiresAt are the six timestamp aliases
independently reproduced on unchanged83b57b1c by221. The three generated
seed12648430 profiles retain the known guest guard code/message mismatch assigned
to221, which subsequently landed separately. This full exit100 is not called
green, and no clock allowance, comparator tolerance or repeated-until-green run
was introduced.

Independent warning-free docs and real Chromium browser2/2 (22assertions) passed
/tmp/issue148-docs-browser.log,exit0. Clean coverage completed all845 native and
all five existing SDK groups, /tmp/issue148-clean-coverage.log,exit0:
31,577/40,892=77.220483%, unchanged75% floor/exclusions. Its213Source paths have
zero duplicate logical workspace files; genuine fixture runtime profiles and
the actual fixture object contribute to the report. It used a fresh owned
coverage target and the supported MBX_DISABLE=1 cache setting without modifying
shared cache artifacts.

All4,991 parent capability requirements remain, plus198 actually measured
constraints from39Kick owners, totaling5,189. Every addition is present in the
final canonical passing evidence. This asserts the measured additions and
retained inventory; it does not claim a green strict gate for the separately
identified115 inherited missing metadata requirements. Exact-main composition
after147/221 is recorded below.

## Final ordinary-main composition

Frozen9be3a191d17caa123cb21b7fcc5137e1ac386be0 on Kakao/221 mainfb8f6597
passes both strict matrices, rustls, both formats, TypeScript,71harness and all845
native feature owners, plus the rebuilt genuine40Kick table/1,582assertions:
/tmp/issue148-main147-221-composed-checks.log,exit0. This preserves all5,104
parent requirements plus198Kick additions,5,302total.

After135 landed, frozend61ce80c7791d5c0e407400756345a6511d52978 on actual
2984354a passes feature all-target strict Clippy, formatting, TypeScript,
71harness and freshly rebuilt40Kick owners/1,582assertions:
/tmp/issue148-main135-composed-checks.log,exit0. Every5,141 parent requirement
remains alongside198Kick additions,5,339total. The password plugin and its
public context changes come exclusively from the ordinarily merged135 parent.

Final frozen53056ce026f5de1cfccd2bd2b93d35effbd27081 is based on signed-header
main2bf51a600d053ea7d1f48d56af25f5d967ee5dce. Its own production and SDK owner
hunks remain unchanged; that comparator-only rebase adds no native delta.
TypeScript, the complete retained72harness/825assertions and genuinely rebuilt
40Kick table/1,582assertions all pass:
/tmp/issue148-main135-286-final-composition.log,exit0. Final publication adds
only this composition audit. Earlier full canonical/clean-floor/docs/browser
results remain attributed to their exact original head rather than inferred
as a new complete collection on the composed parent.
