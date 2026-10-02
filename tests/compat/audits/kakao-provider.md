# Kakao provider (issue #147)

Authority is the unchanged installed Better Auth1.7.6 Kakao public factory,
KakaoProfile/KakaoOptions and actual authorization/code/refresh helpers. The
application must use that public factory; local transport redirects its real
fixed destinations and returns remote responses without inventing admission.

Authorization defaults to kauth.kakao.com/oauth/authorize and ordered
account_email/profile_image/profile_nickname before application/requested scopes,
preserving duplicates and disabled defaults. This factory omits PKCE and
loginHint even when the ordinary social flow creates a verifier. Required client
ID supports secret-post or public code/refresh forms at kauth.kakao.com/oauth/token;
client_key is code-only. Bearer GET kapi.kakao.com/v2/user/me maps nested account:
name is truthy profile.nickname then account.name then empty, image is truthy
profile_image_url then thumbnail_image_url, email is account.email and verified
is boolean truthiness of both is_email_valid and is_email_verified. Original raw
profile.id owns admission independently of mapper.id. No ID-token verifier,
JWKS/issuer/nonce check or remote logout is supplied by this factory.

Authoring gate: actual published public-client registration, missing default
scopes/no-PKCE and nested Kakao mapping are distinct observable contracts that
existing providers do not exercise. One table extends those real options and
profile fallbacks. Retain actual full HTTP forms, raw mapper profile, physical
user/account/session rows, foreign authority, callback replay, refresh rotation
and local logout. Linking and account-info retain their separate public
boundaries. No private predicate owner or test-only production export is added.
Malformed complex projection/async-hook/advanced runtime policies remain bounded
by #181/#184/#188/#193 instead of claiming arbitrary JavaScript equivalence.

Strict API and fixture all-target Clippy, formatting and TypeScript pass. The
actual complete public table passes all58 Source/native owners on its first
executed run,2,016assertions (/tmp/issue147-initial-real-owner-strict.log,exit0).
This retains nested numeric/null/absent/empty/zero/false fallbacks, independent
raw subject and foreign whole-row ownership, exact no-verifier code grants,
secret/public exchanges, rotation/replay, browser linking and account retrieval.

An unchanged3077a96e actual parent with only the genuine fixture and old public
generic constructor compiles; Source preserves all three defaults followed by
requested scopes, while Native replaces them (/tmp/issue147-generic-before-owner.log,
28assertions,exit1). Production and both lockfile diffs from this parent are empty.
This is the intended observable regression, not a missing constructor or404.

Independent review of actual factory/helpers, production and both fixtures found
no blocker. All4,704 parent capability cells retain their order; new Kakao cells
come only from successful real Source/native traces. All287 additions are verified against final canonical artifacts; no prior cell
is lost or reordered. The measured program32b702f80fdd908ec312fcff3e7f46474ce72ff0
was rebased onto actualmain4efe6df4 as9d0b165e: only the already merged Hugging
Face audit differs, with all executable production/fixtures/owners/locks and
capabilities byte-identical. The final audit-only commit changes no runtime input.

Actual canonical `devenv shell -- bash scripts/check.sh` exits100 at full SDK
(/tmp/issue147-final-canonical.log). Default/optional strict Clippy, Rustls, both
format checks,794default/845optional native tests,fixture2,TypeScript and71harness
tests pass. Full actual SDK passes1,350/1,354owners with86,000assertions including
all58 Kakao owners. Four failures remain: fixed membership-policy's six timestamp
aliases and three generatedseed12648430snapshot22guard comparisons tracked by
#221. Exact timestamp aliases are observation6 usersBefore/usersAfter session3
expiresAt, observation7 usersBefore/usersAfter session3expiresAt, snapshot.member7
createdAt and response.createdAt. Allsix exact membership paths reproduce in the
independent unchangedFacebook parent run retained by #221. This does not claim
arbitrary organization clock paths are proven or that full canonical is green.

Warning-free docs and both real Chromium browser owners pass,22assertions
(/tmp/issue147-docs-browser.log,exit0). Clean scoped MBX_DISABLE=1 instrumentation
with both isolated target variables passes all845native and allfiveSDKgroups
(/tmp/issue147-clean-coverage.log,exit0). Complete212-source report contains no
duplicate logical workspace paths and passes the unchanged75%floor at
31,495/40,789native lines (77.214445%). No missing-owner/compiler failure is used
as before evidence, and no Source/comparer change, dependency patch, suppression
or hook bypass is introduced. No Source/comparer edits or hook bypasses.
## Composition with the merged compact-cache repair

Frozen20a7680b9dfe720ee08cff10315b8b491c0cdd52 is based on actual main
16205b5b0e99f69899cf84ac71b11be64c362dba. Its own production/owner hunks
remain unchanged; the actual221 guard and profile registry are retained.
Both strict matrices, rustls, formatting, TypeScript,71harness and all845
feature-native tests pass /tmp/issue147-main221-composed-checks.log,exit0.
The genuinely rebuilt fixture and actual Source/native Kakao table pass all58
owners and2,016assertions. Every4,817 merged-parent evidence requirement remains,
in original route order, alongside the287 measured Kakao additions:5,104total.
An initial merge-union script failed its count assertion before writing; no gate
ran against that intermediate state. The union was regenerated from immutable
parent/own refs, independently checked for retention and squashed into the own
code commit before this frozen validation. All old canonical/coverage outcomes
above remain attributed to their actual earlier measured heads.
