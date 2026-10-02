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
come only from successful real Source/native traces. Full canonical evidence,
broad strict/docs/browser and clean unchanged-floor coverage are pending. No Source/comparer edits or hook bypasses.
