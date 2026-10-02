# Dropbox provider (issue #143)

The authority is the installed unchanged Better Auth 1.7.6 Dropbox factory,
declared profile/options, shared authorization/token helpers and raw account
resolver. Source calls that actual public factory, redirecting only its fixed
token and profile destinations to actual local HTTP. Native uses public
DropboxOptions with trusted application transports. Controls supply remote
responses; the real factory creates authorization, exchanges codes, retrieves
profiles and writes physical accounts. Receipts observe actual HTTP, complete
rows come from the existing physical SQL observer, and foreign principals remain
in the same application database.

The authoring gate owns this missing factory's defaults, ordered configuration,
token_access_type, POST profile protocol and stable raw account_id. Generic
OAuth cannot prove that initialization; Cognito's GET profile owner cannot prove
Dropbox's POST protocol. Real callback owners retain PKCE digests, token forms,
mapper input, whole physical rows, replay, foreign denial before remote requests,
rotation and local sign-out. Explicit browser linking protects an existing local
principal independently of social creation. Existing account-info retrieval
does not re-admit a newly omitted raw subject. No production test seam, synthetic
admission, Source edit or comparison allowance is introduced.

## Native contract and bounds

The dedicated constructor uses www.dropbox.com/oauth2/authorize,
api.dropboxapi.com/oauth2/token and a bearer POST without a body to
api.dropboxapi.com/2/users/get_current_account. Scope defaults to
account_info.read; application and requested scopes follow in order and retain
duplicates. Disabled defaults can omit scope entirely. Offline, online and
legacy token_access_type are explicit; nonreserved caller parameters can replace
the application access type. Configured authorize/redirect endpoints preserve
the actual shared URLSearchParams replacement and form encoding. A primary
client is required. Secret clients use a bound client_secret POST; public clients
omit it. Optional client_key belongs only in the authorization-code form because
the pinned refresh helper ignores it.

The mapper receives the original profile. Default name is name.display_name,
image is profile_photo_url, email is email, and verified-email defaults false.
The original account_id resolves the physical account at admission; a mapped id
cannot replace it. Supported scalar strings/numbers/booleans retain the native
storage representation, with missing/null optional names/images represented by
None and empty strings preserved. Blank/null/missing raw identity is rejected
before writes. General optional JSON property presence and arbitrary additional
mapped fields remain the schema/projection scope of #184; async mapping,
application callback error composition and malformed complex values remain
#181/#188/#193 rather than invented JavaScript behavior in this typed factory.
The generic returned provider still accepts its existing asynchronous user-info
and refresh callbacks, and signup policies.

This factory supplies no ID-token verifier, issuer/JWKS/nonce policy or remote
logout. Real direct ID sign-in is denied before any HTTP or identity write.
Actual sign-out is local. Shared token helpers retain absent/zero expiry as null,
fractional expiry, missing response scope as an empty persisted string, and
existing scope through refresh. The factory does not forward basic/custom token
authentication; no unsupported Source basic mode is claimed.

## Measured draft proof

The initial 43 owners passed 40/43 (1,598 assertions,
/tmp/issue143-initial-43-owner.log). The missing-email expectation was corrected
to the actual Source email_not_found channel; Source and comparator remained
unchanged. Two genuine Native failures store the email as name for null or
absent names instead of Source's empty name. The owner fix already belongs to
#183, whose generic OAuth creation phase supplies an empty name. Dropbox awaits
that parent instead of altering its profile projection to hide the core bug.

The expanded program passes 44/46 owners (1,758 assertions,
/tmp/issue143-46-owners-link-info2.log, terminal exit 1), with only those same two
missing-name failures. All actual POST exchange, refresh, replay, foreign
authority, explicit linking and changed-profile account-info owners pass.
Default authorization on an isolated unchanged f112 parent with the real
generic provider failed for the intended missing-factory contract: Native
replaced default scopes with requested scopes, whereas Source preserves all
three ordered scope entries (29 assertions,
/tmp/issue143-generic-before-owner.log). Only the application registration was
adapted to an existing generic provider literal; parent production is unchanged.
Both before fixtures retain the actual remote receipt endpoints.

All-target strict native API and fixture Clippy, native formatting and TypeScript
checks passed. Independently reviewed factory admission and trusted HTTP
configuration have no identified ownership blocker. Capability additions come
only from the 44 actually passing recorded public owners, retaining every parent
requirement and excluding setup routes or unclassifiable callback denials.
Final #183 integration, complete focused/canonical/docs/browser proof, clean
unchanged-floor coverage and publication remain pending. This draft does not
claim a complete issue or a green full gate.
