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

Implementation, actual before proof, independent review, measured capability
cells and final gates are pending. No Source/comparer edit or hook bypass.
