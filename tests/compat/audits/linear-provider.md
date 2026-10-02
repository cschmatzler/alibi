# Linear provider (issue #150)

Authority is the unchanged installed Better Auth1.7.6 Linear public factory,
LinearUser/LinearProfile/LinearOptions and actual grant helpers. Application
registers that factory; the deterministic local service redirects only fixed
remote destinations, preserving all real requests and responses.

Authorization uses linear.app/oauth/authorize with ordered read, configured
and requested scopes; duplicates remain. This factory supplies no codeVerifier,
so authorization/code grants omit PKCE. loginHint and trusted endpoint/redirect
overrides remain. api.linear.app/oauth/token uses secret-post or public grants,
code-only client_key and the real refresh helper (which ignores clientKey).

User lookup sends actual bearer-authenticated POST application/json to
api.linear.app/graphql, with the published viewer field selection. It selects
data.viewer, maps original id/name/email/avatarUrl, sets verified-email false,
and passes that original viewer to the mapper. active and temporal profile
fields are original data, not locally invented admission policy. GraphQL errors
with a valid returned viewer do not replace the factory's own truthiness check.
Missing viewer rejects. Raw original viewer.id binds identity independently of
mapped ID. No built-in direct ID-token verifier, JWKS or remote logout exists.

Authoring gate: one actual factory/client table owns ordered defaults, absent
PKCE, GraphQL POST/envelope/field selection, first original identity and helper
forms. Existing GET/nested/direct-proof providers cannot exercise that public
contract. Retain all HTTP/mapper/physical/foreign rows, actual signed session,
state/replay, refresh/rotation, link/getter distinctions and local logout.
No private predicate test or test-only production seam. Complex callback/output
extensions remain181/184/188/193, with actual failures retained when encountered.

Implementation, actual before proof, review and final gates are pending.
