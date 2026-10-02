# LinkedIn provider (issue #151)

Authority is the unchanged installed Better Auth 1.7.6 LinkedIn public factory,
LinkedInProfile/LinkedInOptions and actual grant helpers. Actual Source factory
registration and independently implemented Native transport retain all remote
requests and responses.

Authorization uses www.linkedin.com/oauth/v2/authorization with ordered profile,
email,openid defaults, configured and requested scopes, preserving duplicates.
The factory omits codeVerifier: no authorization challenge or code grant verifier.
loginHint, trusted endpoint and redirect overrides remain. Code/refresh use
www.linkedin.com/oauth/v2/accessToken with public or secret-post authentication;
client_key is code-only because the actual refresh helper ignores clientKey.

User lookup is bearer GET api.linkedin.com/v2/userinfo. The original profile.sub
owns account identity independently of mapProfileToUser ID. name,email,picture
map from the profile; email_verified uses nullish false (valid booleans retained).
Original locale/name fields remain original data. Mapper runs on the returned
profile before raw identity admission. No built-in ID-token verifier/JWKS or
remote logout is supplied. Returned providers retain generic asynchronous
user-info/refresh callbacks and signup/link policy options.

Authoring gate: one actual factory/client table independently owns ordered
provider defaults, absent PKCE, exact endpoints, raw profile authority and
nullish verified-email mapping. Existing unrelated defaults and GraphQL/envelope
owners cannot detect these differences. Retain complete HTTP, mapper, physical
rows, foreign principals, signed-session/state/replay, refresh/rotation, link,
getter and local logout observations. No private-predicate test or production
seam only for tests. Arbitrary malformed output transforms and broader callback
composition remain181/184/188/193, preserving any actual failures encountered.

Before proof, implementation, independent review and all final gates pending.
