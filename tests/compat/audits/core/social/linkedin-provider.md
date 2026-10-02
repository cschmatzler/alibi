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

Initial API and real fixture strict compilation pass. Typecheck stopped before
runtime because this fresh worktree had no installed dependencies (tsc absent).
Install the unchanged frozen Bun lockfiles before executing the genuine table.
Add four nullish/boolean verified-email cases and one original nonobject profile
mapper-order denial to the actual SDK table, retaining all callback/physical
and foreign observations. The output trait still bounds arbitrary malformed
nonboolean projection under184; no permissive cast or provider-specific shim.

Actual45-owner collection passes45/45,1,710assertions on the first executed run:
/tmp/issue151-first45-real-owner.log. Full original HTTP GET/form receipts,
mapper inputs, subject ownership, verified-email true/false/null/missing,
nonobject mapper-before-denial, all foreign rows, physical account/session
relationships, signed session/state, callback replay, refresh/link/getter and
local logout remain observed. Initial API/fixture all-target strict checks pass;
TypeScript passes after installing unchanged frozen Bun lockfiles.

Actual90385caed6b86f82d2390153c9e51972244b0267 production with genuine fixture
registration and old public generic constructor reproduces missing ordered
profile/email/openid defaults after Source passes; exit1/28assertions,
/tmp/issue151-generic-before-owner.log. Production and both Cargo.lock files
are unchanged. Only real fixture registration is adapted for the baseline API.

Preserve all5,874 parent requirements and append270 freshly measured
cells from45passing owners, totaling6,144; verify exact set inclusion against
actual passing artifacts. No Source/comparer edit, crypto allowance, dependency
patch or hook bypass. Independent review and frozen broad gates remain pending.
