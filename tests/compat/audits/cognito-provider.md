# Cognito provider (issue #142)

The authority is the installed unchanged Better Auth 1.7.6 Cognito factory and
its declared options/profile, shared OAuth authorization/token helpers and raw
account-key resolver. The Source application calls that real factory. Only its
fixed hosted token/userinfo and region/pool JWKS destinations redirect to local
HTTP. Native calls public CognitoOptions and OAuthProvider::cognito with trusted
local transports. Controls supply endpoint responses and application policy;
they never supply an admission, physical row, authentication or fabricated
callback receipt. Full user/account/session columns and foreign principals are
observed through the existing physical SQL observer.

The authoring gate owns fixed/configured endpoints, ordered duplicate-preserving
scopes and their percent encoding, actual PKCE and client-secret transport,
authenticated exact-kid issuer/audience/age/nonce, profile fallback and the raw
subject, callback replay, scoped refresh and local logout. Existing generic
provider coverage cannot establish this missing factory's initialization,
ID-token profile enrichment or hosted-domain defaults. No test-only production
interface or comparison allowance is introduced.

## Native contract

CognitoOptions requires domain, region and user pool; its factory strips a
lowercase http/https prefix and constructs HTTPS authorize/token/userinfo.
Authorization requires a primary client ID, optionally a client secret. Base
scopes are openid/profile/email, followed by configured and requested scopes,
retaining duplicates. Disabled defaults, prompt, identity-provider and trusted
endpoint/callback overrides are explicit. Caller additionalParams cannot
replace the eight reserved OAuth keys; a nonreserved request parameter can
replace an application parameter. Scope uses the published URI-component form,
including WHATWG's final apostrophe escaping and its placement after other keys.

Actual token helpers use client-secret post or public none; the factory does
not forward a basic-auth option, so no invented Source basic mode is claimed.
Absent/zero access expiry remains null; fractional expiry is retained. Missing
token-response scope is the empty persisted string, not authorization scopes.
Refresh rotates tokens/expiry but the public operation retains persisted scope.
The factory has no remote logout operation: actual signOut revokes its session
without provider HTTP.

ID admission uses real RS256/JWKS, exact kid and the JWK-declared algorithm,
fixed region/pool issuer, all configured client audiences, one-hour maximum age
and exact nonce. Decoded ID profiles enrich name using name/given_name/username
truthiness before an application mapper. Decode/mapper failure can fall back to
access-token userinfo; malformed raw subject is an admission failure after the
mapper and email guard. HTTP userinfo passes the original unenriched profile to
the mapper. Mapped IDs and getUserInfo user IDs cannot replace the original
profile's subject. The native general provider interface therefore exposes an
optional raw account_subject resolver; other factories retain their existing
semantics. The raw data stays intact for identity validation.

## Initial measured proof and remaining publication

The first real 46-owner run passed 44 and failed two assertions on Source's actual
apostrophe escaping. Correcting those expectations to the measured %27 output
changed no Source, production or comparator behavior. The next expanded runs
passed 53/56 and failed the three new owners at their Source assertions: missing
response scope is empty, and refresh leaves it unchanged. Those expectations
were corrected to the actual published operation; original logs remain.

The current working program passes **60 actual Source/native owners / 1,640
assertions** (`/tmp/issue142-60-owners.log`): ordered configured authorization,
reserved-key rejection, signed profile/claim positives and negatives, real
client-secret/public exchange and original PKCE digest, full HTTP vs decoded
profile/mapping receipts, malformed-token fallback, physical callback replay,
foreign refresh denial before token requests, genuine owner rotation and local
logout. An application getUserInfo owner proves valid raw identity and
missing/null/blank raw subjects after the actual callback, retaining foreign
physical rows. All observations and traces are retained.

TypeScript passes for this measured working tree. Earlier strict workspace and
fixture checks passed before the subsequent account-subject addition; those are
not claimed as current strict results. Main rebase, additional configuration,
JWKS retirement/restore, intended missing-factory before proof, independent
review, capability measurement, final strict/canonical/docs/browser and clean
coverage remain pending. This draft is not a completed-issue or green-gate claim.

The typed native profile uses strings and booleans plus supported scalar
coercions; complex user fields and arbitrary malformed callback results are not
claimed equivalent. Additional-field schemas (#184), generalized configured
callback contexts/error composition (#181/#188) and transport malformation
(#193) retain their independent scope. No local dependency patch, hook bypass,
Source code modification or reduced comparison/coverage requirement is used.
