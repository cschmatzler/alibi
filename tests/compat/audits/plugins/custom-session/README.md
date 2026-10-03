# Custom session projection

Pinned Better Auth 1.7.6 `plugins/custom-session/index.ts` replaces GET
`/get-session` and awaits an application transform over the genuine public
session/user response. Its replacement is GET-only: POST returns empty 404,
even with deferred refresh enabled. A guest or failed underlying session read
returns null before calling the transform. An application transform may return
null, filter fields, or reject; intentional API errors retain their response,
while an ordinary callback failure aborts completed hooks with empty 500.

Native `CustomSessionPlugin<S>` exposes `SessionTransform<S>` with the actual
request and initialized database/configuration context. Register it before an
explicit `SessionManagementPlugin`; otherwise the normal first registered route
owns GET. Implicit default core plugins follow explicitly registered plugins.
The native handler reuses core session authentication, projection and refresh;
it changes only response data. It never interprets transformed user/session
claims as storage ownership or authenticated authority. Genuine response
headers and repeated cookies survive a successful transform. Guest/null core
reads do not inherit core cache headers. The replaced POST route rejects without
refreshing stored sessions. Pinned API documentation still describes the base
GET/POST endpoint: its generator excludes replacements sharing a core API key.
Native default documentation preserves that behavior.

`mutate_device_sessions(true)` additionally transforms the actual device list.
Callbacks start concurrently; output order remains the underlying list order.
An owned worker retains genuine request/hook/endpoint context and lets already
launched callbacks finish after an aggregate rejection. No scheduler-specific
microtask counts or sleeps define this behavior.

The primary official-client owner is `tests/plugins/custom-session/transform.test.ts`.
It uses persisted signup principals, configured public/hidden session columns,
actual browser cookies, two device identities, foreign-device and malformed
signature rejection, selection, storage readback, filtered/null/error results,
expiry and logout. A configured adapter output failure on the same genuinely
issued session returns null and bypasses a callback that would reject, without
changing the physical owner rows. Refresh and deferred-refresh cases observe actual JWT headers,
issued cookies, physical clock changes and the GET-only replacement. API and
ordinary transform failures after an actual refresh discard nested issuance
cookies while retaining committed physical refresh writes. Filtered responses
still carry JWT claims from the genuine authenticated principal. Native
coverage protects the distinct callback ownership boundary: after a list rejects,
a held callback retains its original request and performs a real database write,
while the rejected owner's row stays unchanged.

Before enabling the native plugin, the same client owner fails because the
native core response has no application projection. Exploratory traces and
before/after logs stay outside the repository. Focused validation is reported in
the PR; this issue uses targeted checks on both adapters only.


## Whole-second JWT publications (#380)

Published `better-auth@1.7.6` `dist/plugins/jwt/sign.mjs` builds `iat` with
`Math.floor(Date.now() / 1e3)` in `getJwtToken`; its default expiry is 900 seconds
later. The default EdDSA signer produces the same token for the same key and
claims within that second. The custom-session after hook signs the genuine
principal even when the application filters the response. Native signing has
the same whole-second contract.

The frozen SQLx sweep on `ef4c299a` reported token-bijection drift at the filtered
read's raw `set-auth-jwt` header. The original sweep retained its log but no raw
pair for this scenario. Its SeaORM phase was cancelled by the user, not reported
as a compatibility failure. Focused experiments from `e7effea3` captured both
adapters: start the initial read just inside a second, then delay only Rust's
filtered read by 1.1 seconds. Source reuses the earlier JWT while Rust advances
`iat`, reproducing precisely the reported raw token-rotation difference. This
is an observation timing ambiguity, not a production authority error.

The existing owner now waits beyond the last observed JWT's issuance second
before each subsequent signing request. It independently checks the signup
subject/name, integer `iat`, default lifetime, increasing issuance time and
changed token. This makes rotation intentional on both sides while retaining
the entire raw token/claim comparison and all physical storage observations.
No production, fixture, shared comparator or dependency changes are needed.

Before/after pairs, native timing diagnostics and observation-only negative
controls are retained under `/tmp/better-auth-issue380-evidence`. Controls on both
actual adapter pairs still reject stale complete tokens, foreign subjects,
changed raw names/lifetimes, omitted headers, changed persisted user/account/
session ownership and removed cookie protection. Existing generic JWT/identity
negative controls remain the primary comparator tests; no duplicate success
scenario or test-only production seam is introduced.
