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

Independent read-only review identified observable callback ordering for a truthy
nonobject viewer: the actual published factory invokes the application mapper
before the raw account-subject guard rejects admission. Add a genuine empty-array
viewer owner before the production correction; retain its original mapper
receipt, exact final redirect, full remote requests and all unchanged foreign
rows. Existing missing/null envelope controls continue to prove that falsy or
absent viewer values reject before the callback. This tests the actual callback
boundary, not a private truthiness helper. No test-only production seam is needed.

The genuine empty-array viewer owner fails against the unchanged initial native
implementation after Source passes: expected original mapper receipt [ [] ],
actual [], exit1/27assertions in /tmp/issue150-mapper-before-owner.log. Both final
admission guards reject with unable_to_get_user_info and unchanged physical
rows. The bounded production correction uses the published viewer truthiness
check so the mapper runs before the existing raw identity guard. Missing and
null viewers still reject before mapping. No identity guard is weakened.

Strict API and real fixture all-target Clippy, formatting and TypeScript pass.
Initial inferred-record typing failed before execution and was corrected.
First real46-owner collection was45/46,1,796assertions: the account-info oracle
expected serialized dates while the genuine SDK returned Date values. Use the
existing full ctx.snapshot conversion (all fields retained); production and
Source were unchanged. Corrected46/46 collection passes1,830assertions.

Independent review identified the mapper-order regression, reproduced above.
After its production correction, strict API/fixture Clippy and TypeScript pass,
and the full47-owner collection is47/47,1,866assertions, including original empty
array mapper receipt and unchanged final denial/foreign rows.
/tmp/issue150-reviewed47-real-owner.log is terminal0. All genuine envelopes,
actual GraphQL query bytes, inactive/partial-errors mapping, null/missing mapper
denial, code/refresh grants, raw identity, access lifetime, replay/link/read and
local logout retain full observed state and remote requests.

Baseline actual bfab5de6 production plus genuine fixture registration with old
public generic OAuth constructor fails default authorization after Source passes:
expected read requested-scope read, actual requested-scope read; exit1/28assertions,
/tmp/issue150-generic-before-owner.log. Production and both Cargo.lock files are
unchanged on this baseline. No dependency patch or hook bypass.

Preserve all5,596 parent requirements and append278 freshly measured
cells from47 passing actual owners, totaling5,874. No fabricated evidence,
no Source/comparer change. Full frozen canonical/coverage/docs/browser gates
and actual-main composition remain pending.
