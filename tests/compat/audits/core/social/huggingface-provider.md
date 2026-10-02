# Hugging Face provider (issue #146)

Read-only authority: unchanged installed Better Auth1.7.6 Hugging Face public
factory and profile/options, actual authorization/code/refresh helpers and raw
account resolver. The real factory must execute; controls redirect only fixed
remote HTTP and return provider responses, never synthetic admission or rows.

Default authorization is huggingface.co/oauth/authorize with ordered duplicate
preserving openid/profile/email, followed by application and requested scopes.
PKCE is supplied, loginHint is omitted, defaults can be disabled, and trusted
application authorize/redirect overrides remain. Shared code/refresh forms target
huggingface.co/oauth/token: secret POST clients or genuinely public no-secret
clients. client_key is code-only. Bearer GET uses /oauth/userinfo. Raw sub owns
admission independently of a mapped id; name uses JavaScript truthy name then
preferred_username then empty string, image is picture and verification defaults
nullish false. Original profile reaches the mapper. The factory has no built-in
ID-token/JWKS/issuer verification or remote logout, despite openid scopes.

Authoring gate: one real-client table owns this actual factory wiring, public
versus secret grants, truthy fallback field extraction and raw sub admission.
Existing generic/Figma owners do not exercise these initialization and profile
contracts. Complete HTTP receipts, PKCE digest, physical rows, foreign identities,
replay, refresh rotation and local sign-out remain in observations. Existing
linking and account-info owners protect distinct retrieval/admission boundaries.
No private predicate tests or test-only production exports are needed. Complex
additional fields, async mapper/error composition and malformed transport remain
#181/#184/#188/#193 rather than claimed universal JavaScript emulation.

The actual public program passed strict API/fixture all-target Clippy and
TypeScript. An initial script-generation error prevented owner execution after
those checks; its terminal127 log is retained. The first executed table passed
42/47 owners with 1,236 assertions, failing Source-side expected display-name and
scope strings. Actual Source emits Hugging Face User and persists the provider's
space-separated token response scope as the helper's comma-separated array.
Only those expected strings were corrected; production and Source stay unchanged.
The complete corrected run passes all47 Source/native owners with1,740 assertions
(`/tmp/issue146-corrected47-real-owner.log`, exit0).

An unchanged actual568ff991 parent, with only the real application fixture and
constructor adapted to its old public generic provider, compiles and fails the
same default authorization owner for the intended missing default-scope behavior.
Source retains openid/profile/email before requested scopes; Native replaces them
(`/tmp/issue146-generic-before-owner.log`,28assertions,exit1). Production and both
lockfile diffs from that parent are empty. No missing-constructor or404 is used
as regression evidence.

Independent review of production, factory, helpers and real fixtures found no
blocker for declared profile fields and options. Non-null malformed non-boolean
email_verified values are outside the declared boolean contract and are not
claimed by the47 owners. The immutable program preserves all4,472 parent cells
and adds measured Hugging Face cells only from passing real Source/native traces;
all232 additions verified in the final canonical evidence directory, with no
lost cells or changed parent ordering.

Immutable program3077a96ed376d9a48d4e20f683178cd579e6d9ce is composed on actual
mainff2cfec8. The final audit-only commit changes no executable input.
`devenv shell -- bash scripts/check.sh` exits100 at its full SDK run
(/tmp/issue146-final-canonical.log): strict default/optional Clippy, Rustls, both
format checks,794default/845optional native tests, fixture tests, TypeScript and
71harness tests pass. Full actual SDK passes1,292/1,296owners and83,984assertions,
including all47 Hugging Face owners. The remaining four failures are the fixed
membership-policy clock owner and three generated seed12648430snapshot22 guard
code/message comparisons tracked by #221. The clock failure has exactly four
observation7 aliases: snapshot.members7.createdAt, response.body.createdAt and
usersBefore/usersAfter session3.expiresAt. The exact membership aliases reproduce
on the independently run unchangedFacebook parent for #221; no broad claim is
made for every other organization timestamp path. Full canonical is not green.

Warning-free docs and both real Chromium browser owners pass,22assertions
(/tmp/issue146-docs-browser.log,exit0). Clean scoped instrumentation with supported
MBX_DISABLE=1, fresh isolated coverage targets and unchanged75%floor passes all
845native and allfive SDK groups (/tmp/issue146-clean-coverage.log,exit0). The
complete report contains211source records and no duplicate logical workspace
paths, and measures31,380/40,653native lines (77.189875%). All measured capability
cells are backed by this program's actual successful Source/native traces. No Source/comparer edit,
dependency patch or hook bypass is authorized.
