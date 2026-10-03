# Linear provider (issue #150)

The authority is the unchanged installed Better Auth 1.7.6 public Linear
factory and its real grant helpers. Both fixtures register the actual provider;
the Source fixture redirects only the two fixed HTTP destinations to an
application-owned local service. No package, comparator, coverage script or
harness control is patched.

Authorization retains the ordered default `read`, configured and requested
scopes, duplicates, `loginHint`, and trusted authorization/redirect overrides.
This provider supplies no code verifier, so authorization and code exchange omit
PKCE. The real token helper uses secret-post or public authentication and the
code-only `client_key`; refresh retains its own published form and expiry rules.
The provider has no built-in ID-token verifier, JWKS or remote logout; genuine
SDK owners retain its unsupported direct-proof rejection and local logout.

Lookup sends the actual bearer-authenticated GraphQL POST, including the exact
published viewer query. A truthy `data.viewer` is passed unchanged to the mapper
before raw identity admission. Inactive viewers and partial GraphQL errors do
not create invented admission rules. Raw original `viewer.id` determines the
physical account independently from the mapped public id. Missing, null, blank
and unsupported raw subjects continue to deny before identity writes.

The default public user preserves raw `name`, `email`, `avatarUrl` and their
absent/null/empty/numeric JSON shape, with `emailVerified: false`. Mapped public
fields overlay that original output. Typed SQL persistence remains a separate
boundary; undeclared public mapper extras are exposed by account-info without
being written to users or changing account authority.

The authoring gate extends the existing mapping and mapped-lifecycle owners,
rather than adding helper tests or production seams. All original 47 owners
remain, with real SDK authorization/callback/read/refresh/logout operations,
full observed remote requests, complete physical rows, foreign ownership,
replay, link and denial controls. Their public account-info reads independently
protect publication differences that typed persistence alone cannot detect.

## Before and after evidence

The original generic-constructor before proof failed default authorization after
Source passed: expected `read requested-scope read`, received
`requested-scope read` (`/tmp/issue150-generic-before-owner.log`). The original
empty-array viewer regression failed the mapper receipt after Source passed:
expected `[[]]`, received `[]`, while both runtimes rejected final admission
(`/tmp/issue150-mapper-before-owner.log`). The provider retains that original
callback-order owner and the existing raw identity guard.

The resumed native-before SDK run is 43/47, with precisely four publication
failures after Source passes: numeric name, null name, null image and numeric
image (`/tmp/pr292-public-mapping-before.log`). Their complete SQL rows already
match; the failure is the native public account-info user JSON. The repair uses
the existing `OAuthUserInfoResponse.user_output` boundary to retain original
JSON separately from typed persistence, without changing comparisons.

The repaired Source-self and Source/native collections each pass 47/47 with
2,078 assertions (`/tmp/pr292-focused-final2.log`). The mapped lifecycle also
reads the actual owned account after refresh, retains its rotated bearer
receipt and original mapper input, exposes a structured public extra, verifies
that the physical user has no undeclared extra, and preserves all foreign rows.

## Capability accounting and integration

Independent recount starts from main `74309f36`: all 5,742 baseline entries,
including all 5,738 unique requirements and their existing duplicates, remain.
Exactly 303 actual measured cells from the same 47 passing owners are added:
6,045 total entries and 6,041 unique requirements. Each added requirement has an
actual passing trace cell (`/tmp/pr292-independent-recount.json` and
`/tmp/pr292-measured-cells.json`). No flags or explained absences are rewritten.

The old provider stack is isolated onto main; fixtures and scenarios use the
current `fixtures` and `core/social` layout and existing public-output field
policy. Root independently reviewed the final publication, raw account
ownership and trusted transport boundaries without identifying a blocker.
Modern formatting, lint and TypeScript checks pass. All original 89 harness
controls pass with 2,367 assertions; strict API and fixture all-target Clippy
pass. Final Source-self and Source/native reruns after formatting each remain
47/47 with 2,078 assertions (`/tmp/pr292-final-controls.log` and
`/tmp/pr292-strict-native.log`). The unchanged full gate
is `devenv shell -- ./scripts/check.sh`; its terminal status and full native,
SDK, browser, documentation and 75% coverage evidence are reported in PR #292.
