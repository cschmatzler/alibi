# Built-in social authorization scope and Discord configuration

This slice follows actual pinned `@better-auth/core@1.7.6` source:
`dist/social-providers/google.mjs`, `github.mjs`, `discord.mjs`, and
`dist/oauth2/create-authorization-url.mjs`. Public `signIn.social` and
`linkSocial` both reach these provider factories through Better Auth's ordinary
routes. Request scopes append at runtime despite an upstream sign-in comment
claiming replacement. Google/GitHub use defaults, configured scopes, request
scopes; Discord uses defaults, request scopes, configured scopes. Entries keep
order, duplicates and empty strings. `disableDefaultScope` removes only defaults;
a truly empty list omits the query field, while a list containing an empty string
retains `scope=`.

`OAuthProvider.authorization` is the sole optional typed policy. Built-in
constructors set it; a custom provider's `None` preserves its existing Rust
scope replacement and PKCE behavior. The public base `scopes` list keeps its
meaning. The policy separately exposes configured additions, disable defaults,
ordering, PKCE, prompt/default prompt and a Discord JS-number permission value.
It is configuration held in the immutable OAuth plugin, not request authority.
No state generation, ownership, linking, cookies or session issuance are replaced.

Discord uses no PKCE in either authorization URL or authorization-code exchange.
Its absent/empty prompt defaults to `none`. A configured permissions number is
emitted only when effective scope contains the exact string `bot`; zero,
fractional and nonfinite values use JS number strings, without scope trimming or
deduplication. Existing configured authorization-parameter handling remains unchanged; native
collision behavior is still an explicit gap.
Visible URLs retain the actual fixed provider defaults, including Discord's
`https://discord.com/api/oauth2/authorize`.

The private application fixture creates genuine published built-in providers
and equivalent Rust constructors. Its Source fetch wrapper intercepts only the
exact Discord token/user-info destinations into local HTTP; every other fetch
continues through the existing chain with its original input/init. Rust changes
only the configured token/user-info transport URLs. Actual provider POST/GET
requests produce receipts containing every form parameter, authorization and
content type. Profile controls supply deterministic local test accounts, never
expected receipts. Both runtimes expose actual database rows and reset their
real receipt/profile state at the existing reset boundary. All public requests
complete before reset; concurrent outstanding reset is not claimed. The isolated
profiles exclude username support on both sides (`plugins: []` and
`enable_username(false)`), rather than suppressing observable fields.

Four official-client owners cover 48 scope configurations/requests, conditional
permissions and prompt choices, authenticated link scope ordering for all three
built-ins, and a genuine Discord callback/account/session lifecycle. They retain
full SDK authorization URLs, provider receipts, current/foreign sessions and core
user/account/session snapshots, plus every canonical public transport. The
Discord flow checks the exact token form (no `code_verifier`), genuine provider
account ownership, saved tokens/scope, one new session, untouched foreign rows
and consumed-state replay. The latter also exercises the independently frozen
rejection prerequisite; it cannot replace the lifecycle/token-form proof.

Meaningful original-consumer baseline:
`/tmp/social-authorization-meaningful-before.log` has four intended failures:
empty requests replacing defaults, missing Discord prompt, link requests replacing
configured/default scopes and Discord unexpectedly advertising PKCE. Earlier
standalone Source and Native probes retained 66 actual observations each in
`/tmp/social-defaults-{source,native}-observations.jsonl`; investigation binaries
and probes are not feature files. Early fixture Router-state compilation errors
and initial username configuration mismatch were setup corrections, not reported
as production failures.

Final Source-self `/tmp/social-authorization-source-control-final.log` passes
4 scenarios / 900 assertions. Differential full OAuth directory
`/tmp/social-authorization-sdk-family-final.log` passes 21 / 1018, including the
four new owners, two rejection prerequisite owners and 15 existing siblings.
Client type-check and strict fixture Clippy pass in
`/tmp/social-authorization-client-typecheck-final.log` and
`/tmp/social-authorization-fixture-clippy-final.log`. The new Source fixture is
strictly checked with the existing pinned client TypeScript compiler and Bun
types: `/tmp/social-provider-reference-typecheck-final.log`; this is not a claim
that the entire reference server has a configured TypeScript project.

Boundaries: only the three existing Rust built-ins are implemented here. Source
per-request `additionalParams` remains a separate missing Rust API, as do further
provider options/factories, unusual existing endpoint query collisions, other
client-ID forms, unsupported custom-provider policies and Discord profile defaults.
Negative/NaN permission formatting is implemented through the same JS formatter
but is not separately exercised by these configuration owners. No new dependency,
lockfile, schema, inventory or full-gate changes are included. The coordinator
owns final integration and canonical validation.

The 18 existing native account OAuth integration tests also pass after the policy
change (`/tmp/social-authorization-native-siblings-final.log`). Investigation-only
source files are preserved outside the feature tree under
`/tmp/social-provider-investigation-artifacts/compat-tests/`.

Independent phone-owner and coordinator review of frozen `efd9b2e6` is clear for the measured scope/configuration and genuine callback lifecycle. All eleven paths, pinned provider factories and shared authorization/token consumers were inspected. A misleading collision-guard claim was corrected above; unusual endpoint/configured-parameter collisions remain open. Fifteen additive inventory requirements anchor the real official-client consumers without removing prior evidence. The next integrated canonical gate remains pending.
