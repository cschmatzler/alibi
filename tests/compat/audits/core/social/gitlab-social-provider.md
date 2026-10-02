# GitLab social login

This capability adds `OAuthProvider::gitlab` and
`OAuthProvider::gitlab_with_issuer`. The reference is the installed, pinned
`@better-auth/core@1.7.6` source:

- `dist/social-providers/gitlab.mjs` and `gitlab.d.mts`;
- `dist/oauth2/create-authorization-url.mjs`;
- `dist/oauth2/validate-authorization-code.mjs`;
- `dist/oauth2/refresh-access-token.mjs`;
- `better-auth/dist/oauth2/state.mjs`, `link-account.mjs` and the ordinary
  callback/account routes.

The default issuer is `https://gitlab.com`. A configured issuer retains its
deployment path; endpoint construction collapses repeated path slashes exactly
as the provider factory does. Authorization uses the existing immutable typed
policy: default `read_user`, configured scopes, then requested scopes, preserving
order, duplicates and empty additions. Disabling default scopes does not remove
configured or requested scopes. Both login and authenticated account linking
issue genuine PKCE state. Default authorization URLs remain public GitLab URLs;
self-hosted tests expose their issuer at the actual known application base URL.

User information comes from the actual bearer-authenticated `/api/v4/user`
request. Only `state === "active"` and a JavaScript-falsy `locked` value admit
the profile. The mapper preserves nullish name fallback (`name`, `username`,
empty string), avatar, declared boolean email verification and JavaScript-number
account subjects. The primary includes numeric IDs at the safe-integer boundary
and exponent formatting. Existing shared account creation, linking, session,
refresh, ownership and grant-scope persistence paths remain the production
owners; provider receipts come exclusively from actual HTTP requests.

## Primary evidence

`tests/core/social/gitlab.test.ts` has three official-client owners:

1. **GitLab authorization preserves hosted issuer ordered scopes and authenticated
   link PKCE** exercises six immutable configurations and four requested-scope
   forms, guest rejection, a legitimate owner link and unchanged complete rows.
2. **GitLab self hosted callback login link refresh and replay preserve actual
   account and foreign owners** performs actual authorization-code exchange,
   creates and reuses the correct account/session owner, refreshes tokens, reads
   access and original permission scopes, rejects foreign access/refresh and
   mismatched-email linking, then successfully links another account to its
   authenticated owner. Every actual token/user-info form and complete stored
   user/account/session snapshot is retained.
3. **GitLab profile admission rejects inactive and truthy locked rows and
   preserves nullish defaults** exercises ten profiles, including truthy string
   and array locks, inactive/missing state, numeric-falsy lock, empty/nullish
   names and numeric subjects. Rejection, replay and unchanged foreign state
   are asserted alongside successful account and session writes.

Random code verifiers are reversibly represented in compared provider receipts
as `{token, length}` using the existing token identity graph. The tests assert
the full actual form, source alphabet and 128-character length locally, and
independently hash that same verifier to the actual issued authorization
challenge. No harness rules, response fields or canonical transports are removed.

The original consumer had no GitLab constructor or registered built-in. The
saved original consumer returns `404 PROVIDER_NOT_FOUND` in all three new
official-client scenarios, before provider requests or account/session writes:
`/tmp/gitlab-sdk-meaningful-before.log`. This proves the missing provider
admission/configuration boundary, rather than claiming a pre-existing mapper
regression. Independent pinned factory/HTTP probes are retained in
`/tmp/gitlab-social-source-probe.log`; the original native availability and
unchanged-row probe is `/tmp/gitlab-social-native-before.log`.

Shared protocol repairs are the separate prerequisite `c39eb88e`: source-length
PKCE, exact `email_does_not_match` linking rejection and omission of absent
get-access-token `idToken`. Their distinct intended before failures and primary
owners are recorded in `oauth-pkce-link-token-wire.md`. Incorrect initial source
refresh-scope expectations and a zero-test native selector were corrected setup
runs, not production baseline evidence.

## Physical state lifecycle and codec boundary

Two independent real HTTP/storage probes retain complete physical verification
records, including their literal identifier, raw value, ID, expiry, creation and
update timestamps. `/tmp/gitlab-source-physical-state.log` and
`/tmp/gitlab-native-physical-state.log` prove issued record count one, consumed
count zero, replay count zero, no replay writes/extra provider calls, retained
session owner and a full unchanged foreign pending verification record. They
also derive the issued challenge from the actual stored verifier. The probes use
the existing private verification-state observer and ordinary public client
issuance/callback routes; they do not seed expected rows or change production.

The reference stores the state itself as the identifier; the Rust internal OAuth
codec stores `oauth:` followed by that state. Each probe asserts its exact
backend contract and retains all raw records. Literal physical codec parity is
not claimed. The official-client primary remains unchanged: no returned field
is excluded or transformed to hide this namespace difference, and no comparator
normalization is added. Public verification identifier interoperability beyond
this internal lifecycle remains a separate capability.

## Focused validation and bounds

- OAuth family: 25 scenarios / 2108 assertions,
  `/tmp/gitlab-sdk-family-final.log`.
- Reference against itself: five scenarios / 914 assertions,
  `/tmp/gitlab-source-sdk-final.log`.
- Existing native account OAuth consumers: 18 passing tests,
  `/tmp/gitlab-native-siblings-final.log`.
- Strict fixture Clippy, client/reference TypeScript, current fixture build,
  edition-correct Rust formatting and diff checks pass; logs are
  `/tmp/gitlab-fixture-clippy-final.log`,
  `/tmp/gitlab-client-typecheck-final.log`,
  `/tmp/gitlab-reference-typecheck-final.log`,
  `/tmp/gitlab-fixture-build-final.log`,
  `/tmp/gitlab-fixture-format-final.log` and
  `/tmp/gitlab-production-format-final.log`.

This is the fourth Rust built-in provider; the pinned package's other 32
factories remain outside this slice. It does not add excluded authorization-server,
enterprise SSO or other integration packages. Existing generic custom user-info
and refresh handlers remain available, but source callback context and
`mapProfileToUser` configuration equivalence are not claimed here. Malformed
provider profile field types, secretless/client-key configuration, additional
authorization parameters, unusual token/ID-token/expiry payloads, custom schema
projections and broader storage-codec interoperability remain explicit separate
boundaries. No schema, dependency, lockfile, inventory, coverage or full-gate
change is included.

Coordinator independent review is clear at 41a772b3: pinned factory/endpoint
construction, actual provider HTTP receipts and unmodified raw profile, signed
link authority, scope/token persistence, replay and physical-record probes were
inspected. Twenty-nine additive requirements retain all previous evidence; no
internal identifier field is disguised by SDK normalization. Full integrated
validation is pending the next frozen gate.
