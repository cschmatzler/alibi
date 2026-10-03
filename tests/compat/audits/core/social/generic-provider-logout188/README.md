# Generic RP-initiated provider logout — #188 / PR #408

Discovery retained an end-session endpoint, but the native sign-out owner never
used it. `GenericOAuthConfig` now accepts `post_logout_redirect_uri` and
`disable_provider_logout`. Resolved logout settings belong to the registered
provider; existing factories keep their default behavior.

Sign-out reads the signed session token, resolves its stored user, revokes the
local session and clears its cookies. It then queries only that user's accounts,
orders them by updated time and tries each configured provider once. Invalid or
disabled logout endpoints fall through without undoing local logout. Request
account/user IDs and cached account cookies never select the ID token hint.
Published 1.7.6 returns HTTP 200 with `success`, `url`, and `redirect`, and adds
Location unless `disableRedirect` is true. `callbackURL` overrides the configured
return URI; state is included only with a return URI. Client ID is included with
a return URI or without an ID token. Existing query parameters and fragments
survive; set parameters replace all duplicate values in their original position.

Nine distinct focused Source/native scenarios pass on each actual SQLx and
SeaORM store. Eight initially covered discovered/configured URLs, duplicate
query replacement, callback/state, redirect disablement, hints with/without
return URI, absent ID tokens, provider opt-out, invalid endpoints, foreign token
ownership, account update ordering/provider fallback, cookie deletion, stored
session deletion and repeated logout. Users and accounts remain unchanged and
the foreign session survives. The review added malformed optional-field checks
that reject before session mutation. After the query-indexing lint fix, only the
configured duplicate-parameter case and new validation scenario ran again per
adapter; the other passing pairs were retained.

The original sign-out handler was restored exactly for the before control,
while retaining the new configuration so the same fixture can compile. Source
returned the provider URL; native returned only `success`, with the missing URL
causing the recorded failure. Complete original responses and persisted rows
are retained in `before-raw-pairs.tar.gz`. `first.log.gz` retains the initial
harness failures: nested logout URI origins were compared literally, and the
ordered-account seed omitted fields with different fixture defaults. The
comparator now treats `post_logout_redirect_uri` as a URL using its existing
strict origin/path/query comparison. No exclusions were added. Explicit seed
values remove fixture drift; no runtime dependency was patched.

All 465 installed BetterAuth package files match the authentic published 1.7.6
tarball. `source-integrity.json.gz` records archive/file hashes and equality.
Pinned upstream metadata and exclusions are unchanged. Complete paired HTTP
traces, original cookies, URLs, validation responses and users/accounts/sessions
are in the raw-pair archives. These are deterministic synthetic fixture values.

Strict default-feature production Clippy, client typecheck, reference fixture
only typecheck, focused lint/format and whitespace checks pass. An initial
all-features Clippy command was invalid because native-tls and rustls are
mutually exclusive; the supported default-feature command passes after fixing
unchecked query indexing. Review traced session ownership through both
adapters' user-scoped account queries and callbackURL through existing CSRF
redirect validation. No new outbound HTTP request is made during logout.
Review was self-review with test-audit/authz/data-exfil; no independent agent was
delegated. GitHub Actions is disabled, so there are no CI results. No full suite,
devenv test or coverage sweep was run.

Rebase includes unrelated admin ascending-sort PR #406. Its complete incoming
diff and the implementation range diff are retained. It touches no logout,
fixture or comparator owner; passing adapters were not replayed for that update.

Reproduce with the repository Rust/Bun environment, frozen installs in both
compatibility packages, a private CARGO_TARGET_DIR, and:

```sh
cargo build --manifest-path tests/compat/rust-server/Cargo.toml
python3 tests/compat/audits/core/social/generic-provider-logout188/run-pair.py sqlx focused
python3 tests/compat/audits/core/social/generic-provider-logout188/run-pair.py seaorm focused-seaorm
cargo clippy -p better-auth-api --lib -- -D warnings
```

#188 remains open for dynamic refresh parameter context and broader callback,
expiry and concurrency acceptance. Provider callback-page implementation and
back-channel logout are outside this published sign-out contract.
