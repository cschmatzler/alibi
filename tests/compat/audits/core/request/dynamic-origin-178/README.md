# Dynamic request origins (#178)

Global config mode resolves allowed hosts, optional/auto/HTTP/HTTPS protocol,
fallback and async trusted origins from the original `AuthRequest`. Resolution
precedes transport callbacks and middleware; HTTP, before/after hooks, CSRF,
core update-user and plugin handlers share one effective request config. The
existing store, extension policies and cache authority are retained. Proxy host
and protocol headers require `advanced.trust_forwarded_host = true`; the default
ignores them. An unlisted request host can use fallback without becoming trusted.
Empty host allowlists are rejected during config validation.

The retained published Better Auth 1.7.6 tarball is in
`/tmp/origin178-evidence/better-auth-1.7.6.tgz`; `source-integrity.json` verifies its
SHA-512 against npm's published integrity. Source observations and probe are
reused from the interrupted task, without replay or dependency mutation. The
probe imports the published tarball's modules, not repository Source checkout
modules. `native-observations.json` equals `source-observations.json` for six
proxy/host resolutions and ten origin-pattern decisions. Base URL serialization
adds the existing Rust base path for the comparison; production keeps URL and
base path as separate config values.

Native physical SQLite evidence covers actual SQLx and SeaORM stores:
foreign/lookalike request origins reject before users or sessions are created;
allowed sign-in creates sessions/cookies with exact callback Location;
default/foreign ports and custom-scheme authority, userinfo, path traversal,
query/fragment decisions follow the measured Source patterns. Rejected magic-link
callbacks leave the verification challenge unconsumed and produce no cookies,
users or sessions. Valid use consumes it once; replay creates no second session.
SQLx and SeaORM each retain one user/four sessions after the sign-in matrix.
HTTP, before and after SDK callbacks assert their effective config; shared builder
config remains unchanged. Origin-policy tests cover optional vs auto protocol,
explicit protocol override, forwarded-header opt-in, loopback classification,
fallback, missing fallback and empty allowlists.

The original fixture accidentally hit rate limiting. `native-first.log` retains
that failure and both passing magic-link checks; the fixture disables rate
limiting for this origin contract. `wildcard-checkpoint-regression.log` proves
checkpoint 5bad9a443f61a8b4e0d4204e7ccb6c8f7fc65398 incorrectly accepted
`myapp://client/cb?q=1` for `myapp://*`. The repaired matcher follows Source's
separator and recursive-segment rules. Config trust uses the stricter server
loopback classifier rather than dev scheme inference's permissive 127 prefix.

Focused checks only: both adapter dispatch and magic-link contracts, public
config matrices and 22 existing config/CSRF origin tests. Later initializer and
fixture-only corrections replayed just affected config or dispatch checks.
`native-reviewed.log` retains the expanded-IPv6 fixture expectation failure;
Source patterns use literal spelling while URL origins canonicalize IPv6, so the
fixture now uses canonical `[::1]`. No full compatibility/devenv/coverage sweep
was run. Actions are disabled and the PR has no hosted check results. Review was
performed locally without delegation, following test-audit and wrdn-authz.

Boundaries: this is the global config implementation, not dynamic provider
selection. #374 owns provider factories and consumes effective `ctx.config`
indirectly. These are direct published config-module comparisons and native
endpoint/storage outcomes, not a dual-server proof of every OAuth/passkey/proxy
callback family. Existing WebAuthn proof-origin comparison is unchanged. Broader
cross-family equivalence, expiry/concurrency and independent external review
are not claimed. #178 stays open with those boundaries; no full-sweep or frozen
gate is required by the current user policy.
