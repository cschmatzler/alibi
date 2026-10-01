# Better Auth 1.7.6 implementation ledger

The current task is to finish, review, validate and merge existing work, and file
remaining behavior for triage. No new capability families are being started.
This is not a full-parity claim. The oracle remains Better Auth **1.7.6**, Rust
interfaces remain native, passwords use **scrypt only**, and the raw comparison
exception list is empty. The source line coverage floor remains **75%**.

The [upstream target audit](audits/upstream-target.md) accounts for routes,
server-only APIs, middleware/hooks, configuration, storage and providers. The
[remaining-behavior index](https://github.com/cschmatzler/better-auth-rs/issues/234)
links **96 actionable issues**; [the backlog](PARITY-BACKLOG.md) summarizes them.
OAuth authorization server, MCP, CIMD, enterprise SSO, SCIM, Stripe, i18n, Expo
and Electron remain excluded at the user's request. SIWE remains implemented.

## Wrap checkpoint

The following stack is reviewed for its documented scope. The coordinator owns
integration, immutable-head publication, serialized canonical validation and
merging. A focused passing result does not establish a complete gate or full
parity. Each PR and its audit retain the meaningful before failures and remaining
configuration boundaries.

| Work | Owner; dependency | Primary evidence and review |
| --- | --- | --- |
| Physical OAuth account rows (#187) | Account owner; appended populated-schema upgrade | Actual signed Google and GitLab callbacks reject ambiguous same/foreign principals; row-ID refresh/unlink stay scoped and canonical credentials use the first physical row. Four SDK owners retain full SQL state; installed-schema/FK/rollback and independent-connection admission owners retain application data. See [audit](audits/account-row-multiplicity.md); exact-head integration and independent review pending. |
| OAuth admission and provider authorization (#117–119) | JWT owner; existing OAuth state/provider transport | Real authenticated linking, consumed-state replay, scope/prompt/permission defaults and Discord profile callbacks. Complete persisted owner/foreign state; independent review clear. |
| Membership policy and numeric pages (#120) | Organization owner; physical duplicate membership migration already merged | Fixed/async fractional policy, admission, distinct user/member pages and actual SQLite numeric bindings. Independent review clear; cross-adapter branches remain issues. |
| Core origins and OAuth protocol (#121–122) | Coordinator/JWT owner; existing origin and provider interfaces | Canonical origins, callback paths, actual 128-character PKCE, provider form receipts, response token/linking behavior. Independent review clear. |
| GitLab (#123) | JWT owner; provider protocol | Real deterministic authorize/token/profile service, signup/link/refresh and self-hosted issuer; native and official-client lifecycle proof. Independent review clear. |
| Invitation acceptance (#124) | Phone owner; membership policy and CAS/store contracts | Actual committed accepted status, callback ordering, rollback/reset veto, ordinary/API errors and concurrent admission. Physical SQL and complete differential state; independent review clear. |
| Account response dates (#125) | Coordinator; public projection | Official client parses complete UTC millisecond account responses while physical SQL retains its precision. Independent review clear. |
| OAuth observation and encrypted persistence (#126–127) | Coordinator/JWT owner; provider/state codec | Actual admission controls; SHA-256/XChaCha ciphertext import, reads, token rotation and failure. No installed AES fallback or conversion is included. Independent review clear. |
| Complete admin guest observations (#129) | Coordinator; admin transitions | All original fifteen guest calls remain observed; positive ban/unban/relogin snapshots are captured before that full matrix. Independent review clear. |
| Anonymous authentication and upgrades (#130–131) | Coordinator; original issuance snapshots and trusted linking | Anonymous issuance/deletion plus email, username, OAuth, magic link, email OTP/verification, phone, One Tap and passkey transfers. Wrong-owner/state controls and real persisted cleanup; independent review clear. |
| Complete bounded callback observations (#138) | Coordinator; core redirects | All twelve callback values across email and username remain covered in four bounded owners. Full values, transport and persisted state retained; independent review clear. |
| Required primary evidence (#195–196) | Coordinator/phone owner; final evidence gate | Real guest organization denial, expired invitation stages, authentic ES256 origin refusal/reuse, active and retired OAuth authority, owner transitions. Root 34/3,744; OAuth 8/1,326. Every existing requirement retained; independent review clear. |
| Authenticated comparison prerequisites (#199, #226) | Phone/organization owners; published cookie and proxy decoders | Complete signed compact cache/chunks and encrypted proxy bytes/payloads retain relationship, timestamps, URL components and cookie attributes. Actual fresh Source controls and mutation controls; combined harness 53/614. Independent review clear. |
| Stateful compact cookie cache (#233) | Organization owner; shared issuance and comparison prerequisite | Raw numeric lifetime and async version callbacks; Created/Stored/Cached inputs, cached guards, refresh/revoke/tamper, ordinary/API failure stages and rollback. Integration 25/1,204 across cache and anonymous owners; independent review clear. JWT/JWE and stateless modes remain issues. |
| Apple dedicated provider (#139) | OAuth owner; shared production JWKS verifier / direct ID-token error contracts | Actual published factory and official-client RSA/JWKS admission, hybrid form-post PKCE, enriched mapping and stable numeric subject/name, implicit signup / explicit request, replay, key retirement / restoration, real refresh ownership and logout; complete SQL rows and receipts. Source self 44 / 896; combined OAuth/OneTap differential 91 / 4,978; current-main native 788 default / 839 optional. [Apple audit](audits/apple-provider.md) documents prior generic API failures and supported option boundaries. Canonical measurement is recorded per PR. |
| Google default OAuth ID-token verification (#228) | OAuth owner; shared trusted JWKS policy and signed-profile mapping | Actual official social client and local RSA JWKS transport; scalar/array/empty audiences, issuers, exact/wildcard hosted domains, overrides, nonce, signature/key/age failures, original/foreign sessions and accepted token persistence. Source-self 14 controls; missing-default native 404 reproduced; differential and retained OAuth/One Tap controls pass. Independent production/authorization/primary-owner review clear after explicit audience precedence repair; integrated canonical gate pending. |
| Trusted setPassword (#185) | Password owner; duplicate account persistence #187 prerequisite | Public native server API, actual Source server API bridge, authoritative signed physical session, initialized UTF-16 bounds and genuine scrypt callbacks. Twelve SDK/SQL owners / 530 assertions include cached revoked/expired and actual foreign virtual authority, real hash/SQL failures, retry and null-credential concurrency. Runtime canonical-selector regression reproduced; coordinator review clear. Missing-credential dual creation and final-head canonical proof remain pending #187. [Audit](audits/server-set-password.md). |
| Passkey authentication callback deletion (#231) | Passkey owner; awaited real application deletion and optional store update result | Genuine signed assertion deletes the exact verified row yet issues only the original owner's session; actual SQLite deletion failure, wrong credential/challenge/signature, replay/retry and unchanged foreign principals. Complete passkey family 42 / 6,734; independent production and test review clear. Every prior route evidence requirement retained; concurrent deletion between store preload and write remains outside this bounded proof. |
| Database-state OAuth proxy | JWT owner; account-cookie age and comparison prerequisites | Two independent actual SQLite auth instances; real PKCE exchange without production identity writes, preview signup/link, origin/age/provider controls, consumption/replay, SQL deletion veto and ordinary/coded/cancelled session hooks. Four Source and differential owners / 694 assertions; native lifecycle 2 plus ordinary OAuth 18. Exact integration and independent review clear. Cookie-state, rotation and broader configurations remain issues. |

The final route inventory adds only the two genuinely registered proxy routes'
implementation flags. It keeps all **143** existing route identities and every
previous named requirement. Cache and proxy proof is added only from actual
passing differential artifacts; a proxy error redirect is not claimed as generic
rejection evidence. Both completion routes have real foreign-origin **403**
controls. All source/runtime artifacts are reproducible with the canonical gate.

## Validation record

Run `devenv shell -- ./scripts/check.sh` from the
integrated checkout. It serializes native/default/optional tests, strict Clippy,
Rustls/Redis, locked fixture builds, TypeScript, SDK, harness negative controls,
Chromium, alignment, Rustdoc and source coverage. Reports are generated under
`coverage/` and `tests/compat/client-tests/artifacts/` and uploaded by CI.

The last delivered, fully measured historical checkpoint is master `a3a9f568`,
full-tree equal to tested `f2e16ec5`: **543 SDK / 36,788 assertions**, **42 harness /
344 assertions**, **two Chromium / 22 assertions**, and **78.788518% source lines
(29,864 / 37,904)**. Those figures describe that checkpoint, not this later stack.

The intervening frozen 601-scenario gate passed **601 SDK / 43,802 assertions**
and **43 harness / 396 assertions**, then failed the required evidence gate for
26 unqualified declarations. The failure was retained. PRs #195–196 repair the
actual flow/annotations instead of deleting requirements; the combined passing
artifacts qualify all old 2,007 requirements. The compact-cache slice adds 43
and the proxy slice 26, for **2,076** retained or additive requirements. Final
canonical measurements belong to the final gate artifact and merge report;
focused results above are not substituted for it.

## Remaining work and merge boundaries

All known unfinished audit branches are linked from issue #234. Issues identify
confirmed differences separately from absent modes and unproved integrations.
They include 32 unimplemented dedicated provider factories; generic custom
providers already exist. Missing plugins and modes are not disguised by the
selected-profile HTTP inventory, even when all its routes are implemented.

Only parity-stack branches created for this work are merged. Unrelated open PRs
and the original dirty prototype checkout remain untouched. Exact-head squash
merges and rebases must preserve each reviewed layer's complete tree; the final
merged code/test tree must equal the final gated tree. Release notes here are
compatibility documentation and Rustdoc; deleted ROADMAP, docs directory and
CHANGELOG are not restored.


## Remaining-issue implementation work

| Issue | Implementation and primary evidence | Review |
| --- | --- | --- |
| #197 | Ordinary admin callback failures preserve empty500 through email, username and impersonation. Explicit application errors retain their responses; anonymous/cache configured failures preserve issued ownership and physical session state. Existing banned-message owner plus composition owner pass41 scenarios /3602 assertions. | Independent production review found no authorization or session-write-order issue. Full gate recorded in the PR. |

| #133 | Public bearer-to-signed-cookie adapter preserves real session ownership, configured signature requirements, issuance/exposure headers, browser precedence, revocation, expiry and API-key/multi-session composition. Three official-client owners / 416 assertions plus distinct completed native hook propagation proof. | Independent production/test review; exact pre-plugin and padding-alias failures retained. Additive public ReplaceHeaders enum migration documented in bearer audit; combined gate recorded in PR. |

| #180 dispatch policies | [Actual router/media/origin controls](audits/dispatch-security.md) | Official client and HTTP owner: 11 scenarios / 910 assertions, full physical owner/foreign rows; strict default, optional and fixture checks pass. Final integration gates recorded in PR. |
