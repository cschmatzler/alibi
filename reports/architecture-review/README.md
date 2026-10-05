This is the **pre-refactor assessment** at commit `14eaeb28`. Counts, paths and recommendations describe that baseline. See [the implementation record](implementation.md) for the resulting structure and deliberate API changes. Source links below are pinned to the reviewed commit.

Better Auth Rust architecture review, researched on 5 October 2026 against commit `14eaeb28`.

The workspace has sensible outer boundaries: shared core, built-in authentication features, two independent persistence adapters, and a separate schema/code-generation toolchain. The main refactoring opportunity is inside those boundaries. Core mixes contracts with substantial runtime behavior, the facade owns most orchestration, and some feature modules combine several independently understandable responsibilities. I recommend keeping the current crate topology for the first refactoring pass, establishing clearer internal owners, and considering a runtime crate only after that work exposes a useful boundary.

This review covers crate responsibilities, dependency direction, module placement, file organization, oversized files, and fragmentation. It is a static architecture assessment, not a behavior audit or implementation review. Measurements include comments, blank lines, declarations, generated annotations, and inline tests; they are not executable code counts. File lengths alone do not establish an architectural problem. Proposed structures below are recommendations, not existing directories.

Every Rust source file under the workspace libraries and CLI is listed in [source-inventory.tsv](source-inventory.tsv), with line counts, byte counts, and the first inline test-module marker where present. [crate-dependencies.tsv](crate-dependencies.tsv) records the crate inventory and normal workspace dependency edges. I examined all workspace manifests and module surfaces, traced responsibility and dependency boundaries, and inspected the important large files and representative smaller modules. The compatibility harness and repository tooling were checked for their structural role; this does not claim a line-by-line review of every function or test.

There are **11 workspace crates, 370 Rust source files, and 136,536 physical source lines** under `src/` and `crates/*/src/`. The excluded compatibility server is an additional Cargo package, not a workspace member. The source inventory includes dedicated test files under library source trees and inline tests.

| Crate | Source files / lines | What it actually owns | Assessment |
| --- | ---: | --- | --- |
| `better-auth`, repository root | 23 / 3,056 | Public re-exports, `BetterAuth`, builder, HTTP and direct endpoint dispatch, default plugin installation, Axum/Poem integration, telemetry | A composition root as well as a facade. Its name is fine; its internal `core` module obscures that distinction. |
| `better-auth-core`, `crates/core` | 83 / 31,487 | Schema/entity/store contracts, plugin interfaces and context, configuration, session and cookie-cache services, verification services, store decoration, middleware, wire projections, field policies, OpenAPI, compatibility utilities | Correct home for shared contracts and backend-independent services, but overbroad and internally mixed. Its manifest description understates its runtime role. |
| `better-auth-api`, `crates/api` | 164 / 81,517 | All built-in authentication plugins, shared authentication flows, OAuth providers, passkey verification extensions, OpenAPI presentation and token conversion tooling | Cohesive as a built-in feature crate. `api` is a less descriptive name than `plugins`, because the transport adapters and dispatch entry point live elsewhere. |
| `better-auth-sqlx`, `crates/sqlx` | 49 / 8,717 | SQLx pools/transactions, model/value abstractions, schema bindings, store implementations, hook bindings, rate-limit storage, bundled entities/migrations | Good boundary. Backend mechanics belong here. |
| `better-auth-seaorm`, `crates/seaorm` | 45 / 8,207 | SeaORM model bindings, store implementations, hook bindings, rate-limit storage, bundled entities/migrations | Good boundary. Keep independent from SQLx's adapter abstractions. |
| `better-auth-macros`, `crates/derive` | 1 / 282 | `AuthSchema` and `PluginConfig` derives | Appropriate proc-macro crate. Directory/package naming is inconsistent but harmless. |
| `better-auth-entity-codegen`, `crates/entity-codegen` | 1 / 736 | Shared entity attribute parsing, validation, accessor generation, secondary-storage codecs, insert/update plans | Valuable shared boundary. Internal organization can improve. |
| `better-auth-seaorm-macros`, `crates/seaorm-macros` | 1 / 600 | SeaORM `AuthEntity` derive and backend model generation | Correct proc-macro boundary. |
| `better-auth-sqlx-macros`, `crates/sqlx-macros` | 1 / 862 | SQLx `AuthEntity`/`SqlxModel` derives, column parsing and backend model generation | Correct boundary; its single file warrants splitting by generation phase. |
| `better-auth-schema-registry`, `crates/schema-registry` | 1 / 454 | Dependency-free core/plugin field definitions, extra entity definitions, schema lookup | One of the best boundaries in the workspace. Mostly declarative data; not a god file. |
| `better-auth-cli`, `crates/cli` | 1 / 618 | Plugin selection, schema rendering for both backends, SQL migration generation, CLI I/O | Correct independent tool; modest internal separation would help. |

The dependency graph is acyclic at the level of normal workspace dependencies:

```text
better-auth
  -> core
  -> api -> core
  -> sqlx [optional] -> core + sqlx-macros
  -> seaorm [optional] -> core + seaorm-macros

core -> macros + schema-registry
sqlx-macros -> entity-codegen -> schema-registry
seaorm-macros -> entity-codegen -> schema-registry
cli -> schema-registry
```

`api` has a SeaORM dev-dependency for its inline test setup. That does not make SeaORM a production dependency of the plugin crate. Likewise, the root dev-dependency enables adapters/frameworks for repository checks without changing downstream feature defaults. Keep this distinction when discussing crate layering.

The proc-macro crates are justified by Rust's crate model, and `entity-codegen` avoids duplicating backend-independent generation. The CLI's dependency only on the field registry keeps its schema-generation task independent from the authentication runtime. I would retain these boundaries rather than consolidate them merely to reduce the crate count.

The largest dependency-level limitation is feature granularity. `api` has TLS and Axum feature forwarding, but no per-plugin Cargo features. All built-in feature modules and their dependencies, including WebAuthn, OpenSSL, X.509 and several crypto libraries, participate in the dependency graph even when an application installs only email/password authentication. Runtime plugin registration is not compile-time dependency selection. This is a possible reason to introduce plugin features later; this review did not benchmark compile time or binary size. Enabling the Rustls HTTP feature does not remove the unconditional OpenSSL dependency used by passkeys.

The root crate's current module layout is mostly useful public forwarding. Its private `src/core/` and the public `crates/core/` have different roles, so the repeated name creates avoidable ambiguity: the former composes the product, while the latter supports plugins and adapters. The facade is also incomplete by design: the crate reference documentation tells users to depend directly on core for APIs it does not forward, such as user validation and some cache/JSON callback utilities. Decide which authoring APIs the facade promises to expose before making their current public modules private.

The root module map is:

| Area | Current files | Recommendation |
| --- | --- | --- |
| Public facade | `lib.rs`, `prelude.rs`, `config.rs`, `email.rs`, `error.rs`, `hooks.rs`, `middleware.rs`, `plugin.rs`, `plugins.rs`, `schema.rs`, `session.rs`, `store.rs`, `wire.rs`, `sqlx.rs`, `seaorm.rs` | Keep these small forwarding files. They provide stable, discoverable namespaces. Their small size is not excessive fragmentation. |
| Instance composition and dispatch | `core/mod.rs`, `core/auth.rs`, `core/endpoint.rs` | Rename the private directory to `runtime` or `server` and separate building, route resolution, HTTP dispatch, direct endpoint dispatch, body parsing, and built-in handlers. |
| Framework integrations | `integrations/mod.rs`, `integrations/axum/{mod,handlers}.rs`, `integrations/poem.rs` | Correct layer. Split by actual responsibilities where useful and share the dispatch supervisor mechanism. |
| Telemetry | `telemetry.rs` | Small, application-owned concern. Fine next to the composition root; move with it if a runtime crate is extracted. |

`src/core/auth.rs` is 1,438 lines with no trailing inline test section. It builds the initialized store/context, installs default features, aggregates field policies and OpenAPI metadata, configures middleware, normalizes requests, resolves routes, dispatches hooks, parses bodies, implements built-in responses, and updates users. Those are several owners in one file. The user-update endpoint in particular belongs alongside `UserManagementPlugin`, rather than in the top-level instance orchestration. `/ok` and `/error` can live in a small built-in endpoints module. See [auth.rs](https://github.com/cschmatzler/better-auth-rs/blob/14eaeb28/src/core/auth.rs), especially default installation around line 244, request dispatch around line 451, core handlers around line 960, user updates around line 1004, and body parsing around line 1236.

`src/core/endpoint.rs` owns both direct server endpoint dispatch and the HTTP endpoint hook bridge. These use related contracts but have different transport/error/header behavior. Give each a file and keep genuinely shared accumulation helpers together. The distinction should remain visible; combining them into one undifferentiated pipeline could erase compatibility semantics.

Both Axum and Poem implement their own lazy supervisor, job channel, reply channel, runtime recovery, and detached dispatch lifecycle. This is a concrete duplication candidate in [Axum handlers](https://github.com/cschmatzler/better-auth-rs/blob/14eaeb28/src/integrations/axum/handlers.rs) and [Poem integration](https://github.com/cschmatzler/better-auth-rs/blob/14eaeb28/src/integrations/poem.rs). A private shared `integrations/dispatch.rs` can own the task lifecycle while each framework keeps request buffering, response rendering, routing, and session extractors. A separate published crate per framework is optional and not justified by the current file sizes alone.

Core's modules need clearer responsibility names and some grouping:

| Current area | Files and responsibilities | Placement assessment |
| --- | --- | --- |
| Model and storage contracts | `schema.rs`, `entity.rs`, `adapter_record.rs`, `types/mod.rs`, `types_org.rs`, `types_plugin.rs` | Keep backend-independent contracts in core. Group types by domain; the current mix of transport types, write inputs, plugin records and views makes navigation harder. |
| User identity and projection | `authenticated_user.rs`, `user_validation.rs`, `user_query.rs`, `field_policy.rs`, `wire/mod.rs` | Correct shared layer. A coherent `identity` or `model` grouping would expose their relationship. Do not collapse physical entities, retained adapter output, public wire views and authenticated cache views into one type category. |
| Plugin integration | `plugin/mod.rs`, `hooks.rs`, `background_tasks.rs` | Plugin contracts and typed extension storage fit core; context initialization, projection and session operations should be separated from the trait declaration. |
| Endpoint contracts | `endpoint.rs` | Correct core ownership. Separate call/context, hook, request/output and task-local facilities if the file continues to grow. Dispatch remains in the composition layer. |
| Configuration | `config/{mod,origin,client_ip,secrets}.rs`, `config/error-page.html` | Core configuration is correct. Split the large declaration file by session/cookies, account/user, advanced settings and validation. Move HTML/error rendering out of configuration. |
| Sessions | `session/{mod,request}.rs`, `cache/{mod,runtime,jwt,date}.rs` | Correct backend-independent service, but split across misleading namespaces. Put cookie cache under `session/cookie_cache`; distinguish it from secondary cache storage. |
| Persistence services | `store/mod.rs`, `store/{adapter,database_hooks,migrations,org_extensions,secondary_sessions,jwks,wallets}.rs` | Contracts, shared hook queues and policy decoration fit core. The huge module root should become a small index over distinct contracts, decorators and transaction support. |
| Secondary cache backend | `store/cache/mod.rs` | Contains cache contracts and memory/Redis implementations. Rename or group as `secondary_storage` to distinguish it from cookie caching. Redis could become an adapter crate later if independently useful. |
| No-database backend | `store/stateless.rs` and its `api_keys`, `device_codes`, `invitations`, `jwks`, `members`, `optional_records`, `organizations`, `roles`, `teams`, `transaction` files | Correct shared fallback layer for now. Its main file still owns user/account/session/verification implementations; split these consistently with the existing domain files. `optional_records` combines two-factor and passkey storage. |
| Verification records | `verification.rs` | Shared publication, reservation and consumption semantics belong in core, not any single OTP/email plugin. A useful example of a shared service with a distinct owner. |
| Middleware | `middleware/mod.rs`, `body_limit/mod.rs`, `cors/mod.rs`, `csrf/mod.rs`, `rate_limit/{mod,bucket}.rs` | Sensible concern boundaries. Rate-limit configuration/storage/middleware can be split if needed; most middleware files do not need further subdivision. |
| Email | `email/mod.rs` | Shared provider contract and console implementation. Coherent and small. |
| Errors | `error/mod.rs` | Error types and rendering contracts fit core; the built-in message-to-code catalog, body validation and Axum conversion are separate responsibilities. |
| OpenAPI | `openapi/{mod,metadata,annotations,source_endpoints,source_models,input_annotations,model_annotations,account_annotations,email_annotations,oauth_annotations,password_annotations,session_annotations,sign_in_annotations,user_annotations}.rs` | Generic model/registry/document assembly fits core. Built-in plugin endpoint/model descriptions and plugin-specific enrichment should belong with the feature owners in `api`. |
| Compatibility utilities | `utils/{mod,javascript,json,cookie_utils,datetime,password,username,jwe,id,sessions}` | Cross-cutting formats and policies fit core. Group JavaScript JSON/date/coercion behavior explicitly as compatibility infrastructure. Place cookie/password/username behavior with their domain. |
| Administrative token conversion | `oauth_token_conversion.rs` | Appropriate storage capability contract. Its policy/crypto implementation in `api/plugins/oauth_token_conversion.rs` is a sibling of plugins despite registering no plugin; group under administrative migration tooling or OAuth maintenance. |

Core is already a runtime support crate, not a traits-only foundation. Splitting it immediately into many tiny crates would make the dependency graph more complex without first establishing ownership. Improve its internal domains before deciding whether contracts and services truly need independent compilation/publication.

The strongest core file problem is [store/mod.rs](https://github.com/cschmatzler/better-auth-rs/blob/14eaeb28/crates/core/src/store/mod.rs): **3,625 lines, with no trailing inline test module**. It contains every major store trait, the aggregate `AuthStore`, transaction contracts, transform registration, adapter observers, the policy-decorating `PluginStore`, per-domain forwarding implementations, and transaction decoration. Roughly the first 2,150 lines are decoration/implementation, followed by contract definitions and helpers. This makes it hard to distinguish what a backend must provide from what the initialized auth instance adds.

A proposed organization is `store/contracts/{user,session,account,verification,organization,two_factor,api_key,passkey,device,jwk,wallet,transaction}.rs`, `store/decorated/{mod,user,session,account,verification,transaction}.rs`, and a small module root that re-exports the existing public names. Team/member/invitation/role contracts can be grouped with organization initially. Preserve transaction and post-commit observer ownership across this move; they are one architectural concern even when implemented across files.

There is also a real extensibility constraint: [AuthStore](https://github.com/cschmatzler/better-auth-rs/blob/14eaeb28/crates/core/src/store/mod.rs) requires **16 component traits**, covering all built-in plugin domains as well as basic user/session/account/verification storage and transactions. Some extension methods have unsupported defaults, but every adapter must still satisfy the aggregate trait surface. [AuthSchema](https://github.com/cschmatzler/better-auth-rs/blob/14eaeb28/crates/core/src/schema.rs), by contrast, exposes only four associated entity types: user, session, account and verification. Plugin records largely use concrete framework types. This asymmetry is intentional in the current design, but it means plugin modularity does not extend all the way to independently owned storage/model contracts.

I would first make those contracts discoverable through domain modules without changing trait bounds. A later design decision can introduce typed capability registration or capability subtraits for optional plugin storage. Moving the same mandatory traits into separate files does not solve that extensibility problem, and moving them into `api` would reverse the adapters' dependency direction. A separate contracts crate for each plugin is not warranted yet.

[plugin/mod.rs](https://github.com/cschmatzler/better-auth-rs/blob/14eaeb28/crates/core/src/plugin/mod.rs) has about 1,450 lines before its trailing tests. Its `AuthPlugin` contract, route table macro, route definitions, initialization context, runtime context, user/session projection and authenticated session operations deserve separate files. The context currently acts as a service container and a service facade. Keep its convenience methods if useful, but let named services/modules own the underlying behavior. Avoid turning a file split into many context wrappers that add no architectural boundary.

The session ownership issue spans [session/mod.rs](https://github.com/cschmatzler/better-auth-rs/blob/14eaeb28/crates/core/src/session/mod.rs), [cache/runtime.rs](https://github.com/cschmatzler/better-auth-rs/blob/14eaeb28/crates/core/src/cache/runtime.rs), context methods in `plugin/mod.rs`, [store/secondary_sessions.rs](https://github.com/cschmatzler/better-auth-rs/blob/14eaeb28/crates/core/src/store/secondary_sessions.rs), and `api/plugins/helpers.rs`. These represent different phases: stored session access/refresh, cookie cache admission and publication, secondary storage representation, and feature policy applied during issuance. A `session` domain should make those phases explicit. `StatelessStore` also retains instance-local users, accounts, verification and plugin records; its name describes session/no-database policy rather than an absence of all server-side state. Prefer a `no_database` internal module name while preserving the public type if renaming would break callers. Backend storage remains in the adapters; admin ban checks and other plugin participation should be registered policy or clearly owned shared feature behavior, not arbitrary helpers scattered through the plugin crate.

[cache/runtime.rs](https://github.com/cschmatzler/better-auth-rs/blob/14eaeb28/crates/core/src/cache/runtime.rs) is 1,025 lines with no trailing test section. It owns request-scoped issued/published/established session state, cookie chunk reading/writing, cache header construction, cookie publication, cache renewal and authenticated reads. Suggested files are `state.rs`, `cookies.rs`, `read.rs`, `issuance.rs`, and `codec.rs` under a session cookie-cache module. Keep trust distinctions visible: a valid public cache snapshot is not interchangeable with an authoritative typed database model.

OpenAPI's dependency direction is technically legal but semantically inverted. [AuthPlugin::openapi_metadata](https://github.com/cschmatzler/better-auth-rs/blob/14eaeb28/crates/core/src/plugin/mod.rs) defaults to a core function that knows plugin names and built-in route declarations. Core's [source_endpoints.rs](https://github.com/cschmatzler/better-auth-rs/blob/14eaeb28/crates/core/src/openapi/source_endpoints.rs) contains admin, organization, API key, passkey and other feature descriptions; annotation modules additionally inspect instance configuration and feature metadata. A plugin change can therefore require changes below the plugin crate. Leave generic OpenAPI types, registration and document assembly in core; move built-in descriptions and their enrichment into `api`, with each plugin supplying metadata through its existing hook. Keep core model descriptions associated with shared schema contracts.

The generated OpenAPI endpoint catalog is **100,801 bytes despite only 117 lines**. It is a concentrated data catalog rather than a behavioral god file. Splitting generated output by plugin is useful for ownership and navigation, but the generator should perform that split. Do not manually refactor generated declarations, infer simplicity from the line count, or combine generated source data with hand-maintained metadata enrichment.

[error/mod.rs](https://github.com/cschmatzler/better-auth-rs/blob/14eaeb28/crates/core/src/error/mod.rs) has about 1,080 lines before tests; much of that is a global message-to-code catalog. Separate the catalog from error types, serialization and validation. Most built-in plugin error catalog ownership can move alongside plugin metadata if compatibility lookups still need a shared fallback. Its optional Axum `IntoResponse` implementation is the only direct Axum reference in core. That is a small layering leak; a framework wrapper in the integration layer can remove it later without making this an urgent crate split. Rust's orphan rules mean moving the same impl verbatim into another crate will not work.

The built-in feature crate is organized almost entirely as `api/plugins/<feature>`. That is a good domain-first starting point. The main issue is inconsistent division between configuration, public callback contracts, HTTP wrappers, direct endpoint adapters, shared flow logic and compatibility codecs.

| Feature | Current organization | Assessment and suggested direction |
| --- | --- | --- |
| Account management | `account_management.rs` | 124 lines; keep together. Its list-accounts handler reaching into organization session helpers is misplaced sharing. |
| Admin | `mod`, `handlers`, `types`, `access`, `callbacks`, `validation` | Already broadly sensible. Main implementation is about 708 lines before tests; do not split on its total length alone. |
| Anonymous | `anonymous.rs` | Single cohesive feature file; keep until distinct responsibilities justify expansion. |
| API key | `mod`, `endpoint`, `handlers`, `handlers/metadata_sort`, `types`, `storage`, `verification`, `callbacks`, `secondary_usage` | Strong existing decomposition. Main implementation is about 1,137 lines before tests, mainly config, key generation, validation, cleanup and plugin integration. Move config and cleanup lifecycle out; do not rebuild its storage architecture merely because tests make the file 4,207 lines. |
| Bearer, CAPTCHA, custom session, last login method | One file per feature | Reasonable sizes and focused behaviors. Keep as individual modules. |
| Device authorization | `mod`, `types` | About 1,053 lines before tests in the root. Separate configuration/callbacks, issuance/redemption/decision flow, and request/response media handling. |
| Email OTP | `mod`, `endpoint`, `handlers`, `types`, `storage`, `helpers` | Root is only about 355 lines before tests; already split well. The 759-line handler file can divide issuance, verification/sign-in and password reset if those owners are hard to follow. A 33-line helpers file is minor cleanup. |
| Email password | `mod`, `signup` | Main implementation is about 1,395 lines before tests and combines config, request/response types, signup, email/username sign-in, callbacks, synthetic users and plugin routing. Split along those feature operations. `signup.rs` alone does not capture the signup flow. |
| Email verification | `mod`, `handlers`, `types`, `token` | Root is about 421 lines before tests; keep the current broad split. |
| JWT | `mod`, `crypto`, `endpoint` | Main implementation is about 1,669 lines before tests. Separate config/claims, keyring management, signing, verification, JWKS/session issuance and cookie-cache integration. Keep shared key selection consistent across uses. |
| Magic link | `mod` only | About 442 lines before tests. Not an urgent production split. Token storage and callbacks could get their own files when needed. |
| Multi-session | `mod` only | About 406 lines before tests. Focused enough to keep together. |
| OAuth | `mod`, `types`, `state`, `account`, `client_assertion`, `id_token`, `logout`, `account_cookie/mod`, `encryption/mod`, `handlers/mod`, `providers/*` | Largest feature area: 45 files / 15,243 total lines. Provider files are good domain boundaries; the handler module and provider module root are overloaded. See below. |
| OAuth popup | `oauth_popup.rs`, `oauth_popup_script.js` | Cohesive feature plus embedded browser asset; keep together conceptually. |
| OAuth proxy | `oauth_proxy.rs` | 1,035 implementation lines, no trailing tests. Split state/payload codec, initiation/completion flow and request hooks. Own its error signals through the dispatch contract rather than root knowledge of a feature-specific marker. |
| One tap | `mod` only | Small enough to keep. Its reuse of OAuth identity processing is legitimate. |
| One-time token | `mod`, `endpoint` | Existing separation is sufficient for current implementation size. |
| OpenAPI UI | `mod`, `logo.svg` | Correct feature placement. Shared metadata/document assembly is a different concern from this HTTP UI. |
| Organization | `mod`, `endpoint`, `types/mod`, `rbac/mod`, `extensions`, policy files, lifecycle callback files, domain handlers | 26 files / 11,810 total lines. Domain handler splits are mostly sound; callback/policy files are fragmented and public. Root is about 599 lines before tests. |
| Passkey | `mod`, `types`, `handlers`, `registration`, `authentication`, `webauthn`, `raw_none`, private `source/*`, `tests/revocation` | Good separation around protocol extensions, but handler flows are still concentrated. Rename ambiguous codec/verifier modules carefully and consider an optional feature boundary. |
| Password management | `mod`, `handlers/mod`, `types`, `set_password` | Root is about 328 lines before tests. Already reasonable; extra splits are not urgent. |
| Phone number | `mod`, `handlers`, `types` | Root is about 164 lines before tests; handler operations are the area to examine, not the root. |
| Session management | `mod` only | About 557 lines before tests. Keep focused; move generic issuance infrastructure into the shared session domain rather than proliferating feature files. |
| SIWE | `mod`, `config`, `parse`, `validation`, `crypto` | Sensible split by responsibilities. Keep. |
| Two-factor | `mod`, `endpoint`, `otp`, `otp_storage`, `backup_storage` | 2,615 lines before tests in the root. Strong split candidate: TOTP/enrollment, OTP delivery/verification, backup codes, pending challenges/trusted devices, lockout, configuration/types and cookie/legacy codecs. |
| User management | `mod`, `handlers`, `types` | Already modest production files. Consolidate ownership of user update with this feature. |

Shared feature files are `helpers.rs`, `authentication_helpers.rs`, `endpoint.rs`, `token_crypto.rs`, `passwordless_numeric.rs`, plus the administrative `oauth_token_conversion.rs`. Two helper modules have become unhelpful catch-all owners. [helpers.rs](https://github.com/cschmatzler/better-auth-rs/blob/14eaeb28/crates/api/src/plugins/helpers.rs) combines session issuance/publication, credential account lookup, API-key ownership, organization permission checks, admin ban policy and cookies. [authentication_helpers.rs](https://github.com/cschmatzler/better-auth-rs/blob/14eaeb28/crates/api/src/plugins/authentication_helpers.rs) combines JSON validation, email parsing, verification lookup, additional fields, notifications, session responses and access revocation. Proposed shared modules are `sessions`, `credentials`, `request_validation`, `notifications`, and `api_key_authorization`. Keep each only where it has multiple real consumers.

The dependency on organization helpers from [account_management.rs](https://github.com/cschmatzler/better-auth-rs/blob/14eaeb28/crates/api/src/plugins/account_management.rs) is a concrete placement problem. Basic session admission should not be owned by an organization handler module. API-key ownership/organization permission behavior in generic `helpers.rs` should similarly have an explicit feature-facing owner.

Some feature coupling is essential: two-factor participates in sign-in, admin ban policy participates in session creation, OAuth proxy modifies OAuth flows, and one-tap shares OAuth identity processing. However, the source also has mutual references such as OAuth/proxy, email-password/phone/two-factor, and helpers/admin/API-key/organization. These are legal inside one crate but make arbitrary crate-per-plugin extraction expensive. Introduce shared services or registered hooks/policies where they represent actual ownership; preserve deliberate integrations rather than trying to eliminate every cross-feature dependency.

[OAuth handlers](https://github.com/cschmatzler/better-auth-rs/blob/14eaeb28/crates/api/src/plugins/oauth/handlers/mod.rs) is the largest behavioral feature file: about 3,210 lines before tests. It handles authorization URL and PKCE generation, provider token exchanges and refresh, profile fetching, account cookies, redirects, user admission and account linking, ID-token sign-in/linking, flow initiation and callback completion. Suggested owners are `authorization.rs`, `token_exchange.rs`, `identity.rs`, `linking.rs`, `callback.rs`, and `http.rs`. Existing `state`, `account`, `id_token`, and `client_assertion` modules should remain distinct and receive behavior that already belongs to them rather than become duplicated peers.

[OAuth providers/mod.rs](https://github.com/cschmatzler/better-auth-rs/blob/14eaeb28/crates/api/src/plugins/oauth/providers/mod.rs) mixes provider interfaces and policies with embedded GitHub/Google/GitLab/Discord implementations. Most other providers already have named files. Move these remaining provider implementations into named files; separate generic provider contracts/policies from the provider catalog. The 578-line `remaining_profile.rs` is an ambiguous shared compatibility bucket; name its responsibility and distinguish universal coercion rules from provider-specific profile behavior. Per-provider files around 120–400 lines are useful separation, not excess fragmentation.

[Two-factor/mod.rs](https://github.com/cschmatzler/better-auth-rs/blob/14eaeb28/crates/api/src/plugins/two_factor/mod.rs) combines several security flows and their persistence/cookie policy. Its total 5,079 lines overstates implementation size, but the 2,615-line production prefix is still large and spans genuinely different responsibilities. Keep challenge resolution, verification attempt state, lockout and final session publication together architecturally even when their implementations are split. Splitting every helper into its own file would make the phase ordering harder to inspect.

[Passkey handlers](https://github.com/cschmatzler/better-auth-rs/blob/14eaeb28/crates/api/src/plugins/passkey/handlers.rs) has 1,050 lines covering registration option creation, authentication option creation, registration verification, authentication verification, and credential management. `registration.rs` and `authentication.rs` already define callback contracts; give ceremony flow implementation a clearly named home beside them. `source/` contains the private verifier extensions and provenance/license documentation. [Its README](https://github.com/cschmatzler/better-auth-rs/blob/14eaeb28/crates/api/src/plugins/passkey/source/README.md) explains the pinned registry types and legacy persisted codecs. This is a legitimate compatibility/protocol boundary, not evidence that a copied library should be folded into generic core utilities. Rename `source` to `verification` or `verifier` if doing so clarifies ownership. `raw_none.rs` now handles raw credential compatibility, decoding and proof verification beyond the old name; a codec/verification split would be clearer.

The clearest excess fragmentation is organization callback organization. Small files such as `creation_policy.rs` (17 lines), `member_removal_lifecycle.rs` (31), `invitation_acceptance_lifecycle.rs` (44), `member_addition_lifecycle.rs` (50) and `member_role_lifecycle.rs` (50) mostly define closely related callback contexts and traits. The distinction between admission, removal and invitation phases is real, but it does not require a new public top-level module for every operation. A proposed `organization/hooks/{organization,member,invitation}.rs` and `organization/policy.rs` would retain distinct contracts while reducing navigation overhead. Preserve current re-export paths during a mechanical move if downstream callers use them.

The 23-line `organization/handlers/page.rs` contains a focused page error adapter. It could join the relevant shared handler response module, but keeping a tiny module for an explicit error boundary is also defensible. Tiny forwarding modules such as `core/store/jwks.rs`, `wallets.rs`, `migrations.rs` and adapter `hooks.rs` express meaningful contracts and should not be merged on line count alone.

Several directories contain only `mod.rs`, including OAuth handlers, organization types/RBAC/org handlers, password-management handlers, and SeaORM sessions/members/invitations/JWKS/migrator. This is filesystem overhead rather than an architectural defect. Use `name.rs` when a module is one cohesive file; use `name/mod.rs` when it has children or is intentionally about to gain them. The backend adapters currently use different conventions for equivalent domain modules. Standardize opportunistically rather than making it an independent refactor.

The storage adapters' domain decomposition is already one of the strongest parts of the architecture. Both have files for users, sessions, accounts, verifications, organizations, members, invitations, teams, organization roles, API keys, two-factor records, passkeys, device codes, JWKs and wallets. Per-table entity files are small because they are models; their correspondence with store modules is useful. Keep database-specific SQL construction, SeaORM queries, row decoding, transaction connections and locks in their respective adapter crates.

`sqlx` additionally owns `pool.rs`, `sql.rs`, `model.rs`, `value.rs`, `error.rs`, `schema.rs`, `additional_fields.rs`, `json_metadata.rs`, `hooks.rs`, and `rate_limit.rs`. These expose the small SQLx-side model/runtime abstraction needed by generated application entities. `seaorm` owns parallel schema/additional-field/JSON/hook/rate-limit support plus `conversions.rs`, using the ORM's native model layer. Those differences are appropriate; forcing the adapters through a universal ORM abstraction would obscure the existing backend boundaries.

Both `store/mod.rs` files are around 450 lines and contain the store object, initialization/hooks, transaction wrapper and `AuthTransaction` implementation. They could split transaction support into `transaction.rs`, but they are not high-priority god files. The largest domain implementations—users, sessions, verifications, teams—contain matching store operations and backend mechanics. Divide them only when a distinct hook pipeline, query construction or transaction staging concern needs an owner, not at an arbitrary line threshold.

There is duplicated backend-independent compatibility logic around `JsonMetadata`, wallet chain IDs, API-key starting characters, date/window handling in `api_key_usage_phases.rs`, user email/filter conversion, verification publication stages and OAuth token conversion. Share pure value/normalization rules where both adapters need the exact same behavior; leave SQL/ORM encoding and atomic update mechanics local. Identical type names do not prove the entire type can be moved into core: some database trait implementations require local wrappers under Rust's orphan rules.

Bundled entities and migrations coexist with application-owned generated schemas. They are not merely test-only production seams: each adapter implements the runtime `SchemaMigrator` capability using its bundled migration, although internal bundled-schema helpers are also exposed through `__private_test_support`. Keep the public migration role distinct from fixture convenience. The registry, CLI-generated models/DDL, SQLx's bundled SQLite/PostgreSQL SQL files, and SeaORM's 777-line migration implementation represent multiple schema representations. The registry is already the central field source; a future generation step can keep bundled artifacts aligned with it. Treat stored schema/migration compatibility as a separate decision from file moves.

The schema/code-generation toolchain needs internal files, not additional crates:

| Current file | Proposed organization | Reason |
| --- | --- | --- |
| `entity-codegen/src/lib.rs`, 736 lines | `attributes`, `fields`, `accessors`, `secondary_codec`, `write_plan`; thin `lib.rs` | Attribute validation, trait generation and write plans are distinct phases shared by both backends. |
| `sqlx-macros/src/lib.rs`, 862 lines | `roots`, `columns`, `model`, `entities`; thin macro entry point | Path resolution, physical column mapping and generated backend entity behavior are separate concerns. |
| `seaorm-macros/src/lib.rs`, 600 lines | Similar phase names where they correspond | Keep backend-specific generation local and reuse the existing shared codegen. |
| `derive/src/lib.rs`, 282 lines | Optional `auth_schema` and `plugin_config` modules | Two unrelated derives, but the file is small enough that this is low priority. |
| `schema-registry/src/lib.rs`, 454 lines | Keep, or separate `core` and `plugins` declarations if navigation becomes difficult | Declarative registry with few lookup functions. Its size does not justify a major split. |
| `cli/src/main.rs`, about 560 lines before tests | `selection`, `render/sqlx`, `render/seaorm`, `ddl`; small command entry point | Separate reusable schema rendering from arguments, filesystem output and diagnostics. |

The CLI emits application schema/model declarations, while `entity-codegen` emits implementations of traits from derive inputs. They consume the same registry but do different jobs. A single generic generator would not automatically improve the architecture. Share only genuinely common schema/type/field planning if duplication becomes demonstrated.

The most useful prioritization uses implementation responsibility and test-adjusted length:

| Priority | File or area | Approximate lines before trailing tests | Refactoring objective |
| --- | --- | ---: | --- |
| First | Core `store/mod.rs` | 3,625 | Separate adapter contracts from initialized store decoration and transactions. |
| First | OAuth `handlers/mod.rs` | 3,210 | Separate protocol exchange, identity/linking, callback lifecycle and HTTP adaptation. |
| First | Two-factor `mod.rs` | 2,615 | Give each factor/challenge/lockout/codec responsibility a clear owner. |
| First | Root `core/auth.rs` | 1,438 | Make composition, dispatch, request parsing and built-in endpoint ownership explicit. |
| First | Core plugin/context and session/cache ownership | 1,450 in plugin root; 1,025 in cache runtime | Separate contracts, context/service access and session phases. |
| Next | JWT `mod.rs` | 1,669 | Split claims/keyring/signing/verification/cache integration. |
| Next | Email password `mod.rs` | 1,395 | Separate config/types/signup/email and username sign-in. |
| Next | OpenAPI ownership | 100 KB generated endpoint catalog plus annotation modules | Move built-in feature knowledge above generic core contracts. |
| Next | Shared plugin helper modules | 714 and 598 | Name the shared services and remove feature-owned helpers from catch-all modules. |
| Next | Device authorization, OAuth proxy, passkey handlers | 1,053 / 1,035 / 1,050 | Split distinct flows/codecs/transport responsibilities. |
| Later | Organization callback grouping | Several 17–88-line modules | Consolidate related public callback contracts and preserve useful lifecycle distinctions. |
| Later | Codegen, backend transaction roots, config/types/wire | Various | Improve navigation after runtime and feature ownership is settled. |

Conversely, do not prioritize `organization/mod.rs` just because it has 3,987 total lines: only about 599 precede its tests. `email_otp/mod.rs` is about 355 implementation lines despite 2,167 total; email verification is about 421 despite 2,120 total; phone number about 164 despite 1,163 total; password management about 328 despite 1,350 total. Test placement can be revisited separately, but moving tests alone does not change production architecture. This report classified test sections for measurement and did not audit test quality.

A proposed first-pass target keeps all existing crates and reorganizes private modules:

```text
better-auth
  runtime/       builder, initialization, routing, HTTP/direct dispatch
  integrations/ shared task lifecycle and framework-specific conversion/extractors
  public facade namespaces

core
  model/         schema, entities, write inputs, retained records and projections
  plugin/        contracts, routes, initialization context, runtime context
  session/       session service, cookie cache, request state and publication
  verification/  shared record lifecycle
  store/         contracts, decorated store, transactions, secondary storage, noDB
  config/        domain settings and validation
  openapi/       generic metadata registry and document assembly
  compat/        shared JavaScript JSON/date/coercion rules
  middleware/    independent request protections

api
  plugins/       domain-organized feature implementations
  shared/        session/credential/validation/notification services
  metadata/      built-in feature descriptions, generated by feature
  maintenance/   administrative conversion tools

sqlx, seaorm
  schema/model support, store domains, transactions, backend codecs

schema-registry, entity-codegen, proc-macro crates, cli
  same dependency graph; clearer internal generation phases
```

These directories are an ownership sketch, not an instruction to mechanically introduce every folder. Retain existing public paths through re-exports where practical. In particular, many current modules and organization callback paths are public, generated entities rely on facade/private re-exports, and macros resolve crate names. File moves can be behavior-preserving while public module renames are still breaking changes.

After those internal moves, decide whether the composition layer deserves a published `better-auth-runtime` crate. A viable dependency direction is `runtime -> core + api`, with the facade depending on runtime and optional adapters, and framework integration remaining in the facade or separate framework crates. Extracting a plugin-aware runtime into core would create the wrong direction because `api` already depends on core. The extracted runtime would still be coupled to built-ins if it installs the same defaults; that is a valid product choice, but not a pure plugin-independent kernel.

Per-plugin feature gates are a more direct way to address dependency selection than immediately publishing many plugin crates. Passkey is the clearest candidate because it has a distinct protocol/compatibility subsystem and dependency set. Independent OAuth/organization/JWT crates become more feasible after shared services, policy hooks and OpenAPI ownership have been clarified. There is no evidence from this static review alone that each plugin needs its own release unit.

I recommend sequencing the work as follows:

1. Agree on the responsibilities of facade/composition, core services/contracts, built-in features and adapters. Record the direction before moving files.
2. Make mechanical private file moves for store contracts/decorators, root runtime orchestration, plugin/context and session/cache. Preserve behavior, trust distinctions, transaction phases and public names.
3. Split OAuth and two-factor by flow ownership, then JWT and email/password. Do not mix those moves with behavior redesign.
4. Relocate built-in metadata and helper ownership. This is where module boundaries become more meaningful than mere file size reduction.
5. Group organization callback surfaces and normalize module conventions opportunistically.
6. Reassess optional storage capabilities, feature gates and a runtime crate. These are architecture/API choices with broader consequences and should be separate from the mechanical reorganization.

The repository already documents a differential compatibility suite, workspace integration/e2e tiers, feature builds, rustdoc/doctests, formatting and lint checks in its development guide. Use those existing checks as appropriate when implementing the refactor. No tests or builds were run for this research-only change, and no application code was modified. The only added files are this report and its inventories.
