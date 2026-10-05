# Architecture refactor implementation

The [resulting source inventory](source-inventory-after.tsv) lists every workspace source file after the refactor, using the same columns as the baseline inventory. Counts include inline tests and generated declarations; an absent test marker is `-`.

This change implements the internal ownership and file-organization pass from [the baseline review](README.md). It retains the eleven-crate topology and existing behavior. The crate is unreleased, so callers and documentation use the new canonical paths directly; obsolete module aliases are removed.

| Owner | Result |
| --- | --- |
| Root composition | `src/runtime/{builder,http,endpoint,http_hooks,builtin,body,routing}.rs`; shared router dispatch supervision in `src/integrations/dispatch.rs` |
| User profile update | Implementation in `api/plugins/user_management/update.rs`, called by the existing runtime route |
| Core stores | Contracts in `store/contracts`, initialized transforms/hooks and transactional decoration in `store/decorated`, domain implementations in `store/stateless` |
| Session caches | Cookie snapshots under `session/cookie_cache`, with issuance, read and cookie helpers under its runtime module; secondary storage under `store/secondary_storage` |
| Core plugin interfaces | Contracts, routes, extensions, initialization and context in separate files |
| Core configuration/types | Domain configuration files, grouped transport/write/response types, organization/plugin records under `types`, domain wire projections |
| Error presentation | `error/page.rs` and `error/page.html`; code catalog in `error/codes.rs` |
| OpenAPI | Generic contracts/assembly in core; built-in endpoint/model declarations and configuration overlays in API; plugin-owned static metadata used by the embedded builder |
| Authentication features | Two-factor, JWT, OAuth handlers/providers, email/password, API-key, device authorization and passkey implementations split by distinct flow or policy responsibility |
| Organization callbacks | Three domain hook files and one admission-policy module replace operation-specific lifecycle modules |
| Shared API flows | Session/credential/API-key helpers and validation/notification/field/session authentication services have named files |
| Generation tools | Shared entity codegen and backend macro internals split by generation phase; CLI selection and backend rendering separated from command/file handling |

Canonical public paths include `better_auth_core::session::cookie_cache`, `better_auth_core::store::secondary_storage`, `better_auth_core::error::page`, and `better_auth_api::plugins::organization::{hooks,policy}`. One Tap uses the shared `OAuthJwksSource` trait name. Convenient type exports remain where useful; old modules are not retained solely to preserve their previous spelling.

OpenAPI classification and documentation ownership now travel with plugin metadata. Core no longer enumerates built-in plugin names or special-cases username routes. Initialized metadata and document rendering retain the original policies. The shared framework dispatcher retains each framework's response renderer and detached request lifecycle.

Inline behavior tests remain with their existing owners. A public embedded-builder test covers plugin-owned metadata before initialization; the initialized registry tests exercise the same metadata through the live instance.

The broader proposals to redesign optional storage capabilities, gate every plugin, extract a published runtime crate, and generate all bundled migrations remain separate architectural changes, as recommended in the review. Backend query implementations and protocol verifier extensions retain their existing owners.
