# Better Auth 1.7.6 runtime capability audit

This is an implementation ledger input, not a parity completion claim. The
reference remains `better-auth@1.7.6`, `@better-auth/core@1.7.6`,
`@better-auth/passkey@1.7.6`, and `@better-auth/api-key@1.7.6`. Source paths below
are relative to the upstream `v1.7.6` tag unless they begin with `crates/`.
Published runtime sources were inspected in the reference server's installed
packages; the matching tag was downloaded separately for types and tests.

At merged baseline `ae4aa46`, the committed HTTP inventory contains 143
method/path identities, 20 marked missing and seven implemented without
successful scenario evidence. It covers selected profiles. Runtime factory inspection
confirmed a further bundled route, `GET /oauth-popup/start`, missing from those
profiles. Server-only functions and middleware have no route evidence in that
inventory. Additional packages listed below are also outside the profiles.

## Shared contracts and implementation dependencies

- Email OTP, magic links, one-time tokens, OAuth state, SIWE, and phone OTP all
  use verification rows. Preserve identifier scope, expiry, attempts, newest-row
  selection, issuance replacement, and atomic consumption. A successful token
  consumption cannot leave reusable sibling rows.
- User extensions: `isAnonymous` defaults to false, is non-input, and is returned;
  `phoneNumber` is optional, unique, sortable, and returned;
  `phoneNumberVerified` is optional, returned, and non-input, with no schema
  default; `lastLoginMethod` is optional/non-input only with database storage.
- New models: teams, team members, organization roles, JWKS, wallet addresses,
  then the independently packaged integrations' models. Optional plugin models
  must preserve the repository's custom-entity schema contracts.
- Session-creation side effects must compose for every authentication method:
  admin bans, anonymous account linking, multiple sessions, JWT/OTT headers,
  last login tracking, cookies, custom session output, and lifecycle hooks.
- Server-only calls need a controlled fixture interface. They must not become
  public authentication paths merely to obtain scenario evidence.

## Core behavior beyond route existence

| Family | Required branches/evidence | Upstream source |
| --- | --- | --- |
| Email/password | Enabled/disabled signup, `autoSignIn`, verification-required synthetic duplicate responses, `onExistingUserSignUp`, synthetic-user customization, custom hashing/verifying, min/max password length, reset callbacks and session revocation | `packages/better-auth/src/api/routes/{sign-up,sign-in,password}.ts` |
| User validation and updates | `validateUserInfo` for each identity source; additional-field required/default/input/returned/validator/transform behavior; unknown-field handling; immutable/non-input fields | `packages/core/src/types/init-options.ts`; `packages/better-auth/src/db/schema.ts` |
| Email verification/change/deletion | Send-on-signup/signin defaults, expiry, before/after hooks, auto-signin, unverified email promotion, confirmation of old/new emails, delete verification sender/expiry/hooks/freshness and token-owner checks | `packages/better-auth/src/api/routes/{email-verification,update-user}.ts` |
| Server-only core operation | `auth.api.setPassword`: create credentials for authenticated passwordless user; reject existing password and invalid password; no public route | `packages/better-auth/src/api/routes/update-user.ts` |
| Session lifecycle | GET/POST refresh and deferral, no-refresh modes, fresh/sensitive authoritative sessions, remember-me, cache version callback/string, compact/JWT/JWE cache, stateless default JWE+refreshCache, revocation after cached sessions, additional-session-field updates | `packages/better-auth/src/api/routes/{session,update-session}.ts`; `src/cookies/`; `src/context/store-capabilities.ts` |
| Storage modes | Database, secondary-only, combined `storeSessionInDatabase`/`preserveSessionInDatabase`, verification `storeInDatabase`/`storeIdentifier`/cleanup, atomic rate limiter storage and custom storage | `packages/better-auth/src/db/internal-adapter.ts`; `src/context/create-context.ts`; `src/api/rate-limiter/` |
| Security/configuration | Secret version rotation; dynamic base URL allowed hosts/protocol/fallback; dynamic trusted origins/providers; secure/prefixed/domain cookies and overrides; trusted proxies/CIDR and IPv6 subnet; CSRF/origin opt-outs; disabled paths/trailing slashes; response cache-control and media-type validation | `packages/core/src/types/init-options.ts`; `packages/better-auth/src/context/`; `src/api/{index,middlewares}/`; `src/cookies/` |
| Lifecycle/plugin composition | Ordered plugin init, endpoint replacement, global before/after hooks, request/response hooks, mutable database hooks with cancellation; user/session/account/verification create/update/delete; background tasks and error behavior | `packages/better-auth/src/api/{dispatch,to-auth-endpoints,index}.ts`; `src/context/helpers.ts`; `src/db/with-hooks.ts` |

These branches require explicit fixture configurations. The default fixture's
successful endpoint scenarios do not account for them.

## Bundled plugins and pinned installed extension packages

All bundled plugin directories were enumerated and their runtime factory
surfaces inspected. Existing implementation does not establish the branch
evidence listed here. Owners should compare upstream tests as well as routes.

| Family | Missing behavior / branch target | Source and dependencies |
| --- | --- | --- |
| Organization | Teams/default team/custom creator/limits/last-team deletion; dynamic roles, arbitrary resource permissions and escalation rejection; invitation email verification/reinvite cancellation/limits; callback limits and hooks; server-only `addMember`; `getOrganization` output | `packages/better-auth/src/plugins/organization/{organization,types,adapter,has-permission}.ts`; `routes/crud-{org,members,invites,team,access-control}.ts`; models and activeTeamId |
| Email OTP | Full send/check/signin/verify/reset/change-email family; server-only create/get OTP; 6 digits/300 s/plain default; 3 attempts; rotate/reuse; hashed/encrypted/custom storage; signup/verification override hooks; current-email verification and sender failures | `plugins/email-otp/{index,routes,types,otp-token,utils}.ts`; verification and password/user lifecycle |
| Magic link | Issue/deliver/consume; default 300 s; plain/hashed/custom hasher; signup disabled; metadata; callbacks/no-callback JSON; verified-email promotion revokes unproven credentials/sessions; invalid/expired/replay/race | `plugins/magic-link/index.ts`; verification, origin validation, session lifecycle |
| Phone number | Password signin, send/verify/change/reset; server-only `consumePhoneNumberOTP`; 6 digits/300 s/3 attempts; custom validator and verifier; verification-required signin; optional signup/temporary email+name; callback; null clears verified state; direct update blocked | `plugins/phone-number/{index,routes,types,schema}.ts`; unique user phone fields and verification |
| Anonymous | Signin/delete, repeat anonymous signin denial; generated email/name; custom domain/email; deletion disabled; account-link hook and cleanup on every auth method; OAuth state fallback when cookie absent | `plugins/anonymous/{index,types,schema}.ts`; user field and response hooks |
| Multiple sessions | Cookie-set membership, default maximum 5, list/set-active/revoke, foreign device token rejection, expiry/cookie cleanup, signout interaction and duplicate/eviction behavior | `plugins/multi-session/index.ts`; signed per-device cookies and response hooks |
| JWT/JWKS | Default EdDSA/Ed25519 and 15 m token; server-only sign/verify; protected-header/key pinning; rotation/grace; keyring persistence/private-key encryption; custom paths/remote signer/adapter; session cache key use; new-session JWT header | `plugins/jwt/{index,types,adapter,sign,verify,utils,schema}.ts`; JWKS model and asymmetric crypto |
| One-time token | Issue/consume existing session; 3 m default; plain/hashed/custom token storage; cookie disabled/client disabled; new-session `set-ott` header; expired/revoked session, race/replay rejection | `plugins/one-time-token/index.ts`; verification and response hooks |
| OAuth proxy | Different current/production hosts, shared secret/max-age, encrypted profile payload, signed state cookie and origin binding, proxy completion, tamper/expiry, normal-flow bypass and cookie-less callback handling | `plugins/oauth-proxy/index.ts`; OAuth provider/state helpers |
| One Tap | Google ID token signature/audience/nonce/email checks; signup disabled; existing account/linking semantics; session/callback behavior | `plugins/one-tap/index.ts`; local deterministic Google JWKS/token fixture |
| SIWE | Nonce aliases accept a strict empty body, issue globally scoped `siwe:<nonce>` rows for 900 seconds; verifier callback receives actual message/signature/cacao; nonce expiry/consumption/replay; wallet-linked/new/email-required/anonymous modes; ENS lookup; primary wallet state | `plugins/siwe/{index,schema,types}.ts`; walletAddress model |
| OAuth popup | Omitted `GET /oauth-popup/start`; trusted popup origin/redirects; signed marker and 10 m state; callback completion HTML/postMessage nonce/token/error and CSP; bearer pairing, generic provider pairing | `plugins/oauth-popup/{index,client,constants}.ts`; OAuth state, response hooks and browser evidence |
| Bearer | No endpoint: case-insensitive scheme, encoded signed cookie token, unsigned accepted by default, `requireSignature`, invalid signature handling, cookie precedence, exposed `set-auth-token` on session issuance | `plugins/bearer/index.ts`; session cookie hooks |
| CAPTCHA | No endpoint: Turnstile/reCAPTCHA/hCaptcha/CaptchaFox/Vercel BotID; default/custom/wildcard path matching; missing response/provider failures; remote IP, action/hostname and score validation | `plugins/captcha/{index,constants,verify-handlers/}.ts`; injectable local verification HTTP fixture |
| Compromised passwords | No endpoint: SHA-1 prefix fixture, strict count parsing, provider failure, enabled/path/custom message; applies to email/password, admin, email OTP and phone reset hashing | `plugins/haveibeenpwned/index.ts`; hash hook and local provider fixture |
| Last login method | No endpoint: 30 d non-HttpOnly cookie default, database mode, custom resolver/beforeStoreCookie, all auth methods, failed login and exceptions | `plugins/last-login-method/index.ts`; optional user field and response hooks |
| Custom session | Async shape transform; GET replacement with cookie/headers preservation, null/error behavior; multiple-device-session list transformation | `plugins/custom-session/index.ts`; native callback API and composition |
| OpenAPI/reference | Runtime schema generation and HTML reference, custom path/title/theme, disabled default reference and plugin route/schema discovery; server-only/hidden endpoint exclusions | `plugins/open-api/{index,generator}.ts`; Rust runtime schema registry |
| Admin | Existing route fixes plus custom access control/multiple roles/admin IDs, ban expiry, ban enforcement for every session-creating flow, create/update extra fields; remove-user cascade, impersonation restrictions/cookies and lifetime | `plugins/admin/{admin,routes,types,access/}.ts`; every new authentication flow |
| Two factor | Successful disable; server-only `generateTOTP` and `viewBackupCodes`; passwordless mode, method selection/disabled TOTP, custom periods/digits/backup generation+storage, OTP attempts/expiry, trust cookie rotation and session invalidation; interactions with passwordless signin | `plugins/two-factor/{index,types,totp/,otp/,backup-codes/}.ts`; configurable crypto/storage and hooks |
| Username | Availability success, includeDisplayUsername, min/max/custom validation/normalization/order, immutable username, update/signup hook behavior, signin/verification/remember-me | `plugins/username/index.ts`; user extra fields |
| Generic OAuth | No plugin route: discovery success/failure, issuer/JWKS/nonce and ID-token verification, default PKCE, callback account subject, logout, private_key_jwt/none/basic/post auth, custom tokens/userinfo/profile mapping, extra headers/params and signup controls | `plugins/generic-oauth/{index,types,providers/}.ts`; core OAuth interfaces |
| Passkey package | Existing real ES256 flow plus sessionless registration resolver/context, registration afterVerification reassignment/name rules, extensions, authentication callback, RP/origin array/default selection and custom challenge cookie | `packages/passkey/src/{index,routes,types}.ts`; official passkey client/software authenticator |
| API-key package | Existing CRUD/server verification plus server-only deleteAllExpiredApiKeys; custom getter/validator/key generator/permission callbacks, secondary storage/fallback/custom storage/deferred updates; quota refill/expiry and org reference interaction | `packages/api-key/src/{index,types,routes/}.ts`; controlled server fixture and storage |
| Test/additional fields/access helpers | Development test utilities and type-only inference/role builders are separate embedding boundaries; any runtime effects of test helpers and native access-control APIs need explicit accounting | `plugins/{test-utils,additional-fields,access}/`; idiomatic Rust embedding API |

## OAuth provider completeness

`packages/core/src/social-providers/index.ts` exports 36 built-in providers:
apple, atlassian, cloudflare, cognito, discord, dropbox, facebook, figma, github,
gitlab, google, huggingface, kakao, kick, line, linear, linkedin, microsoft,
naver, notion, paybin, paypal, polar, railway, reddit, roblox, salesforce, slack,
spotify, tiktok, twitch, twitter, vercel, vk, wechat, zoom.

The initial implementation audit found dedicated Google, GitHub and Discord constructors. A generic
custom provider is useful but does not establish defaults/profile mapping/ID
token behavior for the other 33 providers. Each provider's capabilities include
scopes, auth URL parameters, PKCE, token authentication/refresh/default expiry,
profile mapping, verified email semantics, signup controls, ID-token nonce/JWKS
verification when supported, and provider logout. Generic helpers additionally
cover auth0, gumroad, hubspot, keycloak, line, microsoftEntraId, okta, patreon,
slack and yandex. These are unresolved target families until exercised with
local deterministic provider endpoints. No credentials or real accounts are
required.

## Additional 1.7.6 package and integration boundaries

The upstream tag packages below are absent from the current selected profiles.
They were enumerated to account for package boundaries beyond route profiles.
At the user's later scope decision, OAuth authorization server/MCP/CIMD, enterprise
SSO, SCIM, Stripe, i18n, Expo and Electron are explicitly excluded implementation
targets. Their rows below retain the original boundary descriptions for audit
provenance and are not outstanding tasks. Redis storage and observable native
framework/custom-adapter integrations remain separately accounted for.
All listed runtime packages are version 1.7.6 in that tag.

| Boundary | Runtime capability and main source | Required dependency |
| --- | --- | --- |
| `@better-auth/oauth-provider` | OAuth authorization server, discovery, authorization/token/introspection/revocation/end-session/logout/device grants, consent, clients/resources, dynamic registration, server-only APIs and protected-resource helpers; `packages/oauth-provider/src/{index,oauth,oauthClient/,oauthConsent/,oauthResource/,oauthDeviceCode/}` | JWT/JWKS; client/token/consent/resource/device schemas; local provider/consumer fixture |
| `@better-auth/mcp` | Wraps OAuth provider, MCP authorization metadata/request handling and protected-resource authentication; `packages/mcp/src/{plugin,handler,require-mcp-auth}.ts` | OAuth provider and JWT |
| `@better-auth/cimd` | HTTPS client-ID metadata discovery, validation/cache/refresh/client persistence and OAuth discovery metadata; `packages/cimd/src/{index,resolver,validate-metadata-document}.ts` | OAuth provider extensions and local metadata fixture |
| `@better-auth/sso` | SSO provider CRUD/register/signin/OIDC/SAML ACS/SLO/metadata, domain verification, provisioning and organization linking; `packages/sso/src/{index,routes/,user-resolution}.ts` | Provider model, transactions, signed local OIDC/SAML fixtures, organization |
| `@better-auth/scim` | SCIM v2 discovery/user/group create/read/list/replace/patch/delete, token auth, filters/pagination/ETag, org provisioning; `packages/scim/src/{index,discovery,user-provisioning,group-provisioning}.ts` | Organization/teams; SCIM token schemas and official consumer-shaped fixture |
| `@better-auth/stripe` | Checkout upgrade/cancel/restore/list/success/billing portal/webhook, customer/subscription and organization lifecycle, authorization hooks; `packages/stripe/src/{index,routes,schema}.ts` | Subscription/customer schema; local Stripe API and signed webhook fixture |
| `@better-auth/i18n` | Locale selection and translated error messages via after hook; dictionaries/client/header/query/cookie configuration; `packages/i18n/src/{index,types,locales/}.ts` | Error response composition; deterministic locale fixture |
| `@better-auth/expo` | `/expo-authorization-proxy`, native callback/session-cookie behavior, origin handling and anonymous OAuth linking; `packages/expo/src/{index,routes,client}.ts` | OAuth/session hooks; official Expo client integration evidence |
| `@better-auth/electron` | `/electron/token`, `/electron/init-oauth-proxy`, `/electron/transfer-user`, one-time auth/user transfer/proxy/session behavior; `packages/electron/src/{index,routes,authenticate,user}.ts` | One-time tokens, OAuth proxy and native client integration evidence |
| `@better-auth/redis-storage` | Secondary-storage TTL/get/set/delete and atomic rate-limit consumption; `packages/redis-storage/src/index.ts` | Redis feature fixtures; core storage modes |
| Framework bindings | Node, Next.js, SvelteKit, SolidStart, TanStack React/Solid and React/Vue/Svelte/Solid/Lynx clients; `packages/better-auth/src/integrations/`, `src/client/` | Rust APIs remain native; preserve shared observable cookie/redirect/error semantics and use official clients where applicable |
| Database adapters | Kysely/Prisma/Drizzle/Mongo/memory adapter query/schema/transaction/joins and migration semantics; same-name packages under `packages/` | SeaORM/custom-store behavior must preserve observable persistence/ordering/atomicity; TS API shape is not required |
| Tooling packages | `auth` CLI, `@better-auth/test-utils`, telemetry and internal release tooling; same-name packages under `packages/` | Explicit embedding/tooling boundary; telemetry enable/disable and runtime side effects need a decision/evidence, release tooling is not an authentication runtime |

The generator's fallback to `oidcProvider`/`mcp` from `better-auth/plugins`
produces neither on 1.7.6: these factories are absent from that barrel. Its
optional-plugin warning cannot account for the separately published package.

## Investigation depth and outstanding evidence

The audit enumerates runtime surfaces, options, schemas, server-only APIs and
important composition points. It does not yet prove every option branch or
additional-package behavior experimentally. Bundled plugin metadata was
constructed from installed 1.7.6 factories. Additional packages were checked
against the matching tag's package metadata and route/source files, and require
their own pinned fixture installation/runtime scenarios before any completion
claim. Independently reviewed implementation evidence should replace each
unresolved family as it lands; route coverage alone is insufficient.

