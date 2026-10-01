# Remaining Better Auth behavior

Status: implementation is wrapping up at the user's request. Finish the existing
reviewed stack; further capability work is tracked for triage. The reference
remains Better Auth **1.7.6** and scrypt is the sole built-in password algorithm.

The [GitHub triage index](https://github.com/cschmatzler/better-auth-rs/issues/234)
links **96 actionable issues**. Each distinguishes a confirmed runtime/code
difference, a missing configuration or capability, or an integration branch whose
equivalence has not been proved. The [upstream audit](audits/upstream-target.md)
accounts for routes, server-only APIs, middleware/hooks, configuration, cookies,
storage, provider factories and package boundaries. Route existence and passing
current tests do not establish complete behavioral parity.

## Suggested triage

| Family | Remaining work |
| --- | --- |
| Concrete correctness differences | [Admin callback error wire](https://github.com/cschmatzler/better-auth-rs/issues/197), [pending two-factor expiry stages](https://github.com/cschmatzler/better-auth-rs/issues/200), [COSE key/algorithm mismatch](https://github.com/cschmatzler/better-auth-rs/issues/214), [default organization no-row/empty update](https://github.com/cschmatzler/better-auth-rs/issues/216), [passkey callback deletion](https://github.com/cschmatzler/better-auth-rs/issues/231). Some require runtime reproduction of a code-level difference before choosing a repair. |
| Session and storage modes | [JWT/JWE cache](https://github.com/cschmatzler/better-auth-rs/issues/171), [stateless sessions](https://github.com/cschmatzler/better-auth-rs/issues/172), [secondary sessions](https://github.com/cschmatzler/better-auth-rs/issues/173), [verification storage](https://github.com/cschmatzler/better-auth-rs/issues/174), [rate limiting](https://github.com/cschmatzler/better-auth-rs/issues/175), [secret rotation](https://github.com/cschmatzler/better-auth-rs/issues/176), [cache guard/plugin composition](https://github.com/cschmatzler/better-auth-rs/issues/221). |
| Organization configuration | [Invitation creation/reissue/delivery/hooks](https://github.com/cschmatzler/better-auth-rs/issues/217), [raw numeric team/role limits](https://github.com/cschmatzler/better-auth-rs/issues/218), [team configuration differential evidence](https://github.com/cschmatzler/better-auth-rs/issues/219), [legacy role permissions/operators](https://github.com/cschmatzler/better-auth-rs/issues/220). |
| Existing authentication branches | [API-key secondary/custom storage](https://github.com/cschmatzler/better-auth-rs/issues/203), [username configuration](https://github.com/cschmatzler/better-auth-rs/issues/206), [passwordless callback context](https://github.com/cschmatzler/better-auth-rs/issues/207), [advanced JWT/JWKS](https://github.com/cschmatzler/better-auth-rs/issues/209), [OTT combinations](https://github.com/cschmatzler/better-auth-rs/issues/210), [anonymous combinations](https://github.com/cschmatzler/better-auth-rs/issues/212), [multiple-session configurations](https://github.com/cschmatzler/better-auth-rs/issues/232). Existing list/switch/revoke and username/two-factor-disable success flows are implemented. |
| Missing plugins | [OAuth popup](https://github.com/cschmatzler/better-auth-rs/issues/132), [bearer](https://github.com/cschmatzler/better-auth-rs/issues/133), [CAPTCHA](https://github.com/cschmatzler/better-auth-rs/issues/134), [compromised-password check](https://github.com/cschmatzler/better-auth-rs/issues/135), [last-login method](https://github.com/cschmatzler/better-auth-rs/issues/136), [custom session transforms](https://github.com/cschmatzler/better-auth-rs/issues/137). |
| OAuth providers and protocols | Four dedicated built-ins are implemented: Google, GitHub, Discord and GitLab. The index links one issue for each of the other 32 factories, plus [advanced OAuth/OIDC](https://github.com/cschmatzler/better-auth-rs/issues/188), [state codecs](https://github.com/cschmatzler/better-auth-rs/issues/189), [installed encrypted-account conversion](https://github.com/cschmatzler/better-auth-rs/issues/190), [proxy variants](https://github.com/cschmatzler/better-auth-rs/issues/227), [default Google ID-token verification](https://github.com/cschmatzler/better-auth-rs/issues/228). Generic provider configuration already exists. |
| Wider integration depth | [Production cookies](https://github.com/cschmatzler/better-auth-rs/issues/177), [dynamic URL policies](https://github.com/cschmatzler/better-auth-rs/issues/178), [trusted proxies](https://github.com/cschmatzler/better-auth-rs/issues/179), [dispatch/security settings](https://github.com/cschmatzler/better-auth-rs/issues/180), [lifecycle composition](https://github.com/cschmatzler/better-auth-rs/issues/181), [schema/fields](https://github.com/cschmatzler/better-auth-rs/issues/184), [trusted server dispatch](https://github.com/cschmatzler/better-auth-rs/issues/205), [database runtime](https://github.com/cschmatzler/better-auth-rs/issues/192), [migration ledger durability](https://github.com/cschmatzler/better-auth-rs/issues/224), [native framework](https://github.com/cschmatzler/better-auth-rs/issues/193) and [runtime tooling](https://github.com/cschmatzler/better-auth-rs/issues/194). |

SIWE is implemented and retained. Its narrower [malformed-media wire follow-up](https://github.com/cschmatzler/better-auth-rs/issues/225)
and shared schema/storage/date boundaries remain recorded. Standard real-signature,
nonce, wallet ownership and replay flows are not missing capabilities.

## Excluded scope

OAuth authorization server, MCP, CIMD, enterprise SSO, SCIM, Stripe, i18n, Expo
and Electron remain excluded at the user's request. They have no implementation
backlog tasks. Rust APIs remain idiomatic; TypeScript API shapes and release
utilities need not be copied to account for observable integration behavior.

## Integration evidence

The [implementation ledger](IMPLEMENTATION-LEDGER.md) records the exact integrated
and merged trees and their measured gates. Historical audit counts describe their
named trees. Prepared or focused-tested work is not described as delivered.
Every remaining issue keeps the pinned oracle, full observations and persisted
state, applicable authorization/expiry/replay/concurrency evidence, independent
review and the canonical gate with its unchanged 75% source line floor.
