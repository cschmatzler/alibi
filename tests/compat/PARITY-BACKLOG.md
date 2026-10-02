# Remaining Better Auth behavior

Status: implementation is wrapping up at the user's request. Finish the existing
reviewed stack; further capability work is tracked for triage. The reference
remains Better Auth **1.7.6** and scrypt is the sole built-in password algorithm.

The [GitHub triage index](https://github.com/cschmatzler/better-auth-rs/issues/234)
tracks the open issues. Each distinguishes a confirmed runtime/code
difference, a missing configuration or capability, or an integration branch whose
equivalence has not been proved. The [upstream audit](audits/upstream-target.md)
accounts for routes, server-only APIs, middleware/hooks, configuration, cookies,
storage, provider factories and package boundaries. Route existence and passing
current tests do not establish complete behavioral parity. Route-level evidence
gaps are listed as `knownGap` entries in [capabilities.json](capabilities.json)
and printed by the gate.

## Suggested triage

| Family | Remaining work |
| --- | --- |
| Session and storage modes | [JWT/JWE cache](https://github.com/cschmatzler/better-auth-rs/issues/171), [stateless sessions](https://github.com/cschmatzler/better-auth-rs/issues/172), [secret rotation](https://github.com/cschmatzler/better-auth-rs/issues/176). |
| Organization configuration | [Invitation creation/reissue/delivery/hooks](https://github.com/cschmatzler/better-auth-rs/issues/217), [raw numeric team/role limits](https://github.com/cschmatzler/better-auth-rs/issues/218), [team configuration differential evidence](https://github.com/cschmatzler/better-auth-rs/issues/219), [legacy role permissions/operators](https://github.com/cschmatzler/better-auth-rs/issues/220). |
| Existing authentication branches | [API-key secondary/custom storage](https://github.com/cschmatzler/better-auth-rs/issues/203), [OTT combinations](https://github.com/cschmatzler/better-auth-rs/issues/210), [anonymous combinations](https://github.com/cschmatzler/better-auth-rs/issues/212), [multiple-session configurations](https://github.com/cschmatzler/better-auth-rs/issues/232). Existing list/switch/revoke and username/two-factor-disable success flows are implemented. |
| Missing plugins | [OAuth popup](https://github.com/cschmatzler/better-auth-rs/issues/132). |
| OAuth providers and protocols | Providers with dedicated SDK scenarios are in `client-tests/tests/core/social`; the index links an issue for each remaining factory, plus [advanced OAuth/OIDC](https://github.com/cschmatzler/better-auth-rs/issues/188), [state codecs](https://github.com/cschmatzler/better-auth-rs/issues/189), [installed encrypted-account conversion](https://github.com/cschmatzler/better-auth-rs/issues/190), [proxy variants](https://github.com/cschmatzler/better-auth-rs/issues/227). Generic provider configuration already exists. |
| Wider integration depth | [Production cookies](https://github.com/cschmatzler/better-auth-rs/issues/177), [dynamic URL policies](https://github.com/cschmatzler/better-auth-rs/issues/178), [lifecycle composition](https://github.com/cschmatzler/better-auth-rs/issues/181), [database runtime](https://github.com/cschmatzler/better-auth-rs/issues/192). |

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
