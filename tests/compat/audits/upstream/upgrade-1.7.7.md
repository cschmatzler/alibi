# Better Auth 1.7.7 release delta

Reviewed upstream `v1.7.6` (`229a02a652185ed32e87eab0c77c09d58532e0f1`)
through `v1.7.7` (`db02f233918ad1233bf0753e437e1c0da353273d`): 28 commits,
118 changed files. Primary references:
[release](https://github.com/better-auth/better-auth/releases/tag/v1.7.7),
[OAuth/Magic Link security change](https://github.com/better-auth/better-auth/pull/11494).

## Ported contracts

- OAuth database verification identifiers use `auth-state:`. OAuth state cookies,
  proxy state, proxy packages and proxy profiles each derive a separate HKDF-SHA256
  key, retaining configured rotation versions. The derived lowercase hex string
  is passed to the existing SHA256/XChaCha persistence encoding. Other encrypted
  records and native authenticated server-context proofs retain their existing keys.
- Magic Links store `magic-link:<stored token>` with a strict purpose-tagged record.
  Validate the pending record before atomic consumption and validate the consumed
  record again before trusting its identity. Reject wrong purposes, malformed
  email/name fields, extra fields and old bare identifiers without authenticating.
- Explicit provider signup disabling applies to ID-token sign-in, including when
  the ordinary factory grant policy does not honor factory options. A requested
  signup bypasses implicit disabling only.
- CAPTCHA and rate-limit JSON error responses declare `application/json`.
- Published client package pins move to 1.7.7, including the organization client's
  active-organization session-signal fix. A fresh encrypted JWK vector is generated
  by the actual 1.7.7 runtime; the old 1.7.6 artifact is not relabeled.

The upstream Kysely consume and Drizzle increment fixes reapply conditional guards
at the physical write. Native verification consumption already locks/selects the
record and deletes by both its identity and original value, checks affected rows,
and invokes the transaction owners. Native seat/rate mutations retain their guards
at UPDATE. This inspection is not a fresh PostgreSQL contention campaign.

The separately published OAuth authorization-server package changes remain outside
this repository's supported social OAuth-client scope. No authorization-server,
MCP or enterprise SAML implementation is claimed. Remaining upstream commits are
release bookkeeping, documentation or dependency maintenance, rather than native
behavior changes in the supported surface.

## Upgrade behavior

Upgrade servers sharing a verification store and all OAuth proxy participants
 together. Request new Magic Links and restart pending OAuth flows. Old identifiers
and old raw-key OAuth ciphertext are deliberately rejected; there is no fallback
that restores the cross-purpose confusion. Existing account credentials, password
hashes and session records need no migration for these release changes.

## Qualification scope

Focused affected runtime tests use the authentic published 1.7.7 packages, real
SQLite-backed SQLx and SeaORM fixtures, unchanged live comparison and retained raw
physical/provider receipts. Existing primary owners were extended for purpose
rejection and explicit-versus-implicit signup policy. Literal expected identifiers,
record tags and Content-Type values follow the new upstream contracts. No comparator
exclusion or tolerance change is introduced. The final PR records exact commands,
results and pre-port controls. Historical audits remain evidence for their recorded
1.7.6 releases; no new full-suite, universal-parity, hosted-CI or coverage-floor
claim is made.
