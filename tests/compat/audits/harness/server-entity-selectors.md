# Observed server selectors

Reference: Better Auth 1.7.6. Issue #287 is a separate harness prerequisite for
#205, based on actual main `4efe6df41cefc7a73228be38eabf6717cb6a4295`. No root or
scoped `AGENTS.md` exists. Source packages, native production, allowlist,
capability requirements and the 75% coverage floor are unchanged.

The complete organization callback owner supplies genuine returned/persisted
member IDs as `memberIdOrEmail` and an actual issued key ID as `keyId` while
revoking it. Those field aliases are absent from the comparison identity graph,
so unchanged Source-versus-Source observations fail literally. The original
`/tmp/issue205-org-source-counterfactual.log` records the exact callback paths,
158 assertions and otherwise successful runtime authority/quota/state checks.

The new primary owner uses two actual published Source instances and SQLite
migrations. It signs up real owner/target/foreign users, issues application-owned
API keys through the installed plugin, disables an actual issued key, creates an
organization, adds actual members, removes by real member ID and literal email,
and rejects the disabled credential. All raw before/after inputs, logical
headers, optional physical request, real virtual principals, responses and full
member/API-key SQL rows remain. Each stored key's SHA256, prefix bytes, SQLite
type, reference owner and exact quota are independently asserted.

The regression protects actual selector relationships. Credible failures are
literal generated-ID drift, selection of another observed member/key, or an
unchecked ownership/reference relationship. Existing ID-field owners do not
exercise these Source selector aliases. The single actual Source owner extends
the strongest boundary; the production application seam remains the actual
comparator, with no test-only export or fabricated callback/state receipt.

`keyId` reconciliation requires the independently validated SQLite issuance,
stored hash, UTF-16 prefix/type/readback receipts already owned by #271/#272.
`memberIdOrEmail` reconciliation requires complete observed member records with
id, organizationId, userId, role and createdAt. Actual corresponding records
anchor their IDs in the existing bijection before selector comparison. Every
record field and ownership relationship continues through that same graph.
Emails, unknown selectors, cross-domain IDs, application data, JWT claims and
shape markers receive no generated-ID exception. No broad name-based identity
rule was added. This proof is deliberately bounded to the observed SQLite
receipts; an absent receipt cannot grant reconciliation.

Each negative control asserts its exact owning path/reason: another real key,
another real member, unobserved IDs, member/key domain swaps, literal email/type
changes, persisted member user/organization scope, key reference/hash corruption,
missing complete member receipts, four application-data locations and JWT
claims. A mismatch in an unrelated row cannot satisfy a selector control.

Before publication:

- Actual unchanged Source owner fails at four selector aliases, 53 assertions
  (`/tmp/issue287-source-before.log`). Complete captures remain in
  `/tmp/issue287-source-before-captures.json`; the same saved captures compare
  with zero differences after repair (`/tmp/issue287-identical-before-after.log`).
- Final actual owner passes, 78 assertions; full harness 72/72, 832 assertions
  retains the prior 71/754 (`/tmp/issue287-harness.log`). Final full observations
  are `/tmp/issue287-source-after-captures.json`.
- Strict TypeScript checking passes (`/tmp/issue287-typecheck2.log`). The earlier
  typecheck correctly rejected a widened boolean outcome; the actual result
  discriminants were typed without changing runtime observations.

## Frozen full gate and final composition

The original immutable `0a08d25f1618a55fda4307242a9be703e62505aa`
completed the actual canonical command with exit 100,
`/tmp/issue287-canonical-0a08d25f.log`. Default native 794, optional-feature
native 845, SQLite fixture 2, strict/build checks, harness 72/832, Axum 36,
endpoint checks 3 and inventory checks 2 passed. The complete SDK run passed
1,290 of 1,296 tests with 83,984 assertions. Six actual failures remain recorded:

- Organization addition observation 5 had two member createdAt aliases.
- Membership-policy observations 6/7 had six member/session timestamp aliases.
- Keyring pinning had four manualState key createdAt/expiresAt aliases:
  Source 04:22:26.575 versus native 04:22:29.278, a 2.703-second difference.
  The scalar timestamp policy is unchanged by this selector repair.
- Generated lifecycle seed 12648430 had snapshot 22 code/message drift in
  default, session-no-refresh and session-deferred profiles, assigned to the
  separately repaired ordinary cache guard #221.

The stopped canonical did not reach its downstream documentation/browser/
coverage stages. Independent strict rustdoc and the actual Chromium wrapper
passed with exit zero (`/tmp/issue287-docs-browser-0a08d25f.log`). T3 preview
reported no headless automation host and no retry; the actual repository
Playwright wrapper was used. This zero-native-production comparator repair
makes no new clean coverage claim and retains the required floor.

Final composition uses actual main
`dbc67fd8d4e10b1857daa54c49ed520a0caee101`, preserving #221, #135, signed-cookie
#284/#286 and the provider additions. The complete capability ledger is
byte-identical to that parent. The only rebase conflict was adjacent string
comparison guards; the existing signed-header guard and selector guard are
both retained. The exact selector delta remains 39 added lines.

Composed strict TypeScript and the complete retained harness passed:
73 tests, 903 assertions, including both signed-header and selector owners
(`/tmp/issue287-composed286-typecheck.log`,
`/tmp/issue287-composed286-harness.log`). The unchanged full #205 organization
and factor owners passed against their actual Source/native fixture programs,
2 tests, 238 assertions (`/tmp/issue287-composed286-real205-consumers.log`).
Their test source was temporarily copied into the composed checkout to use its
actual comparer and removed afterward; no #205 test/fixture or native
production enters this PR. Those focused observations were collected before
the final provider-only rebase; the full SDK/canonical was not rerun after
composition and its historical result is not claimed green.

OpenClaw/Crabbox/autoreview/PR helper tools are not installed. The repository
canonical command is `devenv shell -- bash scripts/check.sh`; `devenv test` is a
no-op. No unexecuted gate is claimed.
