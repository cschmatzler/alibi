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

This is a draft pending immutable canonical execution and independent review.
OpenClaw/Crabbox/autoreview/PR helper tools are not installed. The repository
canonical command is `devenv shell -- bash scripts/check.sh`; `devenv test` is a
no-op. No unexecuted gate is claimed. Signed-cookie prerequisite #284/#286 stays
separate and its frozen gate is untouched.
