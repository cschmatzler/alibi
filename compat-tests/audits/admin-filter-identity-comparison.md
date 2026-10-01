# Observed identities in actual admin filter URLs

The official 1.7.6 admin client appends each array filter operand as a repeated
filterValue query parameter. With filterField=id, those complete values are the
actual persisted user IDs. The previous URL comparator kept filterValue literal
regardless of its declared field. An unchanged Source-to-Source array-filter
scenario therefore fails only at its two actual ID query operands:
`/tmp/admin-array-source-control.log`. That is a comparator defect, rather than
permission to normalize arbitrary application filters.

The distinct harness owner creates actual migrated pinned-runtime SQLite users,
then sends the official client's repeated ID filter through the unchanged auth
handler. Both guest requests retain the actual 401 and complete SDK observations.
Before repair, it fails only on the three generated ID query values in
`/tmp/admin-filter-identity-harness-before-configured.log`. The earlier unenabled
email/password configuration is an excluded setup failure.

Only a parsed URL to the explicitly configured fixture origin and known default
or private fixture admin/list-users path opts into this rule. Both filterField
selectors must be exactly one id, and every full filter operand must independently
occur as an observed entity on its respective side. Those operands then use the
existing global identity bijection. Their array arity, order, duplication and
relationships remain compared, as do the complete selector, operator, origin,
path, hash and all other query fields. No trace or returned field is removed.
Partial IDs, unobserved literal values, other fields/routes, external URLs,
application objects and metadata remain literal. No raw exception is added.

The live negative controls swap owners, remove an operand, introduce a foreign
value, change duplicate identity, change/drop the field or operator, set an empty
operand and change the fragment. Other-field, other-route, external-origin and
metadata controls prove full observed ID strings remain literal there. The
focused owner and whole harness pass: 42 tests / 338 assertions in
`/tmp/admin-filter-identity-harness-selector-removal.log`; TypeScript passes separately.
Canonical integration and independent review remain coordinator-owned. The
separate adapter implementation supplies the successful array-filter behavior;
this comparator repair cannot make an incorrect array query pass its assertions.
