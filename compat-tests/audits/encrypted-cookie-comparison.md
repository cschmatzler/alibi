# Authenticated encrypted account-cookie evidence

The account-cookie interoperability scenario returns the complete compact token,
protected header and decoded payload as `accountCookie: {token, header, payload}`.
The actual official client receives the cookie over HTTP. Its fixture decodes it
with the published Better Auth 1.7.6 `symmetricDecodeJWT`, validates the complete
account result, and preserves every additional decoded field. This is an evidence
container; no public authentication endpoint or comparison exception is added.

The existing comparator incorrectly treated the upstream writer's freshly
randomized UUID `jti` as application text. Two genuine pinned upstream cookies,
created by `symmetricEncodeJWT` and authenticated by `symmetricDecodeJWT`, fail
against each other before the repair: `/tmp/encrypted-cookie-harness-before.log`.
The only differences are the three observed payload JWT IDs. Thus the repair
addresses an actual source-to-source harness defect rather than accepting a
Rust deviation. The production cookie format must separately satisfy the
published decoder and rejection/ownership scenarios.

The comparator recognizes this exact evidence container only outside application
metadata, additional fields and transport shape declarations. Each compact token
must have the source's direct-encryption empty key segment, CBC IV/ciphertext/tag
sizes, and a parsed protected header identical to the supplied header. The two
complete headers compare literally, including the configured-secret thumbprint
and any extension fields. The whole payload follows existing field presence,
array, identity, literal data and date checks. Only its root UUID-v4 `jti` receives
a bijection; nested application IDs remain literal. Runtime-generated issuance
and expiry retain the existing execution-window checks and exact lifetime.

Complete encrypted tokens also retain their existing bijection, so repeated
values, consumption and rotation must agree. A repeated token with different
decoded claims is rejected on either runtime. No fields are removed or projected
away. Arbitrary application objects named `payload` do not gain JWT-ID handling.
The account-cookie fixture owns cryptographic authentication before handing this
container to comparison; structural comparison alone cannot authenticate a JWE.

Independent review reproduced a further failure with genuine source-readable
JOSE cookies containing different protected `id` extensions. The generic visitor
could mistake those header extensions for entity entropy. Direct canonical
header equality fixes it. The probe changes from an empty difference to the
precise protected-header difference in
`/tmp/encrypted-cookie-review-probe.log` and
`/tmp/encrypted-cookie-review-probe-after.log`.

The primary harness owner uses four genuine upstream cookie issuances and
controls incorrect owners/providers, nullable-field presence, ordered array
contents, application JWT-shaped data, expiration duration, fixed clock shifts,
malformed compact tokens, literal protected headers, repeated-token claims and
independent token/JWT-ID rotation. Semantic payload mutations are applied to
both repeated observations, so the controls reach the actual field comparison
rather than passing solely because of inconsistent repeats. Header extensions
are independently encrypted by JOSE and authenticated by the published decoder.

Focused final verification passes all 40 harness tests / 289 assertions and
TypeScript checking: `/tmp/encrypted-cookie-harness-reviewed-final.log`.
Independent JWT-owner review is clear after the header and control repairs.
The canonical gate remains coordinator-owned and is required before landing.
The empty exception list, source coverage floor and TypeScript pin are unchanged.
