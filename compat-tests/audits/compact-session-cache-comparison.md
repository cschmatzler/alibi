# Authenticated compact session-cache comparison

This support-only capability recognizes an explicit observation made with the
published Better Auth 1.7.6 cookie writer and `getCookieCache` decoder:

```
compactSessionCache: {
  token, envelope, decoded, observedAt, effectiveMaxAgeSeconds
}
```

`token` is the entire URI-decoded, reconstructed compact value, including every
chunk. `envelope` is the entire ordinary JSON parse of those original bytes.
`decoded` is the complete published decoder result; its dates are normalized by
the existing observation serializer. `observedAt` is captured immediately before
that decoder call. `effectiveMaxAgeSeconds` is the actual producer age, proved by
the owning scenario's configuration and remember-policy observations. It is
compared literally: ordinary default issuance uses 300 seconds, browser-cookie
issuance uses 60, and a persistent configured zero uses the Source's 300 fallback.
Raw configuration and signed preference evidence remain separate observations.

The comparison context explicitly supplies the existing private fixture secret.
There is no environment lookup or implicit comparator secret. Without that
context, or with an unverified atom, the whole value compares literally.
Application data, metadata, additional fields and transport shape declarations
remain literal even if an application object uses this container name.

## Authentication and complete observations

Recognition requires canonical unpadded base64url, fatal UTF-8 decoding, exact
original `JSON.stringify` bytes and an identical complete envelope copy. The
atom and outer envelope have exact field sets. Its HMAC-SHA256 is independently
verified in constant time over the original complete payload and expiry using
the known fixture secret. No claim is removed. Every session/user field, extra
loose-schema field, array element, identifier and token subsequently passes
through the existing comparison graph. Complete compact tokens retain the
ordinary token bijection, including repeated identity and rotation.

The published `cookies/index.mjs::getCookieCache` performs `safeJSONParse` Date
revival before HMAC verification and applies the loose published session/user
schemas. Comparison independently follows that decoder contract using those
pinned public core schemas and parser. A nonnull decoded observation must equal
the complete parsed result, including passthrough fields. Genuine authenticated
null observations are accepted only when that independent decoder contract
rejects the cookie. Actual negative age, negative-infinite age (`expiresAt:null`)
and literal ISO-date version issuances exercise those reasons. Forged signatures
and naked null decoder observations do not gain semantic comparison.

Validity is evaluated at the observation time, not the later scenario finish.
The scenario owns the actual decoder call and its complete result. This bounded
support assumes the decoder call does not cross an expiry boundary after the
recorded timestamp; boundary-crossing scheduling requires its own evidence.
Positive-infinite age is not claimed: an actual published HTTP signup probe
returns 500 because the cookie writer rejects that Max-Age. Its nonpassing
setup log is retained at `/tmp/compact-cookie-cache-harness-final-v2.log`.

## Clock and lifetime checks

Only the authenticated outer numeric expiry and inner numeric `updatedAt`
clock fields, plus the observation timestamp, use the existing 1500ms relative
runtime clock allowance. Every effective age compares exactly, including a
fractional one-millisecond change. Each cookie additionally must satisfy its
own Source writer law:

```
TimeClip(updatedAt + effectiveMaxAgeSeconds * 1000)
  <= expiresAt
  <= TimeClip(observedAt + effectiveMaxAgeSeconds * 1000)
```

Invalid TimeClip bounds require the actual serialized null expiry. The Source
writer takes two separate `Date.now` readings, so an exact common
`expiresAt - updatedAt` would reject legitimate cookies. An isolated actual
public signup handler with a monotonic, one-millisecond clock increment around
the producer emits 300251ms for configured 300.25 seconds; its public decoder
succeeds. This is recorded in
`/tmp/compact-cookie-cache-source-clock-probe.log`. The isolated process restores
its clock after the call; no production clock seam or normal harness clock
change is introduced. The upper bound uses the real decoder observation, not an
invented intercall grace interval.

## Test value and measured proof

The new harness owners exercise the real published signup handler, migrated Bun
SQLite and public decoder. They independently guard (1) differing authentic
issuance and explicit-secret admission; (2) ownership, token identity/rotation,
lifetime, complete byte/copy/decoder/field/array integrity and application-shape
isolation; (3) retained observation validity versus genuine expired decoder
results; and (4) authenticated null decoder reasons. They need no production
export, pause hook or runtime seam. Existing comparator tests do not exercise
this signed compact format.

The original comparator demonstrably rejects two authentic, independently
issued Source cookies on the numeric cache clocks and signature:
`/tmp/compact-cookie-cache-comparator-before.log`. Correctly signed mutations
then test wrong owners, changed literal claims, reordered/shortened/extended
arrays, absurd expiry and repeated-token rotation. Effective age mutations of
both +0.001 and -0.001 seconds fail without widening date tolerances. Tampered
bytes, copied envelopes/decoder results, extra fields, expired observations and
arbitrary application-shaped atoms also fail.

Final focused verification: all 47 harness tests / 491 assertions pass in
`/tmp/compact-cookie-cache-harness-final-v3.log`; TypeScript checking passes in
`/tmp/compact-cookie-cache-typecheck-final-v3.log`. Earlier path/setup failures
and the positive-infinite Source writer rejection remain nonpassing artifacts.
No dependencies, locks, capability requirements, comparator exceptions or
coverage rules change. SDK cookie-cache lifecycle evidence remains the separate
production owner's responsibility; the coordinator owns independent review,
integration and the full canonical gate.
