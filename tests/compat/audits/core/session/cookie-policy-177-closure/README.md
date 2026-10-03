# Cookie policy closure workpiece — #177

Production checkpoint, proof and reconciliation still in progress. Published
Better Auth 1.7.6 is the oracle; the reference install was copied onto private
inodes before execution. Registry SHA512 integrity and every better-auth/core
published byte were verified. No package mutation was required.

Actual Source/Chromium TLS baseline passes static and trusted-proxy inference;
Native baseline fails both on host-only cookies. The TLS fixture changes no
ambient hosts, trust store or services. See complete raw source/native headers,
physical rows and independent browser/jar observations in the baseline log.
Domain source observations confirm omitted/empty domain => configured URL
hostname (no port; localhost and bracketed IPv6 preserved), explicit domain wins.

Actual Source signup cache TTL observations: configured session_data +17 =>
header17/payload17000ms; zero => header0/payload60000ms; negative => omitted
Max-Age/payload-1000ms. Token remains604800 despite defaultMaxAge99. Baseline
Native fails these assertions (300-second payload); the negative proof also
shows the actual published reader rejects the expired Source envelope.

Serializer Source emission accepts Expires/Partitioned in published order,
forces Host scope and accepts exactly400days. Above400day Max-Age/Expires
returns empty500 with no Set-Cookie. Signup transaction rolls back (lookup by
unique email finds no user), whereas signin commit policy is checked separately.
The original typed Native config could not express Expires/Partitioned and its
infallible integer renderers could not return the published emission error.

Changes: inferred domain API, floating point cookie attributes, Expires and
Partitioned serializer/limits, fallible emission propagated through producers,
family-specific factory/issuance age precedence, signup actual serialization
inside its existing transaction, and session_data age override. SIWE retains
its existing storage-error translation. No credential decoder, factor-local
reader, signer/account policy, OAuth linking/state or proxy behavior edits.

Remaining proof/review/reconciliation and exact tested hashes will be appended
before requesting merge. No closure, CI, full-suite or coverage claim yet.
