# Google default ID-token verification (#228)

The public Google factory previously declared no default ID-token verifier.
Ordinary official-client social sign-in therefore returned native 404
ID_TOKEN_NOT_SUPPORTED for a genuinely signed Google token. Existing social
profiles install application verifiers; One Tap has a separate admission path.
Neither proved this factory contract.

The repair declares trusted issuer/audience/RS256/JWKS/max-age policy, reuses the
shared cryptographic verifier, and maps the authenticated signed Google profile.
Hosted-domain checks follow actual verification. Application verifier overrides
and explicit disabling retain precedence. Explicit audience overrides dominate
builder client-ID arrays, whose empty value remains distinct from a scalar ID.
Google social imports matching keys and chooses the first; One Tap retains its
separate retry-all selection and early algorithm rejection. Google nonces require
exact equality, unlike Apple's exact-or-SHA256 policy.

The new primary SDK owners use the actual pinned Google factory, actual RSA
signatures and local HTTP key delivery. Only the Google JWKS transport is redirected;
no application verifier manufactures successful default admission. The official
client posts the token and all original request, response, cookie and trace values
remain compared. Full physical users/accounts/sessions and foreign user state are
retained. Direct refresh/expiry/unknown scopes are accepted request data but not
persisted, matching the published direct sign-in route. Valid bearer replay issues
another session for the signed subject; sign-out retires only that session and
preserves the original and unrelated principal.

Source-self controls: `/tmp/issue-228-source-proof.log`, 14 passing scenarios.
Pre-fix proof: `/tmp/issue-228-baseline.log`, intended default 404 at the real SDK
sign-in boundary. Auxiliary foreign plugin field differences found in that run
were fixed by configuring the same baseline plugins, without observation filters.
Final Google proof: `/tmp/issue-228-final-proof.log`, 14 controls / 376 assertions.
Final post-review full OAuth/One Tap proof: `/tmp/issue-228-final-retained-proof.log`,
61 controls / 4,458 assertions. Native OAuth owners: 12/12. Strict workspace default
and optional/all-target Clippy, fixture Clippy and client TypeScript pass. Independent
production, authorization and primary-owner review found no remaining bounded
findings after the explicit audience precedence repair. The canonical integrated
gate and Apple shared-policy synchronization remain pending; focused proof is not
a complete gate claim.

The owner-boundary regression covers a public default, signature admission,
configuration, identity ownership and session/token lifecycle. No private helper
mirror, mock success receipt, oracle change, comparator exemption or test-only
production API was introduced. Public trusted JWKS injection is usable by actual
applications. Arbitrary provider customization and production Google network
availability are outside these deterministic local signing controls.
