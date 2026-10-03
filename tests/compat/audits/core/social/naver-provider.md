# Naver provider (issue #153)

Authority is the installed unchanged Better Auth 1.7.6 Naver factory/types and
actual grant helpers. Authorization uses nid.naver.com/oauth2.0/authorize with
ordered profile,email defaults and configured/requested duplicate scopes.
The factory supplies neither codeVerifier nor loginHint: no PKCE or login_hint.
Trusted authorization/redirect overrides remain. nid.naver.com/oauth2.0/token
uses public or secret-post credentials, code-only client_key, no default token
lifetime invented, and real refresh behavior which ignores clientKey.

Bearer GET openapi.naver.com/v1/nid/me must have exact string resultcode00 before
mapping. HTTP errors, null data or another resultcode deny before the mapper.
The application mapper receives the whole original envelope before admission.
profile.response.id binds account identity independently of mapped ID;
name uses response.name or nickname or empty, image uses profile_image, email
uses response.email and verified-email defaults false. message does not replace
the resultcode condition. Missing/null response still reaches mapper with the
valid resultcode envelope, then fails raw identity. Existing account-info reads
without new identity admission. No built-in ID-token verifier/JWKS or remote
logout exists; generic trusted async hooks remain configurable on the provider.

Authoring gate: one actual Source factory/SDK owner table independently protects
ordered Naver defaults, absent PKCE/loginHint, exact envelope/resultcode gate,
truthy name fallback and whole-envelope mapper/raw subject ordering. Existing
flat/envelope-first/GraphQL providers cannot detect this Naver contract. Retain
actual authorization/token/userinfo requests, all complete mapper/physical/foreign
rows, signed-session/state/replay, refresh/link/getter and local logout. No
private helper test or test-only production export. Arbitrary malformed complex
projection and broader lifecycle/framework modes remain181/184/188/193; retain
any actual owner failure rather than erasing unsupported fields.

Implementation, before proof, independent review and final gates pending.

Before adding the remaining envelope branches, actual40-owner collection passes
40/40,1,562assertions. API and fixture all-target strict Clippy, formats and
TypeScript pass with unchanged frozen dependencies. Extend this same real SDK
owner table for Source's exact resultcode pre-mapper rejection and valid-result
missing/nonobject response mapper-before-raw-subject denial. Also cover numeric
and falsy name/nickname precedence and message-independent admission; these
boundaries differ from generic nested provider mapping. Retain actual original
mapper values/full remote requests/physical foreign state and exact redirects.

The first expanded57 invocation stopped at TypeScript before runtime: inferred
spread-record fields and an unknown physical userId used as a string expectation.
Keep the original full record type and bind the returned SDK principal to the
actual physical user row; all state/relationship assertions remain. Production
and Source factory were unchanged. Retain this failed pre-execution outcome.

Expanded actual collection passes57/57,2,040assertions after the recorded
pre-runtime TypeScript correction; /tmp/issue153-expanded57-real-owner2.log.
Independent read-only review found no admission, callback or protocol blocker
within the declared profile types. Exact resultcode precedes mapping; the whole
original envelope and post-mapper raw response.id remain authoritative.

Actual953c80bf production with genuine fixture registration and old generic
constructor fails default scopes after Source passes: missing profile/email
before requested scopes, exit1/28assertions, /tmp/issue153-generic-before-owner.log.
Production and both Cargo.lock files remain unchanged. Preserve all6,144
parent cells and add342 freshly measured cells from57passing owners,
6,486 total. No failed or baseline artifact imports.

User steering: OAuth providers last. Preserve this implementation and all actual
proof on the draft PR. Broad frozen canonical/native coverage/docs/browser and
actual-main composition are NOT yet run; no final landing claim. Work resumes
only after nonprovider issues. No Source/comparer changes or hook bypass.

Resumed October 3: own Naver changes isolated from the old provider stack and
migrated to current core/social and fixture layout. All 342 existing Naver
requirements and every main requirement retained. The existing 14 mapping
owners now observe real owned and foreign SDK account-info, complete original
JSON envelope and account shape, unchanged physical rows and actual GET receipts.
Actual unchanged Source-self passes all 57 owners with 2,326 assertions. Raw
numeric/null/absent public fields are published independently from typed SQL
values using the existing user_output contract; mapper output and additional
fields preserve mapped public ID independently from original account authority.
The native-before unique build was interrupted at the user's explicit deadline;
verification was explicitly waived by the user. No full gate or native-after
pass is claimed. Frozen dependencies, comparators and gate scripts unchanged.
