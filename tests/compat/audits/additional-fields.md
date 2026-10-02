# Additional fields and adapter output (issue #184)

This issue starts on merged main
`c7fc2aa9029f4bef50baa718517676c02a79bbbe`. The exact installed Better Auth1.7.6
`db/schema.mjs`, `@better-auth/core/dist/db/get-tables.mjs`, adapter
`factory.mjs`/`utils.mjs`, field declarations and their endpoint callers are the
oracle. Existing configured session/update and custom organization owners remain
valuable; they do not establish user/account fields or adapter output transforms.

## Read-only contracts

Endpoint input policies merge application configuration before plugins. Adapter
schemas merge plugins before application configuration. Public output starts with
the adapter schema and again applies application fields then plugin overrides.
Unknown input is ignored. Creation applies defaults or reports MISSING_FIELD;
updates do neither. A truthy non-input value reports FIELD_NOT_ALLOWED, with
creation's configured default taking precedence. Input validators precede input
transforms. A Promise-returning endpoint validator is explicitly rejected as
ASYNC_VALIDATION_NOT_SUPPORTED; implementing asynchronous validation admission
would diverge from this published version.

Actual adapter input and output transforms are awaited. Adapter creation defaults
also replace null for required fields; omitted update values invoke onUpdate and
then the input transform. Input parsing and adapter binding are distinct stages,
and binding must use the real value after database before hooks. Adapter output
transforms run on actual storage reads and on the result of writes, before trusted
database after callbacks and public returned:false filtering. Declared hidden
fields therefore remain available to trusted callbacks without exposing
undeclared private physical columns on the auth wire. Public account output
removes credentials even if schema overrides try to return them.

Native FieldConfig currently covers synchronous session input and adapter input
binding, with separate immutable precedence registries. Session entities expose
trusted additional storage values and typed binding. User/account entities lack
the corresponding arbitrary field accessors/bindings and configuration, while
UserView currently represents only core and enabled-plugin output. Adapter output,
onUpdate and explicit unsupported async-validation outcomes are not present.
The retained LINE account-info mapper-added ID owner also demonstrates loss of
the original application-mapped user output shape in shared OAuth projection.

## Primary owner and authoring gate

The primary owner will exercise the official SDK against unchanged Source and
native HTTP servers with concrete application-owned user/session/account columns,
including renamed physical columns and plugin policies. Complete durable owner,
same-owner sibling and foreign rows, literal public responses, trusted callback
receipts and errors remain compared. Credible regressions include omitted custom
creation defaults, ignored required/rejected values, wrong two-stage transform
ordering, onUpdate omissions, leaking hidden/private fields and returning a
filtered callback user. Existing session owners cannot reach user/account storage
or the adapter's output stage; extensions to their existing strongest boundaries
will protect shared lifecycle behavior. Public typed configuration and model
bindings serve actual applications; no test-only production exports, fake
principal, Source patch or comparator change is needed.

## Initial actual before proof

The first owner uses separate real application SQLite databases for both servers,
with concrete user/session/account entities, renamed user display_name/user_label
columns and an undeclared physical sentinel. Source uses the unchanged factory,
its actual migrations and application configuration; native uses ordinary
AuthEntity bindings and its already-supported session field configuration.
There is no user/account default supplied by fixture hooks.

`/tmp/issue184-before-build-ready.log` is terminal0 for real fixture build and
TypeScript. Earlier compile-only fixture import and reset-return-shape errors are
preserved in `/tmp/issue184-before-build.log` and
`/tmp/issue184-before-build-repaired.log`; neither supplied parity evidence.

`/tmp/issue184-before-owner.log` is terminal1,0/1,20 assertions. Source completes
the actual signup/getSession defaults, hidden/private public filtering and
complete declared owner/foreign storage observations. Native then fails at
public signup `user.label`: expected user-initial, but the field is absent.
Production remains the unchanged c7fc2aa parent during this regression proof.
The owner's complete responses and actual physical user/account/session rows
remain the intended after boundary. Implemented native session fields retain
their real existing pipeline and are not synthetic receipts.

Native implementation, wider owners, capability cells and final gates remain
pending. No unrun outcome is claimed as passing.

The same application owner now extends into real async output callbacks and the
record-aware after observer. It protects changed output type, hidden trusted
fields, declared own undefined, actual committed user/account/session presence,
onUpdate followed by adapter input transformation, and output-error signup
rollback with unchanged complete foreign rows. Dropping transforms, filtering
trusted after-hook input, running hooks before commit, or swallowing callback
errors are credible independent regressions. The earlier defaults owner does not
reach those lifecycle branches. This uses ordinary configured fields, real
application schema and public observer API; no private production test seam.
The signed credential observations still verify the actual hash, salt and derived
key with the published verifier, including wrong-password rejection.

The input-policy table owns real required/read-only/validator rejection,
unknown/immutable input, validator precedence before awaited actual adapter input,
callback-error rollback and complete foreign-row preservation. An independent
async-validation branch protects the published explicit 500 rejection and proves
that the declared callback is invoked while optional absent input remains usable.
These extend the same physical application fixture; they do not fabricate writes
or duplicate output-stage assertions. Source output validators are declaration
metadata rather than validation admission at this published stage.

## Partial implementation checkpoint

The initialized store now exposes additive `AdapterRecord<M>` results containing
the actual immutable storage model and one retained adapter output. Canonical
identity, ownership and credential accessors continue to use the model. Declared
output callbacks run before the public record after observer, with transaction
after callbacks deferred until commit and discarded on rollback. Legacy typed
store methods and physical SeaORM hooks remain separate, honest physical APIs.

`/tmp/issue184-policy-owner-ready.log` is terminal0 with the four real SDK owners
passing460 assertions, optional strict lint, fixture build and formatting. The
earlier output-only pass238 assertions and default-only pass52 assertions are
separate older checkpoints. Initial input-policy fixture omissions and SDK type
errors remain in the failed logs; no earlier failure is overwritten. The salted
credential observations verify the actual hash using the installed password
verifier and retain salt/key/token relationships instead of omitting passwords.

The first broad native run stopped with two stack overflows in long existing HTTP
scenarios: `/tmp/issue184-partial-native-strict.log`, terminal100,124/126 tests
passed with667 not run. Both unchanged binaries passed with a larger diagnostic
thread stack. Boxing the actual inner HTTP dispatcher then passed the same two
owners with the normal stack (`/tmp/issue184-normal-stack-ready.log`, terminal0).
The subsequent default workspace run passed793/793 before its optional run
stopped on one older Created-cache callback expectation
(`/tmp/issue184-foundation-native-ready.log`, terminal100, optional291/292 with553
not run). None of these stopped runs is a full-gate pass.

The real Source probe `/tmp/issue184-source-cache-stage-ready-probe.log` shows
Created cache-version and completed newSession receive raw declared hidden
output, including own undefined. Cached inputs contain the filtered wire; the
physical findSession path is already parsed before version resolution, so Stored
inputs are filtered while retaining undefined presence. Source internal-adapter
findSession and cookie helpers independently confirm those distinct stages. The
existing native creation expectation is corrected only for hidden callback
input; its signed-cache, public hidden/private-column, revoked physical-session
and genuine typed-model controls remain. The Source-only probe's updateUser401
reflects its incomplete cookie jar and supplies no native parity claim.

`/tmp/issue184-foundation-optional-native-ready.log` is terminal0 with845/845
optional native tests and strict optional workspace lint. Full canonical,
browser/docs, unchanged75% coverage, cached/completed SDK owners, plugin policies,
refresh/replacement/account projections and schema publication remain pending.
This checkpoint does not complete or close issue184.


The cached/completed owner protects actual raw creation/newSession values versus
filtered signed-cache and physical findSession callback stages, own undefined,
changed types, no adapter callback rerun on a cache hit, actual HMAC/owner-token
relationships and unchanged complete foreign rows. Existing codec/native model
owners cannot observe arbitrary application output or completed callback inputs.
It extends the same real application fixture and official SDK. New immutable
snapshot accessors are justified only by actual trusted application callbacks;
no fabricated model or receipt is admissible.


The plugin table owns distinct application/plugin adapter versus endpoint/public
precedence, actual canonical plugin columns, hidden transformed output retained
by after callbacks, read-only role input and complete foreign rows. A plugin
field whose physical getter is known to the framework must not be lost by an
additional-fields-only projector. Existing custom-column owners cannot detect
that known-column loss or the two distinct precedence registries. All fields use
ordinary public application/plugin schema registration and actual model columns.

The cached snapshot regression was reproduced on the rebased foundation with
Source completing the real SDK lifecycle and Native failing the completed
callback's own-undefined observation: `/tmp/issue184-cache-before-ready-owner.log`
(terminal 1, 98 assertions). The additive immutable snapshot accessors retain the
actual adapter output for trusted version/completed observers; Created retains
raw hidden fields, Stored retains its public filtering and own-undefined
presence, and Cached retains the actual decoded wire snapshot. The existing
published tuple accessor remains available. Optional strict checks, fixture and
client type checking, and all five owners then completed with terminal 0 and
624 assertions in `/tmp/issue184-cache-output-complete-ready-owner.log`.

The plugin-column owner first failed after Source completed its full lifecycle:
Native's user.role response did not equal the actual transformed physical
plugin-role. `/tmp/issue184-plugin-before-owner.log` and the unchanged phase
control `/tmp/issue184-plugin-before-phase-owner.log` both exited 1 with 41
assertions; `/tmp/issue184-plugin-before-events.jsonl` records the failure phase
as Rust. The initialized record projector previously read only custom-column
accessors, which deliberately exclude canonical plugin getters. The shared
record output helper now resolves declared fields from physical canonical
getters plus custom columns before awaiting their configured transforms. Its
base projection still controls undeclared fields, and physical getters retain
identity/ownership authority. The complete six-owner set passed 700 assertions,
with optional strict, fixture build and client type checking all terminal 0 in
`/tmp/issue184-plugin-output-ready-owner.log`. These are partial acceptance
results on the CAPTCHA-composed parent; replacement, refresh, account output,
schema metadata and complete canonical/coverage gates remain required before
this draft can close the issue.


The existing cached lifecycle owner also owns password replacement and subsequent
sign-in publication. It measures the authenticated filtered user with a newly
created raw session, preserved own-undefined callbacks, actual new/old credential
hash verification, revoked old physical authority and complete foreign rows.
A repair that rereads raw user storage during replacement would expose hidden
values to the version/completed callback; the original signup/cache owner cannot
reach that stage. The extension uses the public SDK, existing callback profile,
actual signed cookies and physical SQL only. It adds no production seam and
retains credential bytes plus independently verified relationships.

Password replacement first reproduced an untransformed public user.label after
Source completed the full lifecycle (`/tmp/issue184-replacement-before-ready-owner.log`,
terminal 1, 199 assertions; its run journal explicitly records Rust failure).
The first repaired run retained the actual complete callback-ledger differences
and default test-budget exhaustion; `/tmp/issue184-replacement-after-ready-owner.log`
is not a passing result. The extended owner has a 30-second execution budget
because it performs both complete SDK lifecycles and independently verifies
multiple real salted hashes; cookie TTL, timestamps and comparator allowances
remain unchanged. The subsequent record-aware run retained precise callback
ledger failures in `/tmp/issue184-replacement-record-ready-owner.log` (terminal 1,
840 assertions).

The final bounded repair adds an authoritative record reader using the existing
physical cached-session lifecycle with compact cache bypass, cleared virtual
principal and cleared request-local memo. The old typed reader remains intact.
Credential selection now retains only the real selected row's adapter output,
while sign-in retains the user/account lookup already used for authentication.
Replacement publishes the filtered middleware-selected user and the new raw
session, preserving own undefined without a post-write user reread. Password
hashing still precedes current-password verification, and credentials remain
physical authority. Source deleteManyWithHooks also invokes output policies on
its actual pre-deletion session lookup and ignores lookup/output errors in that
observation phase; initialized session revocation now retains that phase before
the actual deletion. This does not introduce record-aware deletion hooks or
claim new inactive-row storage semantics.

Optional strict checks, actual fixture build, client type checking and the full
six-owner set completed with terminal 0 and 840 assertions in
`/tmp/issue184-replacement-deletion-owner.log`. The owner verifies replacement
credentials against new and old passwords, old physical-cookie revocation,
Source callback stages, subsequent sign-in and complete unchanged foreign rows.
These proofs still precede the SIWE/SQLite-recovery composition and do not claim
whole-issue completion or a full canonical/coverage result.


The cached owner also owns actual refresh: a trusted fixture operator changes
only the issued session's real SQLite expiry, then the public SDK must refresh
that still-valid physical session. It protects onUpdate, transformed after-hook
outputs, filtered-existing-user/raw-updated-session version/newSession stages
and full foreign rows. No clock, authentication receipt or production flag is
fabricated; the original actual token and request-owned expiry input are retained.
Existing codec and plain session refresh owners cannot observe these arbitrary
application field policies or trusted output callbacks.

The SIWE/SQLite-recovery composition at 8d50f16c completed default 794/794 and
optional 846/846 native tests, optional strict checks, actual fixture build and
client type checking, followed by all six real SDK owners with 840 assertions:
`/tmp/issue184-replacement-composed-native-owner.log`, terminal 0. The later
cookie/legacy-name parent was composed cleanly at 560e5617; this earlier native
matrix is not attributed to that later parent.

The refresh before owner completed Source's lifecycle and failed only on Native
retaining session-initial instead of the actual onUpdate session-updated output:
`/tmp/issue184-refresh-before-ready-owner.log`, terminal 1, 268 assertions, Rust
phase recorded in `/tmp/issue184-refresh-before-ready-events.jsonl`. The earlier
fixture compile diagnostic (`/tmp/issue184-refresh-before-owner.log`) is not a
parity result. A separate installed-factory Source audit retained real refresh
before/after/version/newSession receipts in
`/tmp/issue184-source-refresh-stage-ready-probe.log`; its original incomplete
cookie-jar diagnostic is retained and supplies no parity evidence.

The single-write refresh operation shares the actual SeaORM field-update
lifecycle: physical before hooks, pending configured field input/onUpdate
binding, one active-row write and physical after hooks. Initialized record
projection and adapter after observation then use that final row. Custom store
fallbacks retain plain refresh and fail closed when additional writes require
unsupported binding. The refreshed cache/newSession publication retains the
filtered existing user and raw updated session without rerunning output
callbacks. All six real SDK owners passed 928 assertions together with optional
strict, actual fixture build and client type checking in
`/tmp/issue184-refresh-after-owner.log`, terminal 0, on the cookie-composed
checkpoint plus this repair. Account output, schema documentation and complete
canonical/coverage proofs remain outstanding.


The existing transformed-output owner also owns list-accounts projection: the
real SDK must retain declared changed-type account output while removing all
six credential fields even when the application explicitly marks password and
accessToken returned. The complete physical owner/foreign rows and trusted
adapter callbacks remain observed. Existing account DTO owners cannot detect
arbitrary additional output or configured credential re-exposure; no new
production seam or authentication fixture is needed.

The account before owner completed Source and failed on Native's missing changed-type
list-accounts label (`/tmp/issue184-account-before-owner.log`, terminal 1,
161 assertions). The record-aware list keeps the physical session/user ownership
boundary, projects only declared account output, and unconditionally removes all
six credentials even when configured returned. The redundant new map accessor
was removed; all projections consume the single immutable adapter snapshot.
Optional strict checks, fixture build, client types and all six SDK owners passed
984 assertions (`/tmp/issue184-account-after-owner.log`, terminal 0). Schema and
mapped-profile projection proofs remain outstanding.

The schema owner reads complete real application OpenAPI documents for all six
policies, including plugin/config precedence and required callable defaults. It
also observes full SQLite/callback state before and after generation, so invoking
a default or transform while documenting fields is a credible detectable bug.
It independently protects logical names versus renamed/private physical columns;
existing session-only metadata owners do not cover user/account/plugin fields.
The normal creation owner now observes actual callable defaults, and transformed
profiles declare throwing output validators to prove they remain metadata. No
production-only test seam or copied generated document is introduced.

The complete-document schema owner completed Source then failed on Native's
missing logical User label metadata (`/tmp/issue184-schema-before-ready-owner.log`,
terminal 1, 183 assertions). The initial Source-side expectation of no completed
request hook was corrected to retain its actual null-session documentation receipt;
that earlier failed diagnostic is preserved and is not parity proof. The first
post-repair full capture retained six passing lifecycle owners and a schema route
inventory failure: the Native application had not installed the actual OAuth and
email-verification plugins, while Source advertised the built-in endpoints.
Equivalent real plugins/base user settings were configured in both applications.
The final fixture/type gate and all seven real SDK owners passed 1,344 assertions
(`/tmp/issue184-schema-route-ready-owner.log`, terminal 0). Generation captures
complete documents, all physical rows and completed receipts; no default or
adapter callback is evaluated. Throwing declared output validators remained
metadata while the genuine lifecycle transforms completed successfully.
