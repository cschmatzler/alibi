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
