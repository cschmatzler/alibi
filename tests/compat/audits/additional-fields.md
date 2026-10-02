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

Discovery is complete enough to begin a real before owner; implementation,
capability cells and full before/after gates remain pending. No unrun outcome is
claimed as passing.
