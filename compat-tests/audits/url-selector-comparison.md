# Literal empty URL selectors

The pinned Better Auth 1.7.6 admin handler accepts URL query selectors whose literal value is empty or whitespace. The official request trace previously interpreted these parsed URL values as generated entity identifiers and rejected even a source-to-source comparison.

The comparator now carries context only from its actual URL parser into that URL's query values. Empty selectors must match literally; absent parameters, repeated value counts and distinct whitespace still fail. Generated empty IDs, session tokens and application objects named `query` retain their existing rejection rules. Nonempty URL identifiers retain identity relationships.

The primary regression invokes the actual pinned admin handler for both fixture origins and empty/whitespace selectors. It failed before the repair. The complete harness passed 41 tests and 317 assertions afterward, with TypeScript checks. Independent review passed the comparison owner's 34 tests and 279 assertions and confirmed that arbitrary objects cannot acquire URL context. No raw comparison exception was added.
