# Custom API-key prefix comparison

Pinned Better Auth 1.7.6 api-key creation passes length/prefix to the configured
custom generator and stores its full returned key without prepending prefix.
The persisted prefix remains the requested/configured prefix. A legal generator
can therefore return a key that does not begin with that field.

The comparator previously required prefix membership in both runtimes. An
actual source-to-source run fails for a Unicode full key with configured raw_
prefix. The independent harness regression invokes the installed pinned runtime twice,
creates real users and API keys, checks the real SQLite prefix/start/owner,
and compares complete issuance responses. Before the repair it fails only on
both impossible prefix requirements (/tmp/api-key-generator-harness-before.log).

The repair compares observed prefix membership instead. Both absent is valid;
a source-prefixed key paired with a missing-prefix implementation remains
invalid, as does the reverse. Prefix values remain literal. Exact key length,
identity bijection, persisted row relationships, start derivation, rotation,
application data, and trace shape checks remain unchanged. No configuration
marker or comparator exemption is introduced.

The same primary regression checks deliberately missing prefix while retaining
key length and correctly derived start; wrong literal prefix; reversed prefix
membership; and corrupt start. Each negative asserts its relevant diagnostic,
so another guard cannot supply a false success. Existing default-generation
negative controls remain unchanged.

Focused proof: /tmp/api-key-generator-harness-after.log (all harness checks),
/tmp/api-key-generator-harness-typecheck.log (client TypeScript). The first full
harness attempt lacked the reference dependency link, causing only the evidence
gate's ENOENT setup failure; after both project dependency links, the gate passes.
No inventory, lock, capability coverage or production auth change belongs here.
