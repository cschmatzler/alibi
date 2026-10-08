# Configuration error coverage in Better Auth 1.7.7

The named-only configuration scenario owns `NO_DEFAULT_API_KEY_CONFIGURATION_FOUND`: absent, unknown, and literal default selectors reject before persistence; the explicit named selector creates and retrieves the key.

The remaining requested codes have existing owners or typed boundaries:

- `SERVER_ONLY_PROPERTY` is an HTTP/server admission error, not a client-bundle constructor error. `generation-cleanup.test.ts` covers client create attempts with trusted-only properties; `options-installed-state.test.ts` covers update admission.
- `INVALID_REFERENCE_ID_FROM_API_KEY` is checked by the session authentication hook, after consuming key usage. `options-installed-state.test.ts` exercises persisted foreign and nonexistent references with stored quota observations.
- `INVALID_USER_ID_FROM_API_KEY` is exported but has no throw site in the pinned runtime. Creating with `userId` from HTTP rejects `UNAUTHORIZED_SESSION` instead; the existing generation-cleanup scenario owns that guard.
- `INVALID_API_KEY_GETTER_RETURN_TYPE` guards a JavaScript getter returning a non-string during authentication. Rust's public `ApiKeyGetter::get_key` returns `AuthResult<Option<String>>`; a number or array cannot be returned through that API. Adding a fixture that fabricates the upstream error would supply the expected outcome rather than exercise an owner. Existing getter scenarios cover actual missing/string/application-error returns through both plugins.

This scope avoids inventing executable native contracts for unrepresentable callback types or exported unused error names.
