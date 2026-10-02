# Hugging Face provider (issue #146)

Read-only authority: unchanged installed Better Auth1.7.6 Hugging Face public
factory and profile/options, actual authorization/code/refresh helpers and raw
account resolver. The real factory must execute; controls redirect only fixed
remote HTTP and return provider responses, never synthetic admission or rows.

Default authorization is huggingface.co/oauth/authorize with ordered duplicate
preserving openid/profile/email, followed by application and requested scopes.
PKCE is supplied, loginHint is omitted, defaults can be disabled, and trusted
application authorize/redirect overrides remain. Shared code/refresh forms target
huggingface.co/oauth/token: secret POST clients or genuinely public no-secret
clients. client_key is code-only. Bearer GET uses /oauth/userinfo. Raw sub owns
admission independently of a mapped id; name uses JavaScript truthy name then
preferred_username then empty string, image is picture and verification defaults
nullish false. Original profile reaches the mapper. The factory has no built-in
ID-token/JWKS/issuer verification or remote logout, despite openid scopes.

Authoring gate: one real-client table owns this actual factory wiring, public
versus secret grants, truthy fallback field extraction and raw sub admission.
Existing generic/Figma owners do not exercise these initialization and profile
contracts. Complete HTTP receipts, PKCE digest, physical rows, foreign identities,
replay, refresh rotation and local sign-out remain in observations. Existing
linking and account-info owners protect distinct retrieval/admission boundaries.
No private predicate tests or test-only production exports are needed. Complex
additional fields, async mapper/error composition and malformed transport remain
#181/#184/#188/#193 rather than claimed universal JavaScript emulation.

Implementation, intended actual-parent before failure, independent review,
measured capability ledger and final gates are pending. No Source/comparer edit,
dependency patch or hook bypass is authorized.
