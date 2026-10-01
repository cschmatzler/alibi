# OAuth verifier and linking/token response fidelity

Pinned `better-auth@1.7.6` sources are `dist/oauth2/state.mjs:20`,
`dist/crypto/random.mjs`, `dist/oauth2/link-account.mjs:47`,
`dist/oauth2/errors.mjs`, and `dist/api/routes/account.mjs:399`.

The ordinary OAuth state issuer now generates a 128-character verifier from the
source alphabet `a-z`, `0-9`, `A-Z`, `-_`. It retains the existing cryptographic
random generator, SHA-256 challenge, immutable stored state, callback correlation,
expiry and single-use behavior. The former 43-character verifier was valid PKCE
but differed from the pinned runtime's visible token exchange. Actual local
provider HTTP receipts failed the independently derived challenge/length contract
at 128 versus 43 in `/tmp/gitlab-pkce-meaningful-before.log`. Receipts retain their
whole form; returned observations reversibly wrap only the random verifier as
`{token, length}`, using the existing strict token bijection, and locally verify
SHA256 of that actual verifier equals the actual issued authorization challenge.
No comparison rule or receipt generator was added.

An authenticated foreign user's link to a verified profile with a different email
continues to reject before account lookup or writes. Its exact callback code is
now `email_does_not_match`. The existing official-client rejection owner retains
missing/tampered/revoked guards, a positive same-owner link, every owner/account/
session snapshot, and the subsequent foreign linking rejection. Its intended
old literal-code failure is `/tmp/oauth-link-email-code-before.log`.

`AccessTokenResponse.id_token` omits an absent ID token as the source's nullish
expression does. All its constructors and consumers were inspected: the sole
constructor is `oauth/account.rs::valid_access_token`, used by the ordinary
authenticated get-access-token route. Some values, including the empty string,
remain serialized. The independent refresh response keeps its existing null
contract. The primary official-client proof reads access and original permission
scopes after a genuine no-ID-token GitLab refresh, retaining every returned field
and saved account row plus foreign access/refresh denials. Before, the strict
comparison fails solely at `observation.accessed.data.idToken` presence in
`/tmp/gitlab-sdk-repaired.log`.

The GitLab provider capability is frozen separately and owns the actual provider
exchange and no-ID-token lifecycle proof. This prerequisite changes only shared
OAuth handlers, the one access response field, the existing linking rejection
owner and this audit. It adds no schema, dependency, comparator, inventory or
global authentication changes. Final focused validation is recorded in the
coordinator handoff. The final OAuth SDK family passes 25 scenarios / 2108
assertions (`/tmp/gitlab-sdk-family-final.log`); Source-self passes five scenarios /
914 assertions (`/tmp/gitlab-source-sdk-final.log`). All 18 native account OAuth
consumers pass (`/tmp/gitlab-native-siblings-final.log`), with strict fixture
Clippy and client/reference type checks. Broad transport, unusual token payloads and unrelated OAuth
configuration are not claimed by these repairs.

Coordinator independent review is clear for c39eb88e: pinned verifier alphabet,
exact linking error literal and sole access-token response constructor inspected.
The retained signed foreign callback primary now has four additive required
callback categories, alongside its actual same-owner successful persisted link.
No prior required evidence is removed.
