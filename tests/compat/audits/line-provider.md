# LINE provider (issue #149)

Authority is the unchanged installed Better Auth1.7.6 LINE public factory,
LineUserInfo/LineIdTokenPayload/LineOptions and real helpers. Application uses
that factory; local endpoints redirect only its fixed HTTP destinations.

Authorization uses access.line.me/oauth2/v2.1/authorize with ordered duplicate
preserving openid/profile/email, configured/requested scopes, PKCE, loginHint
and trusted application endpoint/redirect overrides. Code/refresh use secret-post
or public forms at api.line.me/oauth2/v2.1/token; client_key is code-only.

Direct ID-token verification delegates to real form POST /oauth2/v2.1/verify:
id_token,client_id and truthy supplied nonce. Error/no data rejects; returned aud
must strictly equal the client ID, and a truthy returned nonce must strictly
equal the supplied nonce. There is no factory-local JWKS/signature/issuer/age
policy; those checks belong to the actual remote verifier. getUserInfo decodes
an available compact JWT payload without a second verification; failed decode
falls back to bearer GET /oauth2/v2.1/userinfo. Browser code-exchange ID tokens
use that same decode path. Preserve the actual factory distinction rather than
inventing local verification or dropping the remote verification receipt.

Raw original profile.sub owns identity independently of mapper.id. User name
uses truthy name or empty string, email/picture map from profile, verified-email
is false unless mapped. Original profile is retained; existing account-info is
retrieval without new identity admission. No remote logout is supplied.

Authoring gate: actual factory/client/HTTP owners protect LINE's delegated proof,
strict returned client/nonce binding, decode versus fallback, supported loginHint
and raw identity/default scopes. Existing local-JWKS and no-verifier providers
cannot exercise those contracts. Retain full HTTP/PKCE/mapper/physical/foreign
rows, state/replay and rotation/local logout. No private predicate tests or
production seam used only by tests. Advanced discovery, malformed complex field
projection and asynchronous hook composition remain #181/#184/#188/#193.

Initial API and real fixture all-target strict Clippy, formatting and TypeScript
pass. The first script/owner attempts retain their exact outcomes: two bounded
production lint corrections, a TypeScript inferred-record field mistake and an
incorrect SDK error type stopped before runtime; the first actual70 collection
passed58 with12failures. Its five browser failures were incorrect expectations
of space-separated persisted scopes (actual Source joins with commas); six direct
account-info failures were actual ACCESS_TOKEN_NOT_FOUND because no access token
was supplied. A per-half token issuance second also caused an expired JWT lifetime
comparison; the real signer now uses one actual module issuance time, as the
existing credential owner does, with no clock substitution or comparator change.
These are recorded as fixture/oracle findings, not product regressions.

The corrected real70-owner collection /tmp/issue149-corrected70-real-owner2.log
terminates1:69pass/1fail,2,450assertions. All delegated remote proof cases,
cryptographic signature/issuer/audience/expiry denials, strict returned-audience
and returned-nonce controls (including truthy nonstring values with absent caller
nonce), false nonce admission, actual PKCE/grants, decode/fallback distinctions,
raw-subject mapping and foreign isolation pass. Remote proof uses actual JOSE
verification on Source's real HTTP service and independently HMAC-verifies native
remote credentials; the factory itself delegates and binds the response.

The sole retained owner failure is observation.info.data.user.id in the mapped
signed direct account-info case: Source returns the mapper-added ID, while the
pre-existing Native AccountInfoUser response type retains only name/email/image/
emailVerified. Full observations remain; no field or assertion is dropped. This
additional output-projection contract is being independently audited against184,
not repaired with a provider-specific serializer workaround. Default and public
account-info behavior, mapped physical identity and original raw-subject binding
pass. The mapped owner's failed artifact supplies no capability evidence.

Actual unchanged40bf31b2 production with genuine fixture registration and the old
public generic constructor fails default authorization for exactly missing
openid/profile/email before requested scopes, /tmp/issue149-generic-before-owner.log,
exit1/28assertions. Source passes first; Native replaces defaults. Production
and application Cargo.lock are unchanged. The genuine remote service's HMAC
fixture dependency/lock entry is test support, not a patched dependency.

Preserve all5,189 parent requirements and append257 actual passing trace cells
from68owners, totaling5,446. The raw captures are retained. Independent review
and final broad gates remain pending. No Source/comparer edit or hook bypass.


Independent factory/fixtures/shared-owner review found no security or admission
blocker. It confirmed the genuine mapped-ID failure is shared output-presence
support: blindly adding an ID would regress ordinary LINE, whose published
getter omits ID until a mapper adds it. A provider-name flag or dropped field is
not an acceptable repair. The full failing owner remains assigned to184.
Final frozen code is composed on the tested Kick stack over actual signed-header
main2bf51a60 (including147/221/135). It preserves all5,339 stack-parent requirements
plus the257 measured passing LINE cells,5,596total, and all parent fixture
profiles. The own production/test hunks are unchanged across this composition.
