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

Implementation, actual before proof, independent review, measured requirements
and final broad gates are pending. No Source/comparer edit or hook bypass.
