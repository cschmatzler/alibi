# Application-owned remote JWT claims

Issue #229 is owned by `tests/plugins/jwt/remote-signing.test.ts`. The oracle is the
published Better Auth 1.7.6 plugin and its public `signJWT` helper, with no
changes to the runtime or comparator.

## Contract and repair

The pinned `plugins/jwt/sign.mjs` calls a configured `jwt.sign` before resolving
managed keys or applying JOSE registered-claim setters. It spreads the original
payload and adds `iat`, `exp`, `nbf`, `iss`, and `aud`, retaining supplied values
and property positions. Missing `iat` and `nbf` become own undefined properties;
null dates remain null. Only nullish expiration, issuer, and audience receive
defaults. Relative expiration uses JavaScript addition, including nonfinite
arithmetic and string/array/object primitive conversion. The application owns
validation, serialization, returned strings, and thrown errors.

Rust previously validated and converted raw claims through finite JSON before
calling `SignRemoteJwt`. `RemoteJwtPayload` now exposes raw `JsValue`, ordered
`own_keys`, and `claim` returning `Absent`, `Undefined`, or `Value`. Undefined
properties are omitted from `raw_claims`, so its JSON serialization matches
JSON.stringify; they remain observable through property metadata. The global
JSON representation is unchanged. `JwtSignOptions.header` is now optional:
`None` passes an omitted argument, `Some(Map::new())` passes an empty object.
Existing native applications migrate the callback argument and wrap explicit
headers in `Some`; managed signing treats either header absence or empty object
as before.

Remote callbacks receive defaults without managed claim validation, finite
projection, or local key creation. Their ordinary internal errors use the
existing contextual empty-500 callback transport; explicit API errors and
custom token strings retain their values. Managed local signing retains key
resolution before invalid-date rejection, its JOSE validation, and real signing
and verification rules. Session-derived payload construction now inserts `iat`
before application payload spread, matching the observable callback order.

## Independent evidence

The primary table observes the complete actual callback payload, property order,
header, and key/algorithm selector arguments. Receipt markers represent actual
undefined, nonfinite, and negative-zero values before serialization. They are
never inferred from requested inputs or substituted for callback results.
A genuine application HS256 signer serializes the received payload and signs
with its own key; the client independently verifies the actual compact JWS with
JOSE 6.2.12 and inspects the full decoded payload and protected header.

Cases cover Infinity, negative Infinity, NaN, signed zero, null, false, strings,
arrays, objects, numeric property enumeration, nested nonfinite claims, explicit and default dates, configured
issuer/audience/expiration, exact custom results, and ordinary versus coded
application exceptions. The raw profile genuinely configures fixed issuer and
audience so a nonnumeric expiration cannot turn differing test-server origins
into unrelated literal URL drift. A separate official-client authentication
owner verifies unconfigured origin defaults, issuer/audience/subject, actual
session ownership, guest denial, wrong-audience rejection, persisted foreign
state, callback failures, sign-out and replay denial. Local key rows remain
empty throughout remote operations. The application's configured payload
callback converts user dates to ISO strings and orders its complete user payload
on both servers before signing; the receipt capture does not alter any value or
field.

The trusted server controls call the public plugin helper with the actual auth
context. NaN controls assign NaN in that application's actual in-process input,
which cannot be represented in JSON transport. They do not replace production
claim parsing, signing, authorization, or exception handling. The native
application signer delegates to real HMAC signing; the independent verifier
never uses that signing implementation. The retained public Rust external-key
owner also exercises the new callback API by forwarding raw claims to a real
managed signer with its own independent persisted keyring.

## Validation

The original production implementation, with the fixture adapted only to its
original Map callback and header types, fails the final identical scenarios.
The repaired implementation and Source control both pass all 15 cases. Native
managed JWT and sibling official-client JWT controls retain invalid-date,
key-mint, key-selection/rotation, session-refresh and signature verification
coverage. Exact counts and checks are recorded in the PR.

No comparator, normalization, error allowance, existing owner, or capability
requirement is weakened. The official-client authentication owner is added to
its existing token, signup and sign-out capabilities; private signing controls
do not claim new public endpoints. Full workspace gates remain coordinator-owned.
The external `$autoreview` executable is unavailable in this environment;
independent coordinator review accompanies the focused executable proof.
