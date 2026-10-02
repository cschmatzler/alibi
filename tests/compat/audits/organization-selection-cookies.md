# Organization selection cookies (Better Auth 1.7.6)

This supplement covers the default signed `dont_remember` preference when
`POST /organization/set-active` selects an owned organization or clears a
current selection. It builds on the selection/default-scope audit without
changing that frozen capability.

The pinned implementation calls `setSessionCookie` after either adapter update
in `better-auth/dist/plugins/organization/routes/crud-org.mjs:403,429`.
`better-auth/dist/cookies/index.mjs:167` reads the first matching signed
preference, treats a verified nonempty payload as truthy, omits the session
cookie's `maxAge`, and reissues signed `dont_remember=true`. Its unselected
explicit-null early return does not call this helper. Invalid signatures yield
no preference. The normal session reader may then refresh a one-day session
to the configured seven-day expiry before the selection handler runs
(`better-auth/dist/api/routes/session.mjs:51,170`).

The Rust handler uses the existing HMAC verification and cookie construction
utilities, following the equivalent update-session cookie path. It retains the
selection-write condition, appends both cookies for a valid preference, and
uses the configured persistent lifetime when the first preference is invalid.
It does not modify the persisted expiry itself.

The official-client lifecycle scenario in
`tests/organization/set-active-cookies.test.ts` signs in with
`rememberMe:false`, creates a real organization, and observes the same stored
session through selection, clearing, and an already-unselected no-cookie
request. Both returned browser-session cookies lack `Max-Age` and `Expires`;
the reissued preference is the real signed value. A tampered signed payload
followed by a valid duplicate must produce persistent session cookies and the
actual seven-day reader refresh. A valid first preference followed by the
tampered duplicate must still produce browser-session cookies. The expiry,
session token, owner and active selection are checked against persisted SQLite
rows, rather than a cookie-only success response. No fixture or comparator
changes are needed.

Before the repair, this scenario fails because the preference cookie is
missing. An independent runtime probe also observed the erroneous persistent
`Max-Age=604800` on the legitimate preference path. After the repair the new
scenario passes with 118 assertions. The focused organization and owned
configuration follow-up passes 45 SDK scenarios with 2,686 assertions. API
library tests, strict API library Clippy, client TypeScript, formatting and
diff checks also pass.

This is not a claim about configured cookie caches, custom cookie attributes,
all cookie-producing organization endpoints, or concurrent adapter/session
deletion. Existing persistent-cookie construction adds an `Expires` attribute
alongside `Max-Age`, whereas the default pinned serializer emits `Max-Age`
alone; that broader byte difference remains explicit. The existing transport
comparison follows RFC 6265 `Max-Age` precedence and is unchanged here.
