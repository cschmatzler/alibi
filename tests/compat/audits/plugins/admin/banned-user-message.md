# Awaited admin banned-user messages

## Bounded contract

The pinned better-auth 1.7.6 admin `bannedUserMessage` option accepts a string or an awaited function over the stored `UserWithRole & Record<string, unknown>`. `dist/plugins/admin/admin.mjs` resolves that function in the session-create before hook only for a banned user whose ban has not expired. `dist/plugins/admin/routes.mjs` invokes session creation for impersonation after its caller and target-admin checks; that creation reaches the same admin before hook. Both paths reject before creating a session. The hidden/read-only additional-field oracle demonstrates that this is the unprojected database user, including application fields omitted from public responses.

Rust keeps the static `AdminConfig.banned_user_message: String` API and adds an optional `AdminBannedUserMessageHandler`, configured directly or through `AdminPlugin::banned_user_message_callback::<StoredUser, _>(handler)`. The public async trait receives `&U` for the application's exact `AuthSchema::User` type. A cloneable opaque wrapper erases only dispatch; safe `Any` downcast and exact `TypeId` validation avoid projecting or serializing the application entity. Debug output hides the handler. Initialization rejects a mismatched user type before this plugin installs its transforms or metadata, then stores immutable callback configuration in `ContextExtensions` for shared session issuance. Impersonation resolves the same handler over its actual stored target. No global mutable callback state or production test-only injection exists.

The callback is awaited only in the nonexpired banned rejection branch. Returned strings become BANNED_USER403 responses. Explicit framework errors pass through unchanged, including documented Upstream400 and500 errors. Static messages and contexts that lack callback configuration retain their existing behavior. User ownership, ban/session writes, original expired-ban response snapshots, and the existing expiry comparison are otherwise unchanged.

## Primary evidence

`tests/compat/client-tests/tests/admin/banned-message.test.ts` owns the public HTTP/official-client callback lifecycle. Two immutable profiles exercise returned strings and explicit callback errors using the unchanged pinned runtime. A real hidden, non-input JSON application field has a stored default. Native storage supplies the same field through a genuine before-create-user hook. A forged client value cannot replace the default, and public signup results omit the field.

Both scenarios retain all original SDK results, signed cookies and actual transport traces. Read-only SQLite state and callback events prove the target ID/email/name/role/ban fields/private metadata actually supplied to each callback. The observations include both sign-in and impersonation, explicit API errors400 and500, absence of target sessions after rejection, wrong-password and authenticated foreign-user denials without callback invocation (the legitimate owner first demotes the foreign user through public set-role, and that foreign user calls the same callback-enabled auth profile), and callback skips for unbanned and expired requests. The expired success paths prove committed session tokens and exact target/impersonator ownership, current-session identity, and unchanged original/foreign owner state. Events are selected by the current stored user ID as well as email/profile, so TS-to-TS runs after database reset do not confuse deleted users' old callback events with the current owner.

The native public AuthBuilder test in `tests/admin_config_tests.rs` independently protects the typed configuration boundary that TypeScript does not possess: configuring a projected `UserView` callback for the stored entity schema must fail with the precise Config error before application bootstrap. A matching stored-entity callback permits bootstrap and normal post-build plugin transforms. Existing real SQLite user/session rows remain byte-for-byte equal through both attempts.

## Baseline failures and focused validation

The new callback configuration cannot compile against a baseline with no callback API. For the behavioral before control, the new trait/configuration/fixture scaffolding was retained while the two production message-resolution owners were restored verbatim from parent aea23a36, and the new model-type validation was disabled. This preserves the actual parent static-message behavior without faking callback results. `/tmp/admin-banned-message-sdk-before.log` records both intended failures: a real banned sign-in rejects but never invokes the configured callback (expected event count1, actual0). `/tmp/admin-banned-message-schema-native-before.log` independently records the wrong-model public builder incorrectly succeeding when validation is absent. All owner repairs were restored before final validation.

* Actual pinned direct HTTP/source oracle: `/tmp/admin-banned-message-oracle.log` (hidden user input, string/explicit-error/ordinary-error paths, expiry skips, real SQLite state).
* Actual pinned TS-to-TS official-client controls: `/tmp/admin-banned-message-oracle-sdk-final.log`, 2 scenarios/276 assertions pass.
* Whole focused admin official-client differential family: `/tmp/admin-banned-message-sdk-final.log`, 24 scenarios/1204 assertions pass.
* Public configuration native tests: `/tmp/admin-banned-message-schema-native-final.log`, 2 tests pass, including the distinct callback model boundary.
* Existing admin native sibling tests: `/tmp/admin-banned-message-native-final.log`, 12 tests pass.
* Strict API/SeaORM library Clippy: `/tmp/admin-banned-message-clippy-final.log`.
* Actual fixture build and strict Clippy: `/tmp/admin-banned-message-build-final.log`, `/tmp/admin-banned-message-fixture-clippy-final.log`.
* SDK TypeScript check: `/tmp/admin-banned-message-typecheck-final.log`.

Only focused checks were run. No inventory, schema, migration, lockfile, harness-comparator, or full-gate changes belong to this slice.

## Remaining boundaries

* Ordinary callback failures are now represented explicitly: an `Internal` returned by `AdminBannedUserMessage` becomes `AuthError::CallbackFailure`, which logs its private cause and emits an empty HTTP500 through both the native response abstraction and Axum. This conversion occurs only after the actual typed callback returns; schema validation, database reads and internal failures elsewhere retain their identities. Explicit Api/Upstream errors including500 preserve their full public response.
* Actual HTTP probes confirm that the source guest-admin guard returns an empty JSON 401 body while native `require_session` currently surfaces structured SessionNotFound. An initial differential guest request exposed that preexisting wire gap; the final callback cases use a real authenticated foreign-user authorization denial and wrong-password rejection as skip controls. Guest wire normalization is not part of this feature.
* Source factory timing versus Rust plugin initialization remains different; ordering against effects from plugins initialized earlier is not claimed. The native test proves ordering against the later application bootstrap and this plugin's transforms.
* The source uses strict expiry `<`; the inherited native `<=` edge boundary remains unchanged and unproved at exact equality.
* Email, username and impersonation ordinary callback failures are covered. An additional immutable compact-cache/anonymous profile proves a failed credential upgrade does not delete the genuine anonymous principal or its session. Cached cookies are issued and transmitted through failures; post-failure session identity is read with explicit disableCookieCache to verify physical authorization. Cached-projection and expired-ban cache behavior remain #221, rather than being normalized or claimed by this callback owner. Other issuing plugins retain their existing shared resolver and endpoint-specific error/redirect contracts. Arbitrary custom schema entities, callback storage captures/transactions, callback mutation, concurrent user updates between the impersonation target lookup and the source hook’s separate user lookup, invalid non-string JS return values, and callback-created sessions are not covered by this bounded proof.

Independent review found that the Rust receipt observer filtered only email/profile, retaining old users' events across database resets. The existing primary owner now resets actual fixture storage, recreates the same email under a new stored user ID, and requires empty callback receipts. Both cases fail before the repair on two/four stale events (`/tmp/admin-banned-message-fixture-repeat-before.log`). Filtering by the actual current stored user ID, like the source observer, repairs both cases; 2 SDK owners / 308 assertions pass in `/tmp/admin-banned-message-fixture-repeat-final.log`. No callback decision or production result is fabricated by the observer.


## Ordinary callback failure regression (#197)

The existing official-client error owner now includes actual ordinary exceptions
in the unchanged pinned fixture and `Internal` returns from the native application
callback. It verifies empty raw HTTP500, complete SDK errors and unchanged target,
owner and foreign user/account/session observations. Wrong passwords and foreign
impersonation remain callback-skip controls; coded400/500 remain public-error
controls. Real username sign-in reaches the same banned stored owner. The
separate anonymous/compact configuration keeps its genuine issued session through
a rejected upgrade and authenticates the original token afterward against physical
storage. A deterministic application email generator prevents random identity
shape differences from obscuring these observations.

The exact pre-fix differential owner fails because native SDK errors contain
`message: "Internal server error"`; the pinned empty response has no message.
`/tmp/issue-197-regression-before-corrected.log` records39 passing admin owners and
this one intended failure. Final `/tmp/issue-197-after.log` records41 passing admin
scenarios /3602 assertions. Private Rust JSON control responses now match Bun's
Response.json charset only for nonempty JSON bodies; public auth responses and
intentionally empty control responses retain their own media type. Comparators,
allowlists, source oracle and coverage floor are untouched. Independent review
checked callback-local classification and permission/session-write ordering.

The independent framework-neutral transport owner fails on nonempty response
bytes when its response mapping is restored to the previous generic renderer
(`/tmp/issue-197-native-transport-before.log`), then passes after the mapping is
restored. It also protects ordinary internal-error JSON and explicit public500
responses. Final native transport, typed application configuration, strict
workspace lint and strict fixture Clippy pass in
`/tmp/issue-197-native-lint-final.log`; TypeScript passes separately.
