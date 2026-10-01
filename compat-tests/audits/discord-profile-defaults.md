# Discord normalized profile defaults

Pinned `@better-auth/core@1.7.6/dist/social-providers/discord.mjs` derives public
user name from `global_name || username || ""`. For an avatar hash it chooses
GIF only for the `a_` prefix; other hashes use PNG. A literal null avatar uses a
default image: modern discriminator `"0"` selects
`Number(BigInt(profile.id) >> 22) % 6`, while the legacy discriminator uses
`parseInt(discriminator) % 5`. The `verified` flag remains authoritative for
email verification. IDs are original provider strings, never avatar indices.

Rust's existing Discord mapper used username alone, always PNG, and null image
for null avatars. The constructor now uses a private mapper that corrects those
normalized public-user fields. The original ID/email/verified data and ordinary
OAuth account/session helper remain unchanged. Modern decimal IDs use the
already available `rsa::BigUint` reexport and shift, then IEEE-754 conversion
**before** remainder. There is no dependency or lockfile change. A decimal-only
check prevents the BigUint parser's underscore grammar from widening declared
snowflake input; nondecimal/signed BigInt coercions are outside this bounded slice.

The existing local genuine built-in fixture supplies controlled provider
profiles; actual token/user-info requests produce receipts, and actual public
callbacks create the user/account/session. One table-driven official-client
owner covers global-name priority, empty global-name fallback, animated/static
avatars, modern/legacy defaults, empty-name fallback and unverified email. It
also exercises a provider ID beyond u64 whose shifted integer is 2^53+1:
`37778931862957165903872` selects avatar 2 because Number rounds to 2^53 first.
Exact integer remainder would incorrectly select avatar 3. A decimal ID of 10^340
is actually admitted by Source and creates a default image ending `NaN.png`
after the Number conversion overflows. Both original IDs are retained in actual
account readback. No digest, token replacement or comparison rule is introduced.

Every case asserts the genuine current session/user, exact stored normalized
fields, original provider account ID and owner, one new user/account/session,
and two additional actual provider receipts. Complete callback results, SDK
results, transport traces and core-row snapshots remain in the differential
observation. A foreign credential owner/session is unchanged throughout all eight
callbacks. Existing rejection/replay ownership coverage remains in its separate
primary owners rather than being reimplemented here.

Meaningful baseline `/tmp/discord-profile-meaningful-before.log` fails at the
actual returned name (`Username` versus `Global Name`). Earlier original-provider
Source/Native runtime observations also retain the animated PNG/GIF and null
avatar differences in `/tmp/social-defaults-{source,native}-observations.jsonl`.
Source-self `/tmp/discord-profile-source-control-before.log` passes 1 / 264,
including both large-ID examples before production edits. Final full OAuth
SDK directory `/tmp/discord-profile-sdk-family-final.log` passes 22 / 1282,
including all preceding authorization/rejection cases and existing siblings.
Client TypeScript and strict fixture Clippy pass in
`/tmp/discord-profile-client-typecheck.log` and
`/tmp/discord-profile-fixture-clippy-final.log`. The final fixture build log is
`/tmp/discord-profile-fixture-build-verified.log`, and the real Rust process uses
port 3987. No full gate, inventory, schema or shared target changes were performed.

Explicit open boundaries: unexpected provider JSON types, malformed/nondecimal
or signed snowflake strings, and unusual legacy discriminator prefix/exponent/
whitespace grammars are not claimed. The source uses general JS `parseInt`, while
this mapper handles Discord's declared decimal discriminator values. Source also
adds `image_url` to the **raw** profile object returned by `getUserInfo`; the
existing Rust generic mapper retains the original raw profile. Public account-info
raw-data parity and custom profile/user-info callbacks remain separate capabilities.
This slice establishes normalized public-user and persisted lifecycle behavior,
not complete provider-option coverage or live external Discord integration.

The unchanged final SDK owner also passes the repeated pinned Source-self run
`/tmp/discord-profile-source-control-final.log` (1 / 264). `git diff --check` is
clean. No native mirror of the same mapper table was added: genuine provider HTTP,
SDK, session and SQLite readback already own this regression at the stronger
boundary.

Coordinator independent review of frozen `6241e7dd` is clear for these normalized fields: original provider string IDs remain account subjects, actual token/profile transports and persisted sessions reach all eight cases, Number rounding precedes remainder, and the source raw-profile mutation boundary remains explicitly open. Six additive inventory requirements enforce real sign-in/callback/session consumers. The next canonical integration gate is pending.
