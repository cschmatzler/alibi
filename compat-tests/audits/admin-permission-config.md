# Admin role configuration and permission fidelity

This bounded repair follows installed Better Auth 1.7.6
`plugins/admin/has-permission.mjs`, `plugins/access/access.mjs`, and the admin
routes' target-admin classification. The source chooses `options.roles ||
defaultRoles`: an explicit JavaScript empty object is truthy and replaces the
built-in role table with no grants. Previously Rust treated every empty map as
absence and granted builtin admin permissions. `AdminConfig.roles` now exposes
`Option<HashMap<String, RolePermissions>>`: None uses builtins, Some(empty)
intentionally grants none. This approved public typed constructor change also
keeps an explicitly configured empty table present during role-value validation.
The existing custom-role native constructor is adapted; no duplicate unit proof
is introduced.

The source permission role fallback is `(role || defaultRole || "user").split(",")`.
Rust now retains exact user-role tokens rather than trimming them, and an empty
persisted role and empty configured default fall back to user. Target-admin
classification shares the exact persisted-token behavior, while configured
admin role names are trimmed as in the source impersonation route. One role
must authorize the entire requested resource map; role grants are not unioned.
A resource request with zero actions rejects instead of vacuous all() granting
it. The existing explicit admin user ID bypass remains in its original position.

Four official-client scenarios own independent observable contracts:

- An actual persisted admin under roles:{} receives false for get/ban permission,
  403 for a real cross-user read and ban, and leaves every observed target row
  unchanged. Its session still belongs to it. A separate ordinary builtin admin
  can actually read it, protecting against a fixture-wide denial.
- A persisted `user, admin` role cannot grant ban, even when body role/userId
  fields overpost an admin identity. The target admin's persisted state remains
  unchanged. Conversely an ordinary authorized admin may impersonate that
  whitespace-bearing target because its exact tokens do not classify it as
  admin. Actual returned/current owner, impersonatedBy, persisted session token
  and owner are checked; stop restores the original admin user.
- A real empty persisted/default role with an explicit user read grant falls back
  to user: get is permitted, ban is denied with all target state unchanged and the
  original session owner retained.
- A real builtin admin has valid get/session-list permissions and can actually
  read another user, but single and mixed empty-action requests, empty maps, and
  an ungranted impersonate-admins action return false. All target state is
  retained; denial is independent from missing authentication or route setup.

Fixtures configure the unchanged pinned plugin and ordinary production Rust
plugins. Username and two-factor plugins are included equivalently so admin
read responses expose the same installed user schema. There are no new fixture
mutation controls or production test flags. All official client values, primary
transport traces, cookies, returned owner identities and raw readUserState
observations remain compared. Local schema parsing only checks stored session
ownership; its projection does not replace the recorded state.

Actual before proof `/tmp/admin-permission-before.log` runs unchanged ce858d7
production with the final equivalent fixtures (old HashMap only adapts absence
representation). Each of four scenarios independently fails its intended
permission boolean: empty role table grants true, spaced admin grants true,
empty role fails user fallback, or empty actions grant true. The actual pinned
source phase succeeds before each Rust phase. `/tmp/admin-permission-oracle-sdk.log`
independently runs the complete four cases TS→TS, and
`/tmp/admin-permission-oracle.log` retains the fresh in-memory pinned handler
probe using actual issued signed cookies. No comparator change is involved.

Validation: `/tmp/admin-permission-sdk-final.log` runs all 11 admin SDK scenarios
(144 assertions); `/tmp/admin-permission-oracle-sdk.log` runs four complete
TS→TS cases (100 assertions); `/tmp/admin-permission-native-final.log` retains
all 11 native admin tests. Root API/SeaORM and fixture strict Clippy,
TypeScript, actual fixture build, formatting and diff checks are recorded in
`/tmp/admin-permission-{clippy,fixture-clippy,typecheck,build}-final.log`.
The coordinator owns inventory, canonical gates, locks and publication.

Explicit unclosed boundaries: source explicit/unset adminRoles factory
validation (including string versus array and case behavior), administrator-ID
configuration profiles, custom access-control callback implementations, OR
ActionRequest/resource connectors, trusted hasPermission dispatch without HTTP,
source authoritative-session versus general session/cache adapter semantics,
and custom adapter/user schema hooks. Existing role-value input validation
still splits/trims comma strings in Rust while source validates each supplied
string literally; its empty-role schema/error ordering is not claimed repaired.
Source users with pathological role names and other normalization options are
not claimed covered. There are no new schema, migration, lock, dependency,
coverage inventory or comparator changes in this capability.
