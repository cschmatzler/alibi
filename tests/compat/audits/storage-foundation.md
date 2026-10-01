# Shared storage foundation for Better Auth 1.7.6

This change supplies persistence contracts for capability implementations. It does not activate organization teams, dynamic roles, anonymous, phone, email OTP, magic links, JWT, or SIWE routes. The TypeScript oracle remains pinned to 1.7.6.

## Verification lifecycle

`VerificationStore` exposes newest-generation lookup without expiry filtering, identifier-wide deletion, atomic consumption, expected-value compare-and-swap, and deterministic reservation. Unsupported custom-store defaults return explicit errors. No default implements a non-atomic read/delete sequence. Existing live lookup APIs remain available to their current callers.

Consumption selects the newest generation and deletes every sibling for its identifier in one transaction. Expired newest rows invalidate older live rows and return no consumed value. Only the actual deletion winner returns a record. SQLite acquires an immediate transaction before reading; independently constructed pools compete against the same database in the concurrency regression. Delete hooks can veto the mutation; winning after hooks run after commit. Identifier deletion observes one hook snapshot for all siblings, matching the pinned adapter. Compare-and-swap uses SQLite/PostgreSQL `UPDATE RETURNING`, runs verification update hooks from the winning snapshot, and advances the optional model-bound `updated_at` field. Other database backends return an explicit unsupported error before mutation.

Expiration cleanup snapshots the configured `advanced.database.default_find_many_limit` page for lifecycle hooks. Any before-hook veto cancels the entire batch. Otherwise every expired match is deleted, while after hooks receive only the original snapshot page. This matches the pinned adapter's bounded `findMany` followed by unrestricted `deleteMany`.

`AuthTransaction::create_verification` lets signup work issue verification records without escaping its transaction. A failed signup callback rolls its issued verification back. Custom stores that lack this operation fail explicitly. Transactional user, account, verification, and session creation callbacks retain their created snapshots and run in operation order only after a successful commit. Rollback discards all queued callbacks. An after-hook error is returned after the writes have committed and cannot roll them back.

Reservation derives the pinned SHA-256 key from `reserve:` and the logical identifier. String and UUID verification schemas support this contract. Numeric schemas must provide a collision-resistant binding; the default returns an unsupported error and leaves no marker. Cleanup or explicit consumption releases an expired reservation.

`CacheAdapter::get_and_delete` is atomic in the memory adapter and Redis adapter. Wiring secondary storage to complete auth persistence remains a separate capability boundary.

## Identity and session contracts

Nullable user fields cover anonymous status, phone number, phone verification, and last login method. Getter defaults preserve application-owned entities that omit these fields. `Option<Option<String>>` updates distinguish leaving a nullable value alone from clearing it. Phone uniqueness permits multiple NULL rows. An appended migration preserves existing users and sessions.

Sessions support active team state and an optional trusted token override. A missing token becomes a secure 32-character alphanumeric value before database `before_create_session` hooks; a hook override is persisted verbatim. Duplicate tokens cannot silently replace an existing session. Batch lookup returns matching persisted rows once each, includes expired rows, respects the configured query limit, and preserves the adapter result order. The bundled SQLite token index determines that order; it is not the request order.

Views carry optional fields without emitting disabled-plugin fields by default. Capability handlers own configured output projection and initialization.

## Organization persistence

Teams, team members, and organization roles remain concrete plugin entities, so `AuthSchema` keeps its four application-owned associated types. Team memberships have an internal unique identity key and exact seat count. Membership addition is idempotent and enforces capacity within a database transaction. Invitation acceptance scopes every team to its organization, checks recipient/session ownership and expiry, and commits invitation status, organization membership, team memberships, and session scope together. A failed later team insertion rolls back earlier insertions.

Deleting a team removes its memberships and prunes its ID only from live pending invitations. User/member/organization deletion removes the relevant links and releases seats. Application-owned numeric user IDs are handled without a hardcoded FK to the bundled user model.

Role mutations are organization-scoped. Permissions preserve insertion order using `IndexMap`, because the pinned adapter persists permission JSON as an observable string. Public team, membership, user-team, and role lists respect the configured query limit. Role counts, seat accounting, and owned deletion cleanup remain unrestricted. The organization migration preserves existing invitations and adds nullable team selection. HTTP role authorization and team configuration are delivered by separate capability changes.

## Evidence and remaining boundaries

Meaningful focused tests cover independent-pool consumption/reservation/CAS races; expired newest generations; wrong token, recipient, session, and tenant; hook cancellation and post-commit observation; compound rollback; seat and invitation races; deletion cleanup; nullable field and populated-table upgrades; secure token and hook overrides; batch adapter order; custom UUID/numeric schemas; atomic cache consumption.

Independent review found and verified repairs for callback execution before commit, CAS snapshot races, and rejection tests that could pass at a later capacity check. Removing each recipient, session-owner, session-expiry, or session-active guard now fails its intended assertion with valid capacities. Focused validation on the isolated branch passed 596 default workspace tests and 635 optional-feature tests, core 147 plus SeaORM 27 tests, strict production Clippy for core/SeaORM with Redis, and the Rustls/Axum/SeaORM/Redis build. Existing ignored tests remain 20 and 22 in the workspace configurations. The coordinator runs the canonical compatibility and coverage gate after integration.

This foundation does not implement secondary-storage-only sessions/verifications, configurable identifier hashing/cleanup, arbitrary additional schema fields/model renaming, JWT keyring persistence, wallet persistence, or capability endpoint hooks/configuration. Those boundaries must remain explicit in the parity audit and capability PRs.

Existing core list operations outside the new contracts still need an audit of the configured default query limit; this foundation does not establish that behavior for them. Millisecond timestamp wire serialization is handled by a separate capability change.
