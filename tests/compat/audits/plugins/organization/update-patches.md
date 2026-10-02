# Organization logo patches and update selectors: Better Auth 1.7.6

This slice owns nullable organization logo mutation, blank update selectors, and the update endpoint's nonmember error. It follows the input-validation and metadata response repairs without changing other organization selector helpers or storage schemas.

## Source and public patch contract

`better-auth/dist/plugins/organization/routes/crud-org.mjs::updateOrganization` declares logo as a nullish string and selects `body.organizationId || session.session.activeOrganizationId`. After selection, no organization produces `ORGANIZATION_NOT_FOUND` (400), while a missing principal membership produces `USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION` (400). These checks precede mutation. `adapter.mjs::updateOrganization` forwards an explicit null logo to the configured adapter; omission leaves the column untouched.

The Rust core `UpdateOrganization.logo` and API `UpdateOrganizationData.logo` now use `Option<Option<String>>`: `None` retains the column, `Some(None)` clears it, and `Some(Some(value))` assigns the string, including an empty string. API deserialization uses the existing `serde_with::rust::double_option` contract. The private ordered `JsValue` parser retains field presence before forwarding the patch. SeaORM assigns the inner option directly to the actual logo column. This is an intentional refinement of the public patch field; a caller assigning a string wraps it in both options. The store trait signature, forwarding wrappers, defaults, and unsupported-store behavior are unchanged.

Only the update handler's selection changes. An empty explicit ID falls back to the authenticated current session's active organization; it cannot use another token's selection. A missing/empty fallback returns the source 400 error. Membership is checked against that same persisted authenticated user. Other route selectors and duplicate-slug error handling retain their existing separate contracts.

## Evidence and primary ownership

Two official-client differential scenarios in `tests/plugins/organization/update-patches.test.ts` use two organization owners, three organizations, and two tokens belonging to the first owner with distinct active selections. Both selections are established by actual organization creation on each token, avoiding an unrelated set-active response discrepancy. A third unselected token establishes the missing-selection rejection branch.

The logo scenario verifies omission on a successful name update, SQL null clearing, an accepted empty string, and a replacement string. It observes actual SQLite logo values and exact raw metadata JSON text, retains unrelated organizations/members and both token selections, and rejects a foreign owner's explicit nullable patch plus a guest nullable patch before retrying successfully as the owner. The selector scenario updates the current token's selected organization with a blank ID, then the second token's different organization; the other organization remains unchanged at each step. It rejects an unselected token, allows another owner's own selection, and preserves every unrelated row and token.

The private `includeLogo=true` projection adds only the actual persisted logo field to the opt-in SQLite state view. Existing creation/input projections remain unchanged; no comparator allowance, invented state receipt, or metadata normalization was added.

A native SQLite test owns the distinct public `OrganizationStore` patch interface, without HTTP or serialization. It applies omission, `Some(None)`, empty string, and replacement string, then reads the actual logo/metadata columns and checks identity, slug, creation time, and metadata preservation. This catches a backend ignoring a valid typed clear independently of the HTTP parser.

Both SDK scenarios fail against the prior update/store behavior: an explicit clear returns the unchanged string and a blank selector receives the old 403 nonmember error. The native test fails when the old store retains the original logo. That replay retains the new typed patch/decoder solely to compile the public regression; the old store's string-only assignment is mechanically adapted to `Some(Some(value))`, and the prior selector/authentication logic is restored. The failure is a real SQL transition, not an invented error response. Final focused proof passed twelve SDK scenarios / 736 assertions (two new / 146 plus ten creation/input siblings), 32 organization API tests, six native SQLite logo/metadata/numeric integration tests, strict API/SeaORM library Clippy, strict new-native and compatibility-fixture Clippy, client and bounded reference TypeScript, both Rust format checks, and diff validation.

## Confirmed separate gaps

During the initial two-token setup, `/organization/set-active` with record metadata exposed actual strict wire drift: upstream returns the stored JSON string and Rust returns a parsed object. The source uses `adapter.findOrganizationById` and returns that row directly; Rust uses `OrganizationResponse::from_organization`. This is a separate response projection repair queued after this slice. Current proof establishes selections through actual creation and preserves all metadata byte observations rather than weakening comparisons.

An empty update object remains schema-valid but differs at the adapter boundary. The pinned Kysely adapter forwards an update object whose only metadata key is undefined; Kysely removes undefined assignments and Bun SQLite prepares an assignment-free UPDATE, throwing a syntax error near `where` and yielding an empty 500 response. SeaORM deliberately treats assignment-free updates as no-ops, while the existing Rust store always changes its native updated-at column. Removing that timestamp alone would still return success. No synthetic failure or global adapter behavior change is introduced here.

Physical absent metadata remains SQL NULL upstream versus JSON text `"null"` in the bundled Rust schema; nullable schema/migration and legacy-row policies require their own approved contract. Configured additional fields, organization lifecycle hooks, and update concurrency remain separate boundaries.
