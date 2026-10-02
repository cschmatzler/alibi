# Kick provider (issue #148)

Authority is the unchanged installed Better Auth1.7.6 Kick public factory,
KickProfile/KickOptions and actual authorization/code/refresh helpers. Its
application must register the real public factory; transport redirects only
fixed remote destinations and returns their responses without inventing rows.

Authorization uses id.kick.com/oauth/authorize with ordered duplicate-preserving
user:read before application/requested scopes, PKCE, ignored loginHint and trusted
application authorization/redirect overrides. Code/refresh use secret-post or
public forms at id.kick.com/oauth/token; client_key is code-only. Bearer GET at
api.kick.com/public/v1/users returns an envelope; the factory selects its first
data profile, uses raw user_id for account identity, and maps name/email/
profile_picture with verified-email false unless mapper overrides it. Mapper
receives the selected original profile, independently of account-subject logic.
There is no built-in ID-token verifier, JWKS/issuer/nonce policy or remote logout.

Authoring gate: one actual factory/client table owns Kick defaults, public/secret
forms, selected-first-profile response and raw user_id admission; generic and
nested Kakao owners cannot exercise that public initialization and envelope.
Retain actual full HTTP forms, PKCE digest, original mapper profile and complete
physical rows, foreign identities, state/replay, refresh/rotation and local
logout. Linking and account retrieval retain distinct operation contracts.
No private predicate tests or production exports used only by tests are added.
Complex malformed projections/async callbacks/advanced policies remain bounded
by #181/#184/#188/#193 instead of claiming arbitrary JavaScript emulation.

Strict API/fixture all-target Clippy and formatting passed. An initial script
failed to generate the new SDK owner and returned127 after strict TypeScript;
that log is retained and does not claim an executed owner. The corrected program
passes all40 actual Source/native owners with1,582assertions
(/tmp/issue148-corrected-real-owner.log,exit0). Every remote profile envelope
contains a second valid unselected profile, so success and missing-first-subject
controls prove first-only selection rather than fallback. All full receipts,
raw mapper input, physical and foreign rows, verified mapping/linking policies,
replay/rotation and local logout remain observed.

Independent factory/helpers/production/fixture review found no blocker. Preserve
all4,991 parent cells and append only actual passing Kick trace constraints.
The unchanged actual32b702f8 parent, with only the genuine fixture and its old
public generic constructor, compiles and fails default authorization for the
intended missing user:read default before requested scopes. Source passes first;
Native replaces the default (/tmp/issue148-generic-before-owner.log,28assertions,
exit1). Production and both lockfile diffs are empty. Independent review already
confirms the actual first-profile boundary and original identity binding.
Final canonical evidence and broad strict/docs/browser/clean-floor gates remain
pending on this immutable program. No Source/comparer edit or hook bypass.
