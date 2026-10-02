# OAuth linking applies its independent profile policy

Pinned Better Auth 1.7.6 `oauth2/link-account.mjs` calls
`applyUpdateUserInfoOnLink` after implicit account creation. The configured
`account.accountLinking.updateUserInfoOnLink` policy copies name/image and
preserves local email and verification identity. Provider sign-in profile
replacement is a separate policy. A failed link profile update is logged and
must preserve the successfully linked account and session flow.

The shared Rust processor now applies that existing account-link configuration
independently. The focused official-client proof in the following One Tap
feature commit first rejects the unverified local account, verifies its email
through actual delivery and the public verification endpoint, then links a
Google account under explicit trust and profile-sync configuration. It checks
returned and persisted local owner/email/verification, Google account binding,
profile columns and resulting session token. It does not introduce a callback
or storage seam; no duplicate native mirror is added.

`/tmp/one-tap-link-policy-before.log` records the actual pinned-success/Rust
failure: Rust retained `Local Profile` and null image instead of the provider
profile. `/tmp/one-tap-sdk-final.log` records the repaired scenario within
14 passing official-client differential cases (664 assertions).
`/tmp/one-tap-oauth-native-freeze.log` contains the 18 existing OAuth native
integration siblings. This prerequisite is separate from One Tap configuration,
verification ordering and public module/export changes. Coordinator owns
inventory, full gates and publication.
