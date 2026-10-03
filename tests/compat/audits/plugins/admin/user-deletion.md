# Admin user deletion

Pinned Better Auth 1.7.6 admin remove-user authenticates the current stored
session, checks delete permission and rejects self-removal. Missing sessions
produce an empty JSON 401 response. A successful removal deletes the target's
credential/provider accounts and sessions, then its user. Further attempts
return USER_NOT_FOUND. Other principals and the admin remain unaffected.

The pinned internal adapter deliberately does not delete plugin-owned twoFactor
rows. Actual enrollment exposed a Rust foreign-key cascade difference. The
bundled schema omits that user foreign key. The single squashed auth migration installs this shape; there is no upgrade path from earlier bundled shapes.
Deleted-user session/password access remains rejected.

The official client regression enrolls a real factor, seeds a second provider
account, creates two sessions, rejects a guest/non-admin/self deletion, deletes
through the authorized admin, inspects persisted rows, and rejects session and
credential reuse. Before logs expose the empty-401 wire difference and then
factor-row loss; after seven admin scenarios / 44 assertions pass.

Independent review found no authorization or persistence issue. The canonical gate passed: 265 SDK scenarios / 7,604 assertions, 37 harness
tests / 210 assertions, two Chromium tests / 22 assertions, and 79.34% source
line coverage (23,962 / 30,202). Other admin
configurations, remove-user string coercion/media ordering and custom adapter
cleanup policies remain separate work; this is not a claim of every admin option.
