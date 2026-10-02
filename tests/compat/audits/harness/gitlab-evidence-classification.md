# GitLab admission and capability evidence — Better Auth 1.7.6

This bounded prerequisite follows integrated `5dfa4863`. All 29 committed GitLab
requirements remain unchanged. No inventory removal, comparator, tolerance,
Source fixture, schema, dependency, lockfile or public testing seam is included.

## Actual missing evidence

The original three GitLab official-client owners passed actual Source-to-Source
3 scenarios / 814 assertions (`/tmp/gitlab-evidence-source-self-before.log`).
Their original evidence files are preserved in `/tmp/gitlab-evidence-before-artifacts`.
The focused diagnostic `/tmp/gitlab-evidence-required-before.log` checks every
committed requirement naming those owners and finds 16 of 29 missing.

Each owner supplied the literal state declaration `state`, whereas the collector
requires actual HTTP route IDs. The owners already prove issued authorization
state/PKCE and unchanged or changed physical account/user/session rows; their
state declarations now name the corresponding observed routes.

Published `api/routes/callback.mjs` emits HTTP 302 redirects to the default auth
error endpoint for rejected provider profile admission, mismatched linking email,
and replayed state. The owners now assert complete actual status and default error
Location alongside full unchanged rows, no new principal, original session owner
and replay rejection. The collector had counted these redirects only as success,
leaving genuine rejection and authorization evidence absent.

## Narrow classification contract

The scenario supplies the actual Source origin to recordCoverage only after both
runtime comparisons pass. collectCoverage's optional origin context defaults to
absent; without it, a Location cannot establish ownership and supplies no extra
denial evidence. There is no module-global origin guess or scenario annotation
claiming that a request was rejected.

Classification requires an actual GET callback/provider trace, exact HTTP 302,
a parseable same-origin Location, the same default/profile auth prefix followed
by `/error`, no credentials or fragment, and exactly one error query value. Only
three measured published codes are recognized: email_does_not_match,
unable_to_get_user_info, and state_mismatch. Those traces provide rejection and
authorization rather than success; actual successful callbacks still provide
success in both required GitLab callback owners. Other status/body/header/cookie
observations and all comparison rules remain unchanged.

The harness primary tests default and profile error channels and rejects other
methods/statuses/routes, callback forwarding, foreign origins, a different auth
prefix, missing/malformed locations, URL credentials/fragments (including empty
fragments), duplicate/unknown error values and ordinary successful destinations.
It also retains the route-ID requirement: literal state cannot manufacture state.
`/tmp/gitlab-evidence-harness-before.log` runs that primary against the old
collector and fails precisely because it records success rather than admission
denial. The supported collector passes the same primary.

The authorization category means rejected authenticated admission, not the exact
internal reason: unable_to_get_user_info also covers unavailable provider data.
The actual GitLab owner independently proves locked/inactive policy inputs and
unchanged state. A successful application callback deliberately selecting the
same default `/error?error=...` URL is indistinguishable from failure from this
transport alone. This bounded collector is for the measured Source default error
channel plus substantive owner assertions; it does not promise general outcome
inference or classify arbitrary configured application error destinations.

## Real guest and foreign account controls

The lifecycle owner keeps its real foreign-account 400 rejections and unchanged
physical rows, and adds actual guest get-access-token, refresh-token and link-social
calls. These provide genuine 401 authorization evidence for each required route.
Every result, transport, account/session field and provider receipt remains in
strict comparison; denied calls do not perform token exchange or mutate rows.

The new calls independently exposed a real native wire mismatch. Source
`api/routes/account.mjs:299–303` resolves HTTP token operation ownership through
getSessionFromCtx and throws a bodyless UNAUTHORIZED when no session exists.
get-access-token and refresh-token use this helper, so their SDK errors contain
only status and statusText. link-social instead uses sessionMiddleware and emits
the coded UNAUTHORIZED / Unauthorized body. The Source owner asserts both exact
forms, without treating them as interchangeable.

Only the two native token HTTP handlers map Unauthenticated or SessionNotFound to
an empty JSON-media 401 after their existing input validation. Other errors retain
their types and behavior; owned account selection and token operations remain
unchanged. `/tmp/gitlab-evidence-guest-native-before.log` proves the old production
fails exactly on its extra guest error body (two sibling owners pass). The supported
production passes the same owner, including both routes and genuine foreign calls.
The account-info handler and trusted server-only ownership mode remain separate.

## Focused validation

- Source-self: 3 / 840, `/tmp/gitlab-evidence-source-self-final-v2.log`.
- Source/Rust: 3 / 840, `/tmp/gitlab-evidence-native-final.log`.
- All 29 committed requirements qualify from actual passing records, zero missing:
  `/tmp/gitlab-evidence-required-source-final.log` and
  `/tmp/gitlab-evidence-required-differential-final.log`.
- Entire harness: 43 / 396, `/tmp/gitlab-evidence-all-harness-final-v2.log`.
- TypeScript: `/tmp/gitlab-evidence-typecheck-final-v2.log`.
- Existing native account OAuth owners: 18 pass, `/tmp/gitlab-evidence-native-account-tests.log`.
- Rust formatting and git diff --check pass.
- Strict API library Clippy reaches only inherited PKCE ALPHABET indexing at
  oauth/handlers.rs:55, `/tmp/gitlab-evidence-production-clippy.log`. The
  coordinator owns that separately prepared fix; this slice does not edit or
  suppress it.

An external diagnostic fetch preload was initially placed before Bun's test
subcommand, causing unwanted broad test discovery. That own test process was
stopped immediately and its Source fixture stopped by finally cleanup. Its log
`/tmp/gitlab-evidence-source-self-location-probe.log` is retained as a nonpassing
setup control, not a full gate or classification proof. No Source behavior or
fixture was changed to repair discovery. Actual location proof belongs to the
three explicitly selected primary owners above.

Full canonical gates, inventory integration and publication remain coordinator-owned.
