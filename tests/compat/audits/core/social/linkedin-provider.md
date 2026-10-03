# LinkedIn provider (issue #151)

The unchanged installed Better Auth 1.7.6 LinkedIn public factory and grant
helpers are the authority. Genuine SDK scenarios configure the published
factory; Native independently implements the public transport and mapping.

Authorization retains ordered `profile email openid` defaults, configured and
requested scopes including duplicates, trusted endpoint/redirect overrides and
login hints. The factory omits PKCE. Code and refresh grants use the LinkedIn
access-token endpoint with public or secret-post authentication; `client_key`
is code-only, matching the pinned refresh helper.

Bearer GET userinfo retains the full original profile and mapper inputs. The
raw `sub` owns the physical account independently of a mapped public ID.
Default public output preserves missing/null/numeric name, email and image
values; `email_verified` uses the factory's nullish false default. Typed
persistence remains separate. Trusted mapped extras and public values overlay
the original defaults through the existing output contract. No built-in direct
ID-token verifier, JWKS discovery or remote logout is supplied; generic
asynchronous user-info/refresh callbacks remain configurable.

The strongest owners are the existing 45 genuine factory/SDK scenarios, extended
rather than duplicated. They retain complete HTTP/form/mapper receipts,
physical rows, unrelated principals, issued session/state, callback replay,
refresh rotation, explicit linking, owned getters and local logout. Getter
extensions assert exact public output, foreign denial and unchanged complete
SQL state. No production test seam, Source patch or comparator exemption is
introduced. Broader arbitrary mapper composition remains tracked separately.

The isolated original generic constructor previously failed the genuine ordered
scope owner (`/tmp/issue151-generic-before-owner.log`). Resuming on current main
required only this PR's two commits, modern fixture registration and strict
lint migration; no old LINE or Linear stack implementation was carried.

The unchanged Source passes all 45 enhanced owners, 2,080 assertions
(`/tmp/pr294-source-self-final.log`). Before publication repair, Native passes
40 and fails five owners at their intended exact public profile assertions:
numeric/null name, numeric/null image, and the existing account-info getter
with null/numeric/missing email (`/tmp/pr294-native-before-final.log`). The
repair uses existing `OAuthUserInfoResponse.user_output`, preserving original
JSON separately from typed persistence and account admission.

Focused repaired SDK passes 45/45 with 2,080 assertions. The unchanged original
harness passes 89/89 with 2,367 assertions. Strict TypeScript/lint, all-target
workspace clippy and strict documentation pass (`/tmp/pr294-focused-after.log`).
The complete
unchanged canonical gate and coverage floor remain pending. Independent fresh Source-self and Source/Native receipt sets agree on 315
measured cells from all 45 owners (`/tmp/pr294-independent-recount.json`). All
5,742 baseline requirement entries, 5,738 unique cells and four existing
duplicates are preserved; 315 provider requirement cells are added, including
45 newly measured getter cells. No requirement is inferred from declared flags.

Composed the independently reviewed dispatch producer clock, Discord callback
producer clock and null-default remote JWT publication guards. Their actual
original signing/SQL/transport receipts remain required; no generic timestamp
tolerance was added. Composed harness passes 92/92, 2,536 assertions, and
LinkedIn plus remote JWT SDK passes 60/60, 2,538 assertions
(`/tmp/pr294-shared-focused.log`). The genuine Discord owner separately passes
(`/tmp/pr294-discord-focused.log`). Full canonical validation remains pending.
