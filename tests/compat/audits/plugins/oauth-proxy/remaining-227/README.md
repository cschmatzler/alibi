# Remaining supported OAuth proxy contracts — issue 227

The published Better Auth 1.7.6 `oauth-proxy/{index,utils}.mjs`,
`oauth2/{account-key,link-account,utils}.mjs`, `api/routes/callback.mjs`,
`cookies/index.mjs` and core GitLab factory are the independent Source owners.
The tarball SHA512 integrity matches registry metadata. Both private dependency
trees match all 465 published Better Auth files and every published core file;
`source-integrity.json` and compressed file manifests retain the verification.
Neither oracle/comparator code nor excluded packages changed.

## Acceptance owners

| Contract | Actual public owner and retained observations |
| --- | --- |
| Transport/dynamic URLs and environment selection | The dynamic official-client owner exchanges a real grant through independent hosts. The selected process proof starts each host with its own NETLIFY_URL and BETTER_AUTH_URL, proves untrusted Host falls back to the vendor receiver, and proves environment production URL controls skipping while only an explicit productionURL changes the exchange base. |
| POST query/body defaults and configured errors | The POST owner supplies state in a form body and conflicting code in query/body. An empty query code wins and redirects no_code without a provider receipt. JSON POST provider errors use configured fallback and ignore transport error_description, matching Source. Missing/empty errorURL fallbacks remain distinct from state/profile overrides. |
| Custom callback path, account subject, loose payloads and signup options | The custom owner uses an application reverse-proxy route for a genuine external provider-return path, with the actual matching token receipt. Async account authority receives real grant tokens and original nested profile. Invalid subjects reject. A full authenticated loose payload preserves extras and binds via account.accountId rather than display userInfo.id. Distinct new identities prove absent, false and true signup policies. |
| Signed browser preference and cache composition | Public email signin issues the actual signed dont_remember cookie. Proxy issuance after a receiving-runtime cache change emits browser-session token/cache cookies. A real cache-version exception retains its committed session but discards all endpoint cookies. That failure behavior already worked; no invented repair was added. |
| Raw maxAge and pending configuration | The original pending flow survives fractional and negative-infinity rejection. Authentic copies of the real provider payload aged by 65 seconds complete under NaN and positive infinity, distinguishing them from the finite default. Both original and changed full payloads/ciphertexts are retained. |
| Concurrent completion | Two actual requests restore the same still-valid cookie against the existing provider account and each issue a session, matching Source's browser-cookie semantics. No server ledger or stronger transaction guarantee is claimed. |
| General OAuth error option consumer | The ordinary fallback owner bypasses the proxy through its public skip header, proves configured query preservation, genuine state consumption/replay, no token exchange on provider error, and empty-option fallback. The option is consumed by OAuth callbacks and ambiguous-account redirects; it is not a claim of global error-dispatch parity. |

The normal owner is `client-tests/tests/plugins/oauth-proxy/proxy.test.ts`.
The separate `client-tests/process-proofs/oauth-proxy-environment.test.ts` is
intentionally launched with selected process environment inputs. `run-focused.sh`
clears ambient vendor/base variables and sets per-server values only for this
owned proof. No unrelated SDK server receives those environment overrides.

The existing default login/link proofs and #397 cookie nonce/expiry/owner/replay
proof are reused, not replayed. `../cookie-state-227/` retains both adapter raw
pairs for the original restoration contracts. `audits/config/managed-secrets.md`
and `tests/config/managed-proxy.test.ts` already prove pending proxy profiles
through dedicated/managed key retention and retirement; that existing proof is
reconciled without new production changes. Existing state codecs remain #189.

## Before/after and scope

`before-sqlx.log` records the unchanged proxy failing actual POST forwarding and
signed preference emission. `ordinary-before-seaorm.log` records the genuine
configured fallback failure, including Native's old state=state_not_found versus
Source's error=state_not_found. `empty-before-seaorm.log` and its full bounded raw
witness pair record invalid_code and an extra token receipt before the review fix;
Source returns no_code without exchange. All failures are retained.

`final-temp-{sqlx,seaorm}.log` and complete compressed pairs prove five remaining
owners / 490 assertions on each adapter. `affected-seaorm.log` proves the two
subsequently strengthened/repaired owners / 210 assertions. The exact temporary
#420 dependency patch and full tracked tree manifests are retained; no dependency
commit is duplicated in this PR. Later integration receipts qualify these proofs
against actual landed production bytes, and record only affected reruns.

Client TypeScript and strict package-only API Clippy passed. Fixture Clippy first
found a needless struct update in this workpiece; it was removed. Original failed
checks remain in the workpiece evidence; final check receipts are recorded at
integration. Actions are disabled; no hosted CI green is claimed. No full suite,
mutation campaign, coverage gate, or default inventory replay ran.

One first custom fixture attempt omitted GitLab's required active/unlocked
fields and failed on Source before completion; the fixture was corrected. One
first POST-owner extension expected no pending state after an intentionally
failed production exchange; its expected row count was corrected to preserve
that authentic pending state. These are fixture/assertion corrections, not
production regression evidence.
