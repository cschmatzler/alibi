# Initialized client IP policies

Issue #179 targets the actual published Better Auth 1.7.6 IP utility and rate
limiter. No Source code, comparison allowance or coverage exclusion changes.

## Contract and public configuration

`IpAddressConfig` exposes ordered case-insensitive headers (default forwarding
header only), trusted proxy addresses/CIDRs, an IPv6 grouping prefix, explicit
localhost fallback and tracking opt-out. Dispatch installs the initialized
policy after discarding caller extensions, before application hooks and native
middleware. The resolver validates addresses before using them as persisted
metadata or bucket keys. It never interpolates them into SQL.

Without a valid trusted network, only a single forwarded address is admitted.
With networks, the resolver validates from the right, removes trusted hops and
selects the rightmost untrusted address. A malformed hop rejects that header;
the next configured header can still resolve. CIDRs compare full address bytes
before IPv6 grouping. Invalid networks are ignored. This is the published
forwarding policy, not a socket-peer trust check; deployment must prevent direct
clients supplying proxy headers.

IPv6 defaults to /64; fractional prefixes are floored, negative values group at
zero, and NaN or prefixes at least 128 keep the full address. Mapped IPv4 uses
IPv4 semantics. The published uppercase hexadecimal `FFFF` marker and embedded
dotted IPv6 representation are retained and covered separately. Trim behavior
matches JavaScript, including BOM and excluding U+0085.

Disabled tracking suppresses fallback and IP rate limiting. Otherwise missing
IP shares `no-trusted-ip|path`. Actual NODE_ENV dev/development/test and truthy
TEST enable fallback; the string TEST=0 is truthy in the published environment
utility. Applications can set the fallback explicitly.

Physical session issuers retain empty-string defaults. Passkey authentication,
verified-email auto sign-in and admin impersonation use the same policy as
other issuers and device redemption. API-key virtual principals retain nullable
resolver output and actual header absence instead. Their validated key remains
the authority when a competing cookie exists.

Axum preserves repeated fields in wire order, joining forwarding fields with
commas and Cookie fields with semicolons. This prevents dropping a forwarding
hop while preserving the real issued cookie. IP-limited responses retain the
actual Source JSON text, text/plain;charset=utf-8 and X-Retry-After header.

## Authoring gate and observations

The HTTP owner protects configured extraction, stored session/device context,
bucket identity and its authority boundaries. Genuine regressions include a
forged multi-hop chain becoming a single IP, grouping before CIDR matching,
ignoring tracking opt-out, inconsistent issuers or virtual null defaults, and
loss of an issued cookie when folding repeated fields. Existing generic
middleware tests cannot observe these public configured/physical contracts.

The fixture initializes real Source/native applications. Private observations
read complete physical session rows; owner and foreign user/account/session
state is retained throughout admission, rejection and replay. Device owners
use the official device client and real approval/token consumption. Passkeys
use genuine generated credentials and signed assertions. Verification uses the
actual delivery callback and signed email proof. Impersonation proves operator
restoration and denial of an ordinary user's request. API-key owners create and
validate actual keys while preserving competing cookie principals. No control
manufactures admission, callback receipts or authentication writes.

Raw TCP owners send actual repeated HTTP fields, including Host, and retain the
actual status/body/media/retry observations. Concurrency keeps every response
and compares order-independent outcomes for identical inputs. The Source
memory limiter shares buckets across auth instances; distinct application
endpoints isolate private controls instead of claiming per-instance parity.
Storage, window and plugin-specific policies remain #175.

## Measured predecessors and current gate

Original native production failed 22 of the initial 24 real HTTP scenarios;
repaired behavior passed all 24. The real repeated-forwarding control separately
failed before transport folding: changing the second field rotated the native
bucket while Source rejected the chain into its shared unresolved bucket.

Immutable 56b909eb288c04bf42b7c233f0fcee3909a07efe passed 45 actual scenarios /
1,794 assertions. Four separate real process initializations (dev, development,
test, production with TEST=0) passed 240 assertions. Their environment owner is
`environment/client-ip.test.ts`; it runs against freshly started processes in
those modes, separately from the ordinary production suite.

The first canonical attempt at that head stopped on the old default-header unit
expectation. The existing assertion was updated to the single header already
independently proved by real HTTP. At a6faf479, clean coverage's real JWT owner
caught a virtual-principal IP regression: physical empty defaults had been
applied to nullable virtual metadata. Its canonical attempt was deliberately
stopped while the SDK sweep was active to repair that identified regression;
no completed full-suite result is claimed for that attempt.

The correction passed strict workspace/fixture checks. Its actual Source/native
owner passed 48 scenarios / 1,908 assertions, including three configured
virtual-principal owners. The subsequent bucket-isolation owner retains every
rate-limit denial, full response and mutation guard, and also proves ordinary
`GET /ok` stays healthy: 48 scenarios / 1,944 assertions. Source shares its memory
buckets across applications, so the low-limit private application route is
`/client-ip-rate-check`; it no longer conflicts with the existing `/ok` inventory.
All 3,052 merged-main public evidence cells remain, plus 381 emitted IP cells.
Private application routes are not declared as upstream capabilities.

Predecessor 2804a022's canonical native/harness checks passed, but the SDK result
was 903 passing / 9 failing / 912 scenarios and 63,897 assertions. Besides the
known reset/API-key/lifecycle differences, that run exposed the real private
profile `/ok` collision repaired above. Its four remote null-expiration paths
also reproduce against one unchanged actual Source server: attempt 30 failed
after 29 passes in `/tmp/issue179-source-null-clock.log`. The null-token owner
passes in the final gate. Those failures are retained, not relabeled as passes.

Final immutable program/support head
`0809803e721dd03fd28cbf02a6b2e1f29033f92b` is based on merged signup/password main
`ea2d2da0a73f13d5fd91be996895b81ad9dc8157`. Its complete canonical command ended
with exit 100 at the SDK stage: **926 passing / 5 failing / 931 scenarios,
66,044 assertions**. All 48 IP owners, all 19 new signup/password owners and the
profile inventory pass. Strict default/optional checks, 794 default and 845
optional native tests, fixture 2, harness 70, Axum 36, endpoint 3 and inventory 2
checks pass before that SDK failure. This is not a green canonical claim.

Four failing SDK scenarios retain the independently measured main differences:
the API-key server validator's ten response-content-type paths, and six
update-user/change-password code/message paths in each of three generated
profiles. The fifth, organization trusted role patches, completes its full callback
and physical-state guards and differs only on twelve creation/expiry timestamp
aliases in its sixth setup. The Source/native offsets are 3.195–3.348 seconds,
just outside the unchanged three-second comparator bound. Independent pre-IP
canonical main failed four exact subset paths (member receipt/result creation
and target sibling session expiry before/after). The eight extra aliases are
not claimed to have independently failed on main. Three fresh unchanged
focused runs on the exact main-equivalent eaa7cda9 tree pass 396 assertions each;
a fresh run on this final program also passes 396. A first follow-up attached to
occupied ports and failed fixture reset; it is infrastructure evidence only.
No organization owner, timestamp production, comparison tolerance or Source
implementation is changed to conceal the full-suite result.

Independent final gates on the same immutable head pass:

- Clean native plus all five actual SDK coverage wrappers: **29,794 / 38,672
  source lines = 77.042822%**, unchanged required floor 75%; all 845 optional
  native tests and all five SDK wrappers pass.
- Strict workspace Rustdoc, actual Chromium **2 scenarios / 22 assertions**, and
  locked fixture all-target Clippy with warnings denied.

Exact logs are `/tmp/issue179-0809803e-canonical.log`,
`/tmp/issue179-0809803e-clean-coverage.log`,
`/tmp/issue179-0809803e-docs-browser-fixture.log`,
`/tmp/issue179-main-org-all.log` and
`/tmp/issue179-current-org-isolated-all.log`. Only documentation changes follow
these measured inputs. No Source patch, comparator change, lint suppression,
reduced coverage floor or removed main capability requirement is used.
