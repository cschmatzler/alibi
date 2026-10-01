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

The correction passed strict workspace/fixture checks. The working-tree
Source/native owner then passed all 48 scenarios / 1,908 assertions, including
three configured virtual-principal owners. Final program
 dda003c5288f778a574be8996ee2a212a66b9157 is rebased onto merged JWT main de61dfb7;
all 3,052 main evidence cells are retained, plus 385 actually emitted public
cells. Its canonical, strict documentation/browser and clean native-plus-SDK
coverage measurements are pending. Earlier partial failures remain recorded;
no Source patch, comparator change or reduced evidence requirement is used.
