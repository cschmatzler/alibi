# Compact cache exotic-input readers (issue #222)

Reference: published Better Auth **1.7.6**, measured in the repository's UTC Bun
runtime. The owner is `tests/core/session/cookie-cache.test.ts`, with separate
public-helper and HTTP observations. No provider, configured-cookie-name,
rotation, JWT or JWE behavior is added by this workpiece.

`reference-server/probes/compact-cache-inputs.ts` generates the original signed
inputs in `tests/fixtures/session/compact-exotic-inputs.json` using the published
`safeJSONParse` and `getCookieCache`. Every input retains its complete original
token, decoded bytes in hex, envelope, signature, raw Cookie header, full decoder
result and version-callback arguments. JavaScript-only values retain the original
envelope and decoded result as JSON text, so storing the evidence does not invent
invalid Rust strings or drop their code units. The official-client scenarios
also retain actual original Source/Rust writer tokens and all ordered raw
Set-Cookie headers through the existing authenticated compact-cache atom.

The exotic application uses an actual database session-create hook to assign the
first genuine session token used by the fixed inputs. The HMAC-authenticated
synthetic cache projection is intentionally distinct from the physical owner.
Fallback must return the physical owner, not a fabricated record or the cached
name. A second genuine owner supplies the token-graft control. Every owner and
foreign physical user/account/session/verification column is compared before
and after rejection; revocation additionally proves that fallback cannot
reconstruct a missing physical session.

## Measured reader distinctions

* The public helper parses the final chunk-name component with `parseInt`,
  including leading zero, signed, partial, nested, empty, negative and unsafe
  numeric suffixes. The HTTP reader accepts only canonical nonnegative safe
  integers. Both sort selected indices, concatenate values and authenticate the
  resulting original envelope. Neither requires contiguous indices; an intact
  token split across indices 2 and 9 remains valid.
* The helper and HTTP chunk reader use Better Auth's last-valid-duplicate cookie
  parser. HTTP's base-cookie lookup uses Better Call's **first** duplicate.
  A truthy base wins over chunks; an empty first base falls through to chunks.
  Quoting, incomplete base quotes, percent decoding, ignored invalid entries,
  duplicate index aliases, gaps, missing prefixes and truncation remain separate
  recorded inputs. Complete raw headers are compared literally for fixed tokens.
* The published binary decoder chooses a base64 alphabet, stops at the first
  padding character and discards residual bits. Its TextDecoder removes an
  initial BOM and replaces malformed UTF-8. Authentication uses the resulting
  parsed/revived JSON, not re-encoded original bytes. A signature over the
  unrevived overflowing date is rejected; a correctly signed replacement
  character survives a genuinely malformed original byte.
* Invalid base64 characters throw before fallback. The genuine HTTP get-session
  route returns `FAILED_TO_GET_SESSION`/500. A malformed JSON envelope, wrong
  HMAC or failed payload schema is a cache miss and performs real storage lookup.
* Date revival remains the exact four-digit ISO-Z grammar. Expanded-year and
  legacy expiry strings fail the date schema; day overflow, midnight overflow
  and fractional truncation can become real dates. A revived midnight past 9999
  emits the canonical six-digit `+010000` year. This differs from accepting an
  original expanded-year string, which the reviver leaves as a string.
* `session.userId` coerces null, booleans, numbers, arrays and plain objects to
  strings. Empty arrays produce an empty string. Revived Date values, including
  array elements, use UTC Date primitive strings in this measured runtime;
  expanded/legacy strings outside the revival grammar remain ordinary strings.
  Plain or primitive `__proto__` values and inherited non-callable `toString`
  rejection are measured separately. Enumerable projection data loses
  `__proto__` during the second pre-parsed-object revival, after HMAC verification.
* Absent image/IP/user-agent fields stay absent; explicit null stays null.
  Native views retain omission metadata instead of introducing an Undefined
  variant. Their normal stored-model constructors still emit their usual fields.

HMAC/schema rejection and a mismatched signed session token precede the HTTP
version callback. An authenticated, bound version mismatch or expired outer/
embedded session reaches the callback before storage fallback. The public helper
has no separately signed-token binding check, so its callback receipt is measured
independently. Missing HTTP token authority returns null despite a valid cache.

## Native representation boundary

Rust's UTF-8 `String` cannot contain an unpaired UTF-16 surrogate. A native
own-property JSON object does not expose an inherited `Array.prototype.toString`
method. The pinned helper accepts these JavaScript-only values; the frozen
`javascriptOnlyObservations` explicitly preserve their raw envelopes and full
published results. The native decoder rejects these representations and uses
physical storage. No native placeholder, JavaScript prototype model, generic
Undefined enum, lossy string replacement or comparator exemption is introduced.
The same genuine-builder native control runs on both SQLx and SeaORM and checks
complete physical SQL snapshots, including the foreign owner. A valid supported
cache control proves these rejections do not come from a broken token or secret.

A Source writer's undefined object property is omitted by JSON.stringify; it is
not an additional value in the original signed JSON envelope. The absent userId
case measures the published decoder's actual rejection. Symbols, functions,
accessors and arbitrary pre-parsed JavaScript objects have no original-byte
compact-cookie representation. Locale/timezone-dependent Date-to-string behavior
outside the explicitly measured UTC runtime is not a portable Rust string
contract established by these tests.

## Comparison and regression evidence

Original fixed inputs are literal application data, including invalid date
syntax. All actual HTTP responses, callback receipts and persisted rows remain
in the normal strict comparison graph. Empty cached `session.userId` strings
compare literally only when both sides contain the exact empty value at that
schema field; an empty generated user ID, foreign replacement or missing field
still fails. Valid six-digit ISO output joins the existing timestamp grammar;
malformed five-digit years and changed lifetimes still fail. Harness negative
controls cover both corrections. There is no scenario skip, filtered difference,
raw-field removal or entropy exception for a malformed input.

Retained logs under `/tmp/compact-222-*` distinguish instrumentation errors from
intended regressions. `before-sqlx-v4` reaches Source successfully and fails on
native optional-field null synthesis and duplicate-chunk selection.
`after-seaorm-v1` retains the real `+10000` versus `+010000` production failure.
Earlier path, callback-suppression, parser-expectation, compilation and lint
errors are retained and are not counted as passing proof. The native control's
initial one-hour physical session legitimately refreshed under a seven-day
configuration; its corrected fresh session uses that actual configured lifetime
and retains exact SQL equality without suppressing refresh or normalizing rows.

Validation commands are file-selected official-client runs with
`BETTER_AUTH_COMPAT_BACKEND=sqlx` and `seaorm`; targeted native session/model/
refresh controls; comparator negative controls; TypeScript/lint/format checks;
strict production and fixture Clippy. Complete local gates are intentionally
owned by the coordinator, not this workpiece.
