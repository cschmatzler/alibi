# Bearer session authentication (#133)

The public BearerPlugin adapts validated Authorization headers to the configured
signed session cookie. Ordinary session lookup, expiry, revocation and plugin
composition still decide admission. Unsigned tokens are accepted by default;
BearerConfig.require_signature ignores them. Invalid bearer headers leave browser
cookies intact. Genuine issuance returns the decoded signed token in set-auth-token
and adds that header to the ordered, deduplicated exposure list; deletion does not.

The pinned Better Auth 1.7.6 bearer plugin is the oracle. Three official-client
owners cover default, signature-required and actual MultiSession/ApiKey composition.
Real persisted sessions receive deterministic tokens from an application database
hook on both servers, allowing full signed response header comparison. No fixture
supplies authentication, signatures or expected callback decisions. Controls include
case/whitespace, encoded signed values, wrong/foreign signatures, malformed escapes,
extra components, unsigned values, foreign-cookie replacement, revocation and actual
SQL expiry. Complete owner/foreign user/account/session observations remain compared.

Source-self and final differential proof pass 3 scenarios / 416 assertions
(/tmp/issue133-alias-source.log and /tmp/issue133-alias-after.log). The pre-plugin
owner fails on absent real set-auth-token issuance. A further real signed-token
padding alias reproduces a native cookie verifier rejection while Source accepts
identical authenticated HMAC bytes (/tmp/issue133-alias-before.log, all 3 owners
fail). The core decoder now accepts unused trailing bits, keeping padding syntax,
32-byte HMAC verification and constant-time authentication intact.

The distinct public native dispatch owner proves replaced headers reach the
endpoint and completed application hooks under a custom base path. Removing
original-request propagation leaves endpoint authentication working but fails the
completed-hook assertion (/tmp/issue133-native-before.log). Final native owner,
formatting, strict workspace/all-target Clippy, strict fixture Clippy, fixture build
and client TypeScript pass (/tmp/issue133-final-checks.log and
/tmp/issue133-tsc-final.log). Full combined canonical gate evidence belongs to the
PR; focused proof does not claim that the repository-wide SDK baseline is green.

ReplaceHeaders is an additive public BeforeRequestAction variant for real
application authentication adapters. Exhaustive downstream matches must handle
it. It changes the request seen by subsequent hooks and dispatch, preserving
request extensions and virtual sessions. No private mirror, comparator exception,
removed evidence requirement, or test-only production API was introduced. Custom
cookie/cache/stateless configurations and arbitrary plugin ordering remain outside
these bounded default/composition owners.
