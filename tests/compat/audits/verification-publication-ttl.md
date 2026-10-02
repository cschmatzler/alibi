# Verification publication TTL comparison

Issue #302 is a tests-only prerequisite for verification storage issue #174.
The unchanged installed Better Auth 1.7.6 Source-source default-duration
counterfactual passed 128 real publication-floor assertions but failed six
integer TTL aliases in `/tmp/issue174-default-source-counterfactual-30.log`.

The implementation is in progress. Acceptance binds each comparison to the
complete raw publication observer, one successful issuing request, its default
300-second OTP/magic or 180-second transfer deadline, and the actual
before-create to cache-set interval. Other application fields remain literal.
No final passing or coverage claim is made by this initial checkpoint.
