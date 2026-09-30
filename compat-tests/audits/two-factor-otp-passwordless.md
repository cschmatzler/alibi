# Combined passwordless OTP enrollment evidence

This follow-up reviews and exercises committed OTP integration `550864d` with
its integrated passwordless configuration. The route uses the configured
password requiredness, validates `method` before `issuer`, and validates the
body before requiring an authoritative session. Credential verification
remains before the OTP branch; the branch enables the user, rotates the actual
stored session with its configured fields, retires the old token, and does not
create a TOTP factor. Non-enable password-bearing routes retain their narrower
password schema. The separate disable validation repair remains separate.

One additional official-client case in the existing passwordless test owner
protects the combined configuration. Existing passwordless cases select TOTP;
existing OTP cases require a password. Neither would reject a merge that made
password required on OTP enrollment, bypassed a retained credential password,
accepted null, changed method/issuer error order, or rotated only a response
without retiring the actual signed cookie and stored token.

The case creates an actual credential account and a real social account row.
It rejects a wrong credential password without mutation, removes the credential
through the existing fixture, checks that only the social account remains, and
rejects null and malformed optional fields without mutation. It then enables
OTP with an omitted password and asserts the official response, updated user,
sole rotated persisted session, absent factor, and denial of the original real
signed session cookie. Delivery uses the existing configured async sender.
Actual verification records prove wrong-owner isolation, counter advancement,
consumption, valid verification, and replay denial. Complete owner and foreign
persisted states remain unchanged through verification; the credential is not
recreated. No social-provider sign-in is claimed by this credential-removal
configuration case.

There is no production change or newly discovered bug in this evidence slice,
and no claim that the integrated implementation failed before the test existed.
The production contract and credible regressions above justify this test at the
public SDK/HTTP/persistence boundary; no weaker duplicate native case or new
fixture seam was added. Source expectations come from published Better Auth
1.7.6 two-factor endpoint schemas and the actual pinned runtime.

Focused proof in the isolated checkout:

- Five passwordless SDK scenarios, 244 assertions in the final family run.
- Complete focused two-factor family: 43 SDK scenarios, 1,914 assertions;
  seven Rust selectors passed in `/tmp/two-factor-otp-passwordless-sdk-final.log`.
- Fourteen two-factor native tests passed in
  `/tmp/two-factor-otp-passwordless-native-final.log`.
- Client TypeScript and `git diff --check` passed; TypeScript log is
  `/tmp/two-factor-otp-passwordless-typecheck-final.log`.

Base is `550864d`. Dependency `f37bb0d` carries only the coordinator's four
existing OTP scenario state-evidence declarations (equivalent to `b6f757b`),
which the coordinator should omit when already integrated. This capability
changes only the existing passwordless test and this audit. No production,
fixtures, selectors, schemas, migrations, locks, comparator behavior, skips,
inventory, or coverage changes. Coordinator independent review is requested;
the skill's external autoreview command is unavailable in this environment.
