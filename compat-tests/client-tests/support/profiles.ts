/** Explicit configurations of the pinned authentication runtime. */
export type FixtureProfile =
  | "magic-link-hashed"
  | "magic-link-disabled"
  | "passwordless-hashed"
  | "passwordless-encrypted-reuse"
  | "passwordless-proof"
  | "passwordless-proof-explicit"
  | "passwordless-disabled"
  | "verification-cleanup"
  | "verification-no-cleanup"
  | "email-verification-required"
  | "email-verification-no-signup-mail"
  | "email-verification-failing-notifications";

export function authProfilePath(profile: FixtureProfile): string {
  return `/__test/profiles/${profile}/api/auth`;
}
