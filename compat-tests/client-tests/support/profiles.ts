/** Explicit configurations of the pinned authentication runtime. */
export type FixtureProfile =
  | "email-verification-required"
  | "email-verification-no-signup-mail"
  | "email-verification-failing-notifications";

export function authProfilePath(profile: FixtureProfile): string {
  return `/__test/profiles/${profile}/api/auth`;
}
