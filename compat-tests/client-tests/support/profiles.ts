/** Explicit configurations of the pinned authentication runtime. */
export type FixtureProfile =
  | "email-verification-required"
  | "email-verification-no-signup-mail"
  | "email-verification-failing-notifications"
  | "jwt-default" | "jwt-es256" | "jwt-es512" | "jwt-rs256" | "jwt-ps256"
  | "jwt-claims" | "jwt-path-header" | "jwt-plain-rotation";

export function authProfilePath(profile: FixtureProfile): string {
  return `/__test/profiles/${profile}/api/auth`;
}
