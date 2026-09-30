/** Explicit configurations of the pinned authentication runtime. */
export type FixtureProfile =
  | "session-deferred"
  | "session-no-refresh"
  | "session-deferred-no-refresh"
  | "session-no-freshness"
  | "session-cookie-cleanup"
  | "email-verification-required"
  | "email-verification-no-signup-mail"
  | "email-verification-failing-notifications"
  | "ott-default"
  | "ott-hashed"
  | "ott-no-cookie"
  | "ott-server-header"
  | "ott-refresh-disabled"
  | "ott-refresh-deferred";

export function authProfilePath(profile: FixtureProfile): string {
  return `/__test/profiles/${profile}/api/auth`;
}
