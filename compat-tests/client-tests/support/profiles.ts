/** Explicit equivalent configurations of the pinned runtime. */
export type FixtureProfile =
  | "session-deferred"
  | "session-no-refresh"
  | "session-deferred-no-refresh"
  | "session-no-freshness"
  | "session-cookie-cleanup"
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
  | "email-verification-failing-notifications"
  | "jwt-default" | "jwt-es256" | "jwt-es512" | "jwt-rs256" | "jwt-ps256"
  | "jwt-claims" | "jwt-path-header" | "jwt-plain-rotation"
  | "org-teams-dynamic"
  | "org-roles-limited"
  | "org-roles-no-ac"
  | "org-roles-delegated"
  | "org-roles-callback"
  | "org-teams"
  | "org-teams-no-default"
  | "org-teams-limited"
  | "org-teams-removable";

export function authProfilePath(profile: FixtureProfile): string {
  return `/__test/profiles/${profile}/api/auth`;
}
