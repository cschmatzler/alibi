/** Explicit equivalent configurations of the pinned runtime. */
export type FixtureProfile =
  | "email-verification-required"
  | "email-verification-no-signup-mail"
  | "email-verification-failing-notifications"
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
