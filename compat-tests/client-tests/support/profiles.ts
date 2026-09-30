/** Equivalent organization configurations in both compatibility fixtures. */
export type FixtureProfile = "org-teams" | "org-teams-no-default" | "org-teams-limited" | "org-teams-removable";

export function authProfilePath(profile: FixtureProfile): string {
  return `/__test/profiles/${profile}/api/auth`;
}
