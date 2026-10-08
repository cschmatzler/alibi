import { type BetterAuthOptions, betterAuth } from "better-auth";

/**
 * Account-linking policy profiles. `allowDifferentEmails` (default `false`)
 * decides whether an OAuth callback may link to a user whose local email
 * differs from the provider's.
 */
export function accountLinkingFixture(base: BetterAuthOptions) {
  const profiles = new Map<string, ReturnType<typeof betterAuth>>();
  for (const name of ["account-linking-different-emails"] as const) {
    const path = `/__test/profiles/${name}/api/auth`;
    profiles.set(
      path,
      betterAuth({
        ...base,
        basePath: path,
        // Core account-linking policy needs no plugin surface; the differential
        // scenario drives password sessions and the core account routes only.
        plugins: [],
        account: {
          ...base.account,
          accountLinking: {
            ...base.account?.accountLinking,
            allowDifferentEmails: true,
          },
        },
      }),
    );
  }
  return { profiles };
}
