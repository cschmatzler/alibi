/** Default published Google verifier; only its real HTTP JWKS transport is redirected. */
import { type BetterAuthOptions, betterAuth } from "better-auth";

export function googleIdTokenProfiles(options: BetterAuthOptions) {
  const profiles = new Map<string, ReturnType<typeof betterAuth>>();
  for (const name of [
    "google-id-default",
    "google-id-array",
    "google-id-empty-array",
    "google-id-domain",
    "google-id-domain-any",
    "google-id-disabled",
    "google-id-override",
  ] as const) {
    profiles.set(
      name,
      betterAuth({
        ...options,
        basePath: `/__test/profiles/${name}/api/auth`,
        socialProviders: {
          google: {
            clientId:
              name === "google-id-array"
                ? ["google-default-client", "google-secondary-client"]
                : name === "google-id-empty-array"
                  ? []
                  : "google-default-client",
            clientSecret: "local-google-default-secret",
            ...(name === "google-id-domain" ? { hd: "workspace.fixture.test" } : {}),
            ...(name === "google-id-domain-any" ? { hd: "*" } : {}),
            disableIdTokenSignIn: name === "google-id-disabled",
            ...(name === "google-id-disabled" ? { verifyIdToken: async () => true } : {}),
            ...(name === "google-id-override" ? { verifyIdToken: async () => false } : {}),
          },
        },
      }),
    );
  }
  return profiles;
}
