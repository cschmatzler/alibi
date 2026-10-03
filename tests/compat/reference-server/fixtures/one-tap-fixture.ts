/** Actual pinned One Tap configuration profiles with a local Google JWKS transport. */
import { type BetterAuthOptions, betterAuth } from "better-auth";
import { oneTap } from "better-auth/plugins";

const jwks: unknown = await Bun.file(
  new URL("../../../fixtures/one-tap/jwks.json", import.meta.url),
).json();

let jwksFetches = 0;

export function googleOneTapJwks(): Response {
  jwksFetches++;
  return Response.json(jwks);
}

export function createOneTapProfiles(options: BetterAuthOptions) {
  const profiles = new Map<string, ReturnType<typeof betterAuth>>();
  for (const name of [
    "one-tap-default",
    "one-tap-fallback",
    "one-tap-plugin-only",
    "one-tap-missing",
    "one-tap-empty-array",
    "one-tap-empty-audience-member",
    "one-tap-domain",
    "one-tap-domain-any",
    "one-tap-disabled",
    "one-tap-provider-disabled",
    "one-tap-required",
    "one-tap-required-no-mail",
    "one-tap-no-override",
    "one-tap-account-cookie",
    "one-tap-account-cookie-account-fractional",
    "one-tap-account-cookie-account-zero",
    "one-tap-account-cookie-account-negative",
    "one-tap-account-cookie-account-nan",
    "one-tap-account-cookie-fractional",
    "one-tap-account-cookie-zero",
    "one-tap-account-cookie-negative",
    "one-tap-account-cookie-nan",
    "one-tap-account-cookie-infinity",
    "one-tap-account-cookie-override",
    "one-tap-update-link",
    "one-tap-encrypted",
    "one-tap-retain-account",
  ]) {
    const google = {
      clientId:
        name === "one-tap-fallback"
          ? ["one-tap-provider-client", "one-tap-provider-secondary"]
          : "one-tap-provider-client",
      clientSecret: "local-unused-google-secret",
      verifyIdToken: async () => false,
      ...(name === "one-tap-domain" ? { hd: "workspace.fixture.test" } : {}),
      ...(name === "one-tap-domain-any" ? { hd: "*" } : {}),
      disableSignUp: name === "one-tap-provider-disabled",
      overrideUserInfoOnSignIn: name === "one-tap-no-override",
      requireEmailVerification: name.startsWith("one-tap-required"),
    };
    profiles.set(
      name,
      betterAuth({
        ...options,
        basePath: `/__test/profiles/${name}/api/auth`,
        ...(name.startsWith("one-tap-account-cookie-")
          ? {
              session: {
                ...options.session,
                cookieCache: {
                  enabled: false,
                  maxAge: (
                    {
                      "one-tap-account-cookie-fractional": 1.75,
                      "one-tap-account-cookie-zero": 0,
                      "one-tap-account-cookie-negative": -4.25,
                      "one-tap-account-cookie-nan": NaN,
                      "one-tap-account-cookie-infinity": Infinity,
                      "one-tap-account-cookie-override": 1.75,
                    } as Record<string, number>
                  )[name],
                },
              },
            }
          : {}),
        ...(name.startsWith("one-tap-account-cookie-account-")
          ? {
              advanced: {
                ...options.advanced,
                cookies: {
                  ...options.advanced?.cookies,
                  account_data: {
                    attributes: {
                      maxAge: (
                        {
                          "one-tap-account-cookie-account-fractional": 1.75,
                          "one-tap-account-cookie-account-zero": 0,
                          "one-tap-account-cookie-account-negative": -4.25,
                          "one-tap-account-cookie-account-nan": NaN,
                        } as Record<string, number>
                      )[name],
                    },
                  },
                },
              },
            }
          : {}),
        ...(name === "one-tap-account-cookie-override"
          ? {
              advanced: {
                ...options.advanced,
                cookies: {
                  ...options.advanced?.cookies,
                  account_data: { attributes: { maxAge: 7, httpOnly: false, sameSite: "strict" } },
                },
              },
            }
          : {}),
        socialProviders:
          name === "one-tap-plugin-only" || name === "one-tap-missing" ? {} : { google },
        account: {
          ...options.account,
          storeAccountCookie:
            name.startsWith("one-tap-account-cookie") || name === "one-tap-retain-account",
          encryptOAuthTokens: name === "one-tap-encrypted",
          updateAccountOnSignIn: name !== "one-tap-retain-account",
          accountLinking: {
            ...options.account?.accountLinking,
            updateUserInfoOnLink: name === "one-tap-update-link",
            ...(name === "one-tap-update-link" ? { trustedProviders: ["google"] } : {}),
          },
        },
        emailVerification: {
          ...options.emailVerification,
          sendOnSignIn: name === "one-tap-required",
          ...(name === "one-tap-required-no-mail" ? { sendOnSignUp: false } : {}),
        },
        plugins: [
          ...(options.plugins ?? []),
          oneTap({
            ...(name === "one-tap-fallback" || name === "one-tap-missing"
              ? {}
              : {
                  clientId:
                    name === "one-tap-empty-array"
                      ? []
                      : name === "one-tap-empty-audience-member"
                        ? [""]
                        : "one-tap-plugin-client",
                }),
            disableSignup: name === "one-tap-disabled",
          }),
        ],
      }),
    );
  }
  return profiles;
}

export async function oneTapState(profiles: ReturnType<typeof createOneTapProfiles>) {
  const { adapter } = await profiles.get("one-tap-default")!.$context;
  const [users, accounts, sessions] = await Promise.all([
    adapter.findMany<Record<string, unknown>>({ model: "user" }),
    adapter.findMany<Record<string, unknown>>({ model: "account" }),
    adapter.findMany<Record<string, unknown>>({ model: "session" }),
  ]);
  return Response.json({
    jwksFetches,
    users: users.map((row) => ({
      id: row.id,
      email: row.email,
      name: row.name ?? null,
      emailVerified: row.emailVerified,
      image: row.image ?? null,
    })),
    accounts: accounts.map((row) => ({
      id: row.id,
      userId: row.userId,
      providerId: row.providerId,
      accountId: row.accountId,
      scope: row.scope ?? null,
      idToken: row.idToken ?? null,
    })),
    sessions: sessions.map((row) => ({
      id: row.id,
      userId: row.userId,
      token: row.token,
    })),
  });
}
