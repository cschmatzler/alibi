import { betterAuth } from "better-auth";
import { APIError } from "better-auth/api";
import { twoFactor } from "better-auth/plugins";

export function createTwoFactorTotpFixture(base: Parameters<typeof betterAuth>[0]) {
  const numeric = new Map<string, { digits: never; period: number }>([
    ["two-factor-totp-fraction", { digits: 3.5 as never, period: 30.5 }],
    ["two-factor-totp-negative-period", { digits: 6 as never, period: -30 }],
    ["two-factor-totp-infinite-period", { digits: 6 as never, period: Infinity }],
    ["two-factor-totp-negative-infinite-period", { digits: 6 as never, period: -Infinity }],
    ["two-factor-totp-large-period", { digits: 6 as never, period: 1e30 }],
    ["two-factor-totp-nan", { digits: NaN as never, period: NaN }],
    ["two-factor-totp-invalid-digits", { digits: -1 as never, period: 30 }],
    ["two-factor-totp-infinite-digits", { digits: Infinity as never, period: 30 }],
    ["two-factor-totp-tiny-period", { digits: 6 as never, period: Number.MIN_VALUE }],
  ]);
  const profiles = new Map(
    [
      "two-factor-totp-default",
      "two-factor-totp-config",
      "two-factor-totp-disabled",
      "two-factor-totp-zero",
      ...numeric.keys(),
    ].map(
      (name) =>
        [
          name,
          betterAuth({
            ...base,
            appName: "Fixture Auth",
            basePath: `/__test/profiles/${name}/api/auth`,
            databaseHooks:
              name === "two-factor-totp-fraction"
                ? {
                    ...base.databaseHooks,
                    session: {
                      ...base.databaseHooks?.session,
                      create: {
                        before: async (_session, context) => {
                          const failure = context?.headers?.get("x-two-factor-session");
                          if (context?.path === "/two-factor/verify-totp" && failure) {
                            if (failure === "cancel") return false;
                            throw new APIError("FORBIDDEN", {
                              message: "session creation cancelled by database hook",
                            });
                          }
                        },
                      },
                    },
                  }
                : base.databaseHooks,
            plugins: [
              twoFactor({
                issuer: "Enrollment Issuer",
                skipVerificationOnEnable: numeric.has(name) && name !== "two-factor-totp-fraction",
                totpOptions:
                  numeric.get(name) ??
                  (name === "two-factor-totp-config"
                    ? { issuer: "Authenticator Issuer", digits: 8, period: 45 }
                    : name === "two-factor-totp-disabled"
                      ? { disable: true }
                      : name === "two-factor-totp-zero"
                        ? { digits: 0 as never, period: 0 }
                        : {}),
              }),
            ],
          }),
        ] as const,
    ),
  );
  return async function handle(request: Request, url: URL): Promise<Response | undefined> {
    for (const [name, auth] of profiles) {
      if (url.pathname.startsWith(`/__test/profiles/${name}/api/auth/`)) {
        return auth.handler(request);
      }
    }

    if (url.pathname !== "/__test/two-factor-totp" || request.method !== "POST") {
      return;
    }

    const body: unknown = await request.json();

    if (
      !body ||
      typeof body !== "object" ||
      !("secret" in body) ||
      typeof body.secret !== "string"
    ) {
      return Response.json({ message: "secret required" }, { status: 400 });
    }

    const name =
      "profile" in body && typeof body.profile === "string"
        ? body.profile
        : "two-factor-totp-default";
    const auth = profiles.get(name);

    if (!auth) {
      return Response.json({ message: "unknown fixture profile" }, { status: 400 });
    }

    try {
      return Response.json(await auth.api.generateTOTP({ body: { secret: body.secret } }));
    } catch (error) {
      if (
        error &&
        typeof error === "object" &&
        "statusCode" in error &&
        typeof error.statusCode === "number" &&
        "body" in error
      ) {
        return Response.json(error.body, { status: error.statusCode });
      }
      return Response.json({ message: "Internal server error" }, { status: 500 });
    }
  };
}
