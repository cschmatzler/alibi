import { betterAuth } from "better-auth";
import { twoFactor } from "better-auth/plugins";

export function createTwoFactorTotpFixture(base: Parameters<typeof betterAuth>[0]) {
  const profiles = new Map(
    [
      "two-factor-totp-default",
      "two-factor-totp-config",
      "two-factor-totp-disabled",
      "two-factor-totp-zero",
    ].map(
      (name) =>
        [
          name,
          betterAuth({
            ...base,
            appName: "Fixture Auth",
            basePath: `/__test/profiles/${name}/api/auth`,
            plugins: [
              twoFactor({
                issuer: "Enrollment Issuer",
                totpOptions:
                  name === "two-factor-totp-config"
                    ? { issuer: "Authenticator Issuer", digits: 8, period: 45 }
                    : name === "two-factor-totp-disabled"
                      ? { disable: true }
                      : name === "two-factor-totp-zero"
                        ? { digits: 0 as never, period: 0 }
                        : {},
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
