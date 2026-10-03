import { betterAuth, type BetterAuthOptions } from "better-auth";
import { emailOTP, twoFactor, jwt, multiSession } from "better-auth/plugins";
import { createJwk } from "better-auth/plugins/jwt";
const old = "managed-old-reader-key-at-least-32-characters";
const current = "compat-test-only-key-not-real-minimum-32chars";
const legacy = "managed-legacy-reader-key-at-least-32-characters";
export function createManagedSecretsFixture(base: BetterAuthOptions) {
  let counter = 0;
  const profiles = new Map<string, ReturnType<typeof betterAuth>>();
  const deliveries = new Map<string, string>();
  for (const mode of ["old", "retained", "retired", "legacy", "bare"]) {
    const path = `/__test/profiles/managed-${mode}/api/auth`;
    const secrets =
      mode === "bare"
        ? undefined
        : mode === "old"
          ? [{ version: 0, value: old }]
          : [
              { version: 2, value: current },
              ...(mode !== "retired" ? [{ version: 0, value: old }] : []),
            ];
    profiles.set(
      path,
      betterAuth({
        ...base,
        basePath: path,
        secret: mode === "bare" || mode === "legacy" ? legacy : undefined,
        secrets,
        rateLimit: { enabled: false },
        account: {
          ...base.account,
          encryptOAuthTokens: true,
          storeAccountCookie: true,
          storeStateStrategy: "cookie",
        },
        databaseHooks: {
          session: {
            create: {
              async before(session) {
                return {
                  data: { ...session, token: `managed${String(++counter).padStart(25, "0")}` },
                };
              },
            },
          },
        },
        session: {
          ...base.session,
          cookieCache: {
            enabled: !["old", "bare"].includes(mode),
            strategy: "compact",
            maxAge: 300,
          },
        },
        plugins: [
          jwt(),
          emailOTP({
            storeOTP: "encrypted",
            async sendVerificationOTP({ email, otp }) {
              deliveries.set(email, otp);
            },
          }),
          twoFactor({
            skipVerificationOnEnable: true,
            backupCodeOptions: { customBackupCodesGenerate: () => ["backup-one", "backup-two"] },
          }),
          multiSession(),
        ],
      }),
    );
  }
  return {
    profiles,
    async handle(request: Request) {
      const url = new URL(request.url);
      if (url.pathname === "/__test/managed-secrets/jwk" && request.method === "POST") {
        const body = (await request.json()) as { profile: string };
        const auth = profiles.get(`/__test/profiles/${body.profile}/api/auth`);
        if (!auth) return Response.json({ error: "Unknown profile" }, { status: 400 });
        await createJwk({
          context: await auth.$context,
          path: url.pathname,
          request,
          headers: request.headers,
        } as any);
        return Response.json({ created: true });
      }
      if (url.pathname === "/__test/managed-secrets/state") {
        const context = await profiles.values().next().value!.$context;
        const accounts = await context.adapter.findMany<Record<string, unknown>>({
          model: "account",
          where: [{ field: "userId", value: url.searchParams.get("userId") }],
          sortBy: { field: "createdAt", direction: "asc" },
        });
        const keys = await context.adapter.findMany<Record<string, unknown>>({
          model: "jwks",
          sortBy: { field: "createdAt", direction: "asc" },
        });
        const users = await context.adapter.findMany<Record<string, unknown>>({
          model: "user",
          where: [{ field: "id", value: url.searchParams.get("userId") }],
        });
        const sessions = await context.adapter.findMany<Record<string, unknown>>({
          model: "session",
          where: [{ field: "userId", value: url.searchParams.get("userId") }],
          sortBy: { field: "createdAt", direction: "asc" },
        });
        const fields = (rows: Record<string, unknown>[], keys: string[]) =>
          rows.map((row) => Object.fromEntries(keys.map((key) => [key, row[key] ?? null])));
        return Response.json({
          users: fields(users, [
            "id",
            "name",
            "email",
            "emailVerified",
            "image",
            "twoFactorEnabled",
            "createdAt",
            "updatedAt",
          ]),
          sessions: fields(sessions, [
            "id",
            "userId",
            "token",
            "expiresAt",
            "ipAddress",
            "userAgent",
            "createdAt",
            "updatedAt",
          ]),
          accounts: fields(accounts, [
            "id",
            "userId",
            "accountId",
            "providerId",
            "accessToken",
            "refreshToken",
            "idToken",
            "accessTokenExpiresAt",
            "refreshTokenExpiresAt",
            "scope",
            "password",
            "createdAt",
            "updatedAt",
          ]),
          keys: keys.map((k) => ({
            ...k,
            publicKey: JSON.parse(String(k.publicKey)),
            privateKey: JSON.parse(String(k.privateKey)),
          })),
        });
      }
      if (url.pathname !== "/__test/managed-secrets/delivery") return null;
      const otp = deliveries.get(url.searchParams.get("email") ?? "");
      return otp
        ? Response.json({ otp })
        : Response.json({ error: "No delivery" }, { status: 404 });
    },
  };
}
