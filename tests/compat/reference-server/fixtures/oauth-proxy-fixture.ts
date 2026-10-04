import { Database } from "bun:sqlite";
import { createHash } from "node:crypto";

import { type BetterAuthOptions, betterAuth } from "better-auth";
import { APIError, createAuthMiddleware } from "better-auth/api";
import { getMigrations } from "better-auth/db/migration";
import { oAuthProxy } from "better-auth/plugins";

export const OAUTH_PROXY_SECRET = "local-fixture-dedicated-oauth-proxy-secret-32";
export const OAUTH_PROXY_PATH = "/__test/profiles/oauth-proxy/api/auth";

/** Two genuine auth stores on different transport origins; no copied profile/state. */
export async function oauthProxyFixture(base: BetterAuthOptions, managed = false, cookie = false) {
  const path = cookie
    ? "/__test/profiles/oauth-proxy-cookie/api/auth"
    : managed
      ? "/__test/profiles/managed-proxy/api/auth"
      : OAUTH_PROXY_PATH;
  const control = cookie
    ? "/__test/oauth-proxy-cookie"
    : managed
      ? "/__test/managed-proxy"
      : "/__test/oauth-proxy";
  const modes = new Map<string, string>();
  const optionModes = [
    "dedicated",
    "request",
    "dynamic",
    "environment",
    "environment-skip",
    "error",
    "empty-error",
    "fractional",
    "nan",
    "infinity",
    "negative-infinity",
    "cache",
    "cache-error",
    "signup-absent",
    "signup-disabled",
    "custom",
    "bad-key",
  ];
  const preview = String(base.baseURL);
  const production = preview.replace("localhost", "127.0.0.1");
  const records: unknown[] = [];
  const grants = new Map<string, { challenge: string; redirect: string; used: boolean }>();
  let count = 0;
  let failure = "none";
  let tracking = false;
  const afterRequests: { callbackURL: string }[] = [];
  const sessionHooks: unknown[] = [];
  const databases = new Map<string, Database>();
  let profile: Record<string, unknown> = {
    id: 777,
    email: "proxy-owner@fixture.test",
    email_verified: true,
    name: "Proxy Owner",
    avatar_url: "https://assets.fixture.test/avatar.png",
    state: "active",
    locked: false,
  };
  const instances = new Map<string, ReturnType<typeof betterAuth>>();

  for (const origin of [preview, production]) {
    const database = new Database(":memory:");
    databases.set(origin, database);
    modes.set(origin, managed ? "old" : "dedicated");
    for (const mode of managed ? ["old", "retained", "retired", "legacy", "bare"] : optionModes) {
      const old = "managed-old-reader-key-at-least-32-characters";
      const current = "compat-test-only-key-not-real-minimum-32chars";
      const legacy = "managed-legacy-reader-key-at-least-32-characters";
      const options: BetterAuthOptions = {
        ...base,
        ...(managed
          ? {
              secret: mode === "bare" || mode === "legacy" ? legacy : undefined,
              secrets:
                mode === "bare"
                  ? undefined
                  : mode === "old"
                    ? [{ version: 0, value: old }]
                    : [
                        { version: 2, value: current },
                        ...(mode !== "retired" ? [{ version: 0, value: old }] : []),
                      ],
            }
          : {}),
        database,
        ...(cookie ? { account: { ...base.account, storeStateStrategy: "cookie" as const } } : {}),
        baseURL:
          mode === "dynamic"
            ? { allowedHosts: ["localhost:*", "127.0.0.1:*"], protocol: "http", fallback: origin }
            : mode === "environment"
              ? production
              : origin,
        ...(mode === "error"
          ? { onAPIError: { errorURL: `${preview}/configured-error?kept=yes` } }
          : mode === "empty-error"
            ? { onAPIError: { errorURL: "" } }
            : {}),
        ...(["cache", "cache-error"].includes(mode)
          ? {
              session: {
                cookieCache: {
                  enabled: true,
                  strategy: "compact",
                  maxAge: 120,
                  ...(mode === "cache-error"
                    ? {
                        version: async () => {
                          throw new Error("private cache publication failure");
                        },
                      }
                    : {}),
                },
              },
            }
          : {}),
        basePath: path,
        trustedOrigins: [preview, production],
        plugins: [
          oAuthProxy({
            ...(["request", "dynamic", "environment", "environment-skip"].includes(mode)
              ? {}
              : { currentURL: origin }),
            ...(["environment", "environment-skip"].includes(mode)
              ? {}
              : { productionURL: production }),
            maxAge:
              mode === "fractional"
                ? 0.125
                : mode === "nan"
                  ? NaN
                  : mode === "infinity"
                    ? Infinity
                    : mode === "negative-infinity"
                      ? -Infinity
                      : 60,
            ...(managed ? {} : { secret: OAUTH_PROXY_SECRET }),
          }),
          {
            id: "proxy-provider-policy",
            init(context) {
              if (["custom", "bad-key"].includes(mode)) {
                const provider = context.socialProviders.find(
                  (provider) => provider.id === "gitlab",
                )!;
                provider.callbackPath = "provider-return";
                provider.accountSubject = async ({ tokens, profile }) => {
                  if (!tokens.accessToken) throw new Error("actual provider token required");
                  return mode === "bad-key"
                    ? ""
                    : ((profile as Record<string, unknown>).account_key as string);
                };
              }
            },
          },
          {
            id: "proxy-application-observer",
            hooks: {
              after: [
                {
                  matcher: (ctx) =>
                    tracking &&
                    (ctx.path?.endsWith("/oauth-proxy") || ctx.path === "/oauth-proxy-callback"),
                  handler: createAuthMiddleware(async (ctx) => {
                    const callbackURL = ctx.query?.callbackURL;
                    if (typeof callbackURL !== "string") {
                      throw new Error("actual completion callback required");
                    }
                    afterRequests.push({ callbackURL });
                  }),
                },
              ],
            },
          },
        ],
        databaseHooks: {
          session: {
            create: {
              before: async (session, context) => {
                if (context?.path?.includes("oauth-proxy")) {
                  sessionHooks.push({ userId: session.userId, mode: failure });

                  if (failure === "cancel-session") {
                    return false;
                  }

                  if (failure === "ordinary-session-error") {
                    throw new Error("private proxy session failure");
                  }

                  if (failure === "coded-session-error") {
                    throw new APIError("INTERNAL_SERVER_ERROR", {
                      code: "PROXY_SESSION_DENIED",
                      message: "Configured proxy session denied",
                    });
                  }
                }
                return { data: session };
              },
            },
          },
        },
        emailAndPassword: { enabled: true },
        socialProviders: {
          gitlab: {
            clientId: "proxy-fixture-client",
            clientSecret: "proxy-fixture-secret",
            issuer: `${preview}${control}/provider`,
            disableImplicitSignUp: false,
            ...(mode === "signup-absent" ? {} : { disableSignUp: mode === "signup-disabled" }),
          },
        },
      };
      await (await getMigrations(options)).runMigrations();
      instances.set(`${origin}:${mode}`, betterAuth(options));
    }
  }

  async function state() {
    const output: Record<string, unknown> = {};
    for (const [label, origin] of [
      ["preview", preview],
      ["production", production],
    ]) {
      const { adapter } = await instances.get(`${origin}:${modes.get(origin!)}`)!.$context;
      const [users, accounts, sessions, verification] = await Promise.all(
        ["user", "account", "session", "verification"].map((model) =>
          adapter.findMany<Record<string, unknown>>({
            model,
            sortBy: { field: "createdAt", direction: "asc" },
          }),
        ),
      );
      output[label!] = {
        users: users!.map((r) => ({
          id: r.id,
          name: r.name,
          email: r.email,
          emailVerified: r.emailVerified,
          image: r.image ?? null,
          createdAt: r.createdAt,
          updatedAt: r.updatedAt,
        })),
        accounts: accounts!.map((r) => ({
          id: r.id,
          userId: r.userId,
          accountId: r.accountId,
          providerId: r.providerId,
          accessToken: r.accessToken ?? null,
          refreshToken: r.refreshToken ?? null,
          idToken: r.idToken ?? null,
          scope: r.scope ?? null,
          accessTokenExpiresAt: r.accessTokenExpiresAt ?? null,
          refreshTokenExpiresAt: r.refreshTokenExpiresAt ?? null,
          createdAt: r.createdAt,
          updatedAt: r.updatedAt,
        })),
        sessions: sessions!.map((r) => ({
          id: r.id,
          userId: r.userId,
          token: r.token,
          expiresAt: r.expiresAt,
          createdAt: r.createdAt,
          updatedAt: r.updatedAt,
          ipAddress: r.ipAddress ?? null,
          userAgent: r.userAgent ?? null,
        })),
        verification: verification!.map((r) => ({
          id: r.id,
          expiresAt: r.expiresAt,
          createdAt: r.createdAt,
          updatedAt: r.updatedAt,
        })),
      };
    }
    return Response.json({ ...output, receipts: records, sessionHooks, afterRequests });
  }

  return {
    async reset() {
      for (const database of databases.values()) {
        database.exec("DROP TRIGGER IF EXISTS proxy_delete_veto");
      }

      for (const instance of instances.values()) {
        const { adapter } = await instance.$context;
        for (const model of ["session", "account", "verification", "user"]) {
          await adapter.deleteMany({ model, where: [] });
        }
      }

      grants.clear();
      records.length = 0;
      sessionHooks.length = 0;
      count = 0;
      failure = "none";
      tracking = false;
      afterRequests.length = 0;
      profile = {
        id: 777,
        email: "proxy-owner@fixture.test",
        email_verified: true,
        name: "Proxy Owner",
        avatar_url: "https://assets.fixture.test/avatar.png",
        state: "active",
        locked: false,
      };
      for (const origin of [preview, production]) modes.set(origin, managed ? "old" : "dedicated");
    },
    async handle(request: Request): Promise<Response | null> {
      const url = new URL(request.url);

      if (url.pathname.startsWith(`${path}/`)) {
        const origin = databases.has(url.origin) ? url.origin : preview;
        const forwardedURL = new URL(url);
        if (forwardedURL.pathname === `${path}/provider-return`) {
          forwardedURL.pathname = `${path}/callback/gitlab`;
        }
        return instances
          .get(`${origin}:${modes.get(origin)}`)!
          .handler(forwardedURL.href === url.href ? request : new Request(forwardedURL, request));
      }

      if (url.pathname === `${control}/keys` && managed && request.method === "POST") {
        const input = (await request.json()) as { mode: string; origin?: string };
        if (
          !["old", "retained", "retired", "legacy", "bare"].includes(input.mode) ||
          (input.origin && ![preview, production].includes(input.origin))
        ) {
          return Response.json({ error: "Unknown key runtime" }, { status: 400 });
        }
        for (const origin of input.origin ? [input.origin] : [preview, production]) {
          modes.set(origin, input.mode);
        }
        return Response.json({ status: true });
      }
      if (url.pathname === `${control}/options` && !managed && request.method === "POST") {
        const input = (await request.json()) as { mode: string; origin?: string };
        if (
          !optionModes.includes(input.mode) ||
          (input.origin && ![preview, production].includes(input.origin))
        ) {
          return Response.json({ error: "Unknown option runtime" }, { status: 400 });
        }
        for (const origin of input.origin ? [input.origin] : [preview, production]) {
          modes.set(origin, input.mode);
        }
        return Response.json({ status: true });
      }
      if (url.pathname === `${control}/state`) {
        return state();
      }

      if (url.pathname === `${control}/control` && request.method === "POST") {
        const input = await request.json();
        failure = input.mode;
        tracking = true;
        const database = databases.get(preview)!;
        database.exec("DROP TRIGGER IF EXISTS proxy_delete_veto");

        if (failure === "delete-veto") {
          database.exec(
            "CREATE TRIGGER proxy_delete_veto BEFORE DELETE ON verification BEGIN SELECT RAISE(ABORT, 'proxy delete veto'); END",
          );
        }

        return Response.json({ status: true });
      }

      if (url.pathname === `${control}/profile` && request.method === "POST") {
        profile = await request.json();
        return Response.json({ status: true });
      }

      if (url.pathname === `${control}/provider/oauth/authorize`) {
        records.push({ stage: "authorize", query: Object.fromEntries(url.searchParams) });
        const code = `proxy-fixture-code-${++count}`;
        grants.set(code, {
          challenge: url.searchParams.get("code_challenge")!,
          redirect: url.searchParams.get("redirect_uri")!,
          used: false,
        });
        const callback = new URL(url.searchParams.get("redirect_uri")!);
        callback.searchParams.set("code", code);
        callback.searchParams.set("state", url.searchParams.get("state")!);
        return new Response(null, { status: 302, headers: { location: callback.href } });
      }

      if (url.pathname === `${control}/provider/oauth/token`) {
        const body = Object.fromEntries(new URLSearchParams(await request.text()));
        records.push({ stage: "token", body });
        const grant = grants.get(body.code!);

        if (
          !grant ||
          grant.used ||
          grant.redirect !== body.redirect_uri ||
          grant.challenge !== createHash("sha256").update(body.code_verifier!).digest("base64url")
        ) {
          return Response.json({ error: "invalid_grant" }, { status: 400 });
        }

        grant.used = true;
        return Response.json({
          access_token: "proxy-fixture-access",
          refresh_token: "proxy-fixture-refresh",
          token_type: "Bearer",
          scope: "read_user issued",
          expires_in: 3600,
        });
      }

      if (url.pathname === `${control}/provider/api/v4/user`) {
        records.push({ stage: "userinfo", authorization: request.headers.get("authorization") });
        return Response.json(profile);
      }

      return null;
    },
  };
}
