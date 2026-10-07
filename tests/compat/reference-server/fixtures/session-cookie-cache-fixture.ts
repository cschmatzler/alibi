import { Database } from "bun:sqlite";

import { apiKey } from "@better-auth/api-key";
import { passkey } from "@better-auth/passkey";
/** Immutable real compact-cache configurations and actual callback/state controls. */
import { betterAuth, type BetterAuthOptions } from "better-auth";
import { APIError } from "better-auth/api";
import { getMigrations } from "better-auth/db/migration";
import {
  admin,
  anonymous,
  deviceAuthorization,
  jwt,
  multiSession,
  oneTimeToken,
  organization,
  twoFactor,
  phoneNumber,
} from "better-auth/plugins";
import { createJwk } from "better-auth/plugins/jwt";
export async function sessionCookieCacheFixture(base: BetterAuthOptions, database: Database) {
  const profiles = new Map<string, ReturnType<typeof betterAuth>>();
  const states = new Map<
    string,
    {
      version: string;
      failure: boolean;
      sequence: number;
      sessionSequence: number;
      events: unknown[];
    }
  >();
  const modes = [
    "jwt-interactions",
    "jwe-interactions",
    "jwe-old",
    "jwe-retained",
    "jwe-retired",
    "jwt",
    "jwe",
    "managed",
    "override-fractional",
    "override-nan",
    "override-positive",
    "override-zero",
    "override-negative",
    "standard",
    "attributes",
    "defaults",
    "exotic",
    "disabled",
    "version",
    "version-api",
    "version-ordinary",
    "zero",
    "nan",
    "fractional",
    "negative",
    "infinite",
    "negative-infinite",
    "date-version",
    "guards",
    "interactions",
  ] as const;
  for (const mode of modes) {
    const state = {
      version: "1",
      failure: false,
      sequence: 0,
      sessionSequence: 0,
      events: [] as unknown[],
    };
    states.set(mode, state);
    const callback = async (session: Record<string, unknown>, user: Record<string, unknown>) => {
      await Promise.resolve();
      state.events.push({ mode, session: structuredClone(session), user: structuredClone(user) });
      if (state.failure && !user.isAnonymous) {
        if (mode === "version-api") {
          throw new APIError("INTERNAL_SERVER_ERROR", {
            code: "APPLICATION_CACHE_DENIED",
            message: "Configured cache version rejected issuance",
          });
        }
        throw new Error("Configured cache version rejected issuance");
      }
      return state.version;
    };
    const maxAge =
      mode === "zero"
        ? 0
        : mode === "nan"
          ? NaN
          : mode === "fractional"
            ? 0.5
            : mode === "negative"
              ? -1
              : mode === "infinite"
                ? Infinity
                : mode === "negative-infinite"
                  ? -Infinity
                  : 300;
    const options: BetterAuthOptions = {
      ...base,
      ...(["jwe-old", "jwe-retained", "jwe-retired"].includes(mode)
        ? {
            secret: undefined,
            secrets:
              mode === "jwe-old"
                ? [{ version: 1, value: base.secret as string }]
                : [
                    { version: 2, value: "cache-managed-new-secret-at-least-32-characters" },
                    ...(mode === "jwe-retained"
                      ? [{ version: 1, value: base.secret as string }]
                      : []),
                  ],
          }
        : {}),
      ...(mode === "managed"
        ? {
            baseURL: "https://session-cache.fixture.test",
            advanced: { ...base.advanced, useSecureCookies: false },
            trustedOrigins: [base.baseURL as string],
          }
        : {}),
      basePath: `/__test/profiles/session-cache-${mode}/api/auth`,
      ...(mode.startsWith("override-")
        ? {
            advanced: {
              ...base.advanced,
              useSecureCookies: false,
              defaultCookieAttributes: { maxAge: 99 },
              cookies: {
                session_data: {
                  attributes: {
                    maxAge:
                      mode === "override-zero"
                        ? 0
                        : mode === "override-negative"
                          ? -1
                          : mode === "override-fractional"
                            ? 0.5
                            : mode === "override-nan"
                              ? NaN
                              : 17,
                  },
                },
              },
            },
          }
        : {}),
      ...(mode === "defaults"
        ? {
            advanced: {
              ...base.advanced,
              useSecureCookies: false,
              defaultCookieAttributes: {
                path: `/__test/profiles/session-cache-${mode}/api/auth`,
                domain: "localhost",
                sameSite: "strict",
                httpOnly: false,
              },
            },
          }
        : {}),
      ...(mode === "attributes"
        ? {
            advanced: {
              ...base.advanced,
              useSecureCookies: false,
              defaultCookieAttributes: {
                path: "/discarded",
                domain: "discarded.invalid",
                sameSite: "none",
                httpOnly: true,
              },
              cookies: {
                session_token: {
                  attributes: {
                    path: `/__test/profiles/session-cache-${mode}/api/auth`,
                    domain: "localhost",
                    sameSite: "lax",
                  },
                },
                session_data: {
                  attributes: {
                    expires: new Date("2027-01-01T00:00:00Z"),
                    partitioned: true,
                    secure: true,
                    path: `/__test/profiles/session-cache-${mode}/api/auth`,
                    domain: "localhost",
                    sameSite: "strict",
                    httpOnly: false,
                  },
                },
              },
            },
          }
        : {}),
      ...(mode.endsWith("interactions") || mode === "exotic"
        ? {
            databaseHooks: {
              session: {
                create: {
                  async before(session) {
                    const sequence = ++state.sessionSequence;
                    return {
                      data: { ...session, token: `0001${String(sequence).padStart(28, "0")}` },
                    };
                  },
                },
              },
            },
          }
        : {}),
      ...(mode.endsWith("interactions")
        ? {
            emailVerification: {
              ...base.emailVerification,
              autoSignInAfterVerification: true,
              async sendVerificationEmail({ user, url, token }, request) {
                state.events.push({
                  mode,
                  stage: "verification-mail",
                  user: structuredClone(user),
                  url,
                  token,
                  request: request
                    ? {
                        method: request.method,
                        url: request.url,
                        marker: request.headers.get("x-lifecycle-marker"),
                      }
                    : null,
                });
              },
              async beforeEmailVerification(user, request) {
                state.events.push({
                  mode,
                  stage: "before-verification",
                  user: structuredClone(user),
                  request: request
                    ? {
                        method: request.method,
                        url: request.url,
                        marker: request.headers.get("x-lifecycle-marker"),
                      }
                    : null,
                });
              },
              async afterEmailVerification(user, request) {
                state.events.push({
                  mode,
                  stage: "after-verification",
                  user: structuredClone(user),
                  request: request
                    ? {
                        method: request.method,
                        url: request.url,
                        marker: request.headers.get("x-lifecycle-marker"),
                      }
                    : null,
                });
              },
            },
          }
        : {}),
      plugins: [
        ...(mode === "managed" ? [jwt({ sessionCookieCache: true })] : []),
        organization(),
        anonymous({
          generateRandomEmail: () => `cache-anonymous-${mode}-${++state.sequence}@fixture.test`,
          generateName: () => "Cache Anonymous",
          onLinkAccount: async ({ anonymousUser, newUser }) => {
            await Promise.resolve();
            state.events.push({ mode, link: { anonymousUser, newUser } });
          },
        }),
        ...(mode === "guards"
          ? [
              admin({ defaultRole: "admin" }),
              apiKey({ enableSessionForAPIKeys: true }),
              passkey(),
              oneTimeToken(),
              deviceAuthorization(),
              phoneNumber({
                async sendOTP({ phoneNumber, code }) {
                  state.events.push({ mode, stage: "phone-delivery", phoneNumber, code });
                },
                async callbackOnVerification({ phoneNumber, user }) {
                  state.events.push({
                    mode,
                    stage: "phone-verified",
                    phoneNumber,
                    user: structuredClone(user),
                  });
                },
              }),
            ]
          : []),
        ...(mode.endsWith("interactions")
          ? [
              twoFactor({
                otpOptions: {
                  async sendOTP({ user, otp }) {
                    state.events.push({ mode, otp, user: structuredClone(user) });
                  },
                },
              }),
              multiSession(),
              jwt(),
            ]
          : []),
      ],
      session: {
        additionalFields: {
          hidden: { type: "string", defaultValue: "cache-server-secret", returned: false },
          label: { type: "string", defaultValue: "cache-public-label" },
        },
        cookieCache: {
          enabled: mode !== "disabled",
          strategy: mode.startsWith("jwe")
            ? "jwe"
            : mode.startsWith("jwt") || mode === "managed"
              ? "jwt"
              : "compact",
          maxAge,
          version:
            mode.startsWith("version") ||
            mode.endsWith("interactions") ||
            mode === "exotic" ||
            mode === "managed"
              ? callback
              : mode === "date-version"
                ? "2026-10-01T00:00:00.000Z"
                : "1",
        },
      },
    };
    await (await getMigrations(options)).runMigrations();
    const path = options.basePath!;
    profiles.set(path, betterAuth(options));
  }
  return {
    profiles,
    async handle(request: Request) {
      if (new URL(request.url).pathname !== "/__test/session-cookie-cache/control") return null;
      const body = (await request.json()) as {
        mode: string;
        action: string;
        version?: string;
        failure?: boolean;
        userId?: string;
        token?: string;
        name?: string;
        email?: string;
        key?: Record<string, unknown>;
      };
      const state = states.get(body.mode);
      const auth = profiles.get(`/__test/profiles/session-cache-${body.mode}/api/auth`);
      if (!state || !auth) {
        return Response.json({ error: "Unknown cache profile" }, { status: 400 });
      }
      const context = await auth.$context;
      if (body.action === "rotate-cache-key") {
        await createJwk({ context } as any);
        return Response.json({ keys: await context.adapter.findMany({ model: "jwks" }) });
      }
      if (body.action === "cache-keys") {
        return Response.json({ keys: await context.adapter.findMany({ model: "jwks" }) });
      }
      if (body.action === "import-cache-key") {
        if (!body.key) return Response.json({ error: "Key missing" }, { status: 400 });
        const key = {
          ...body.key,
          createdAt: new Date(body.key.createdAt as string),
          expiresAt: body.key.expiresAt ? new Date(body.key.expiresAt as string) : null,
        };
        if (
          !(await context.adapter.findOne({
            model: "jwks",
            where: [{ field: "id", value: key.id as string }],
          }))
        ) {
          await context.adapter.create({ model: "jwks", data: key, forceAllowId: true });
        }
        return Response.json({ keys: await context.adapter.findMany({ model: "jwks" }) });
      }
      if (body.action === "retire-cache-key") {
        await context.adapter.delete({
          model: "jwks",
          where: [{ field: "id", value: body.token! }],
        });
        return Response.json({ keys: await context.adapter.findMany({ model: "jwks" }) });
      }
      if (body.action === "reset") {
        state.version = "1";
        state.failure = false;
        state.sequence = 0;
        state.sessionSequence = 0;
        state.events.length = 0;
      } else if (body.action === "clear-events") {
        state.events.length = 0;
      } else if (body.action === "policy") {
        if (body.version !== undefined) state.version = body.version;
        if (body.failure !== undefined) state.failure = body.failure;
      } else if (body.action === "rename") {
        if (!body.userId || typeof body.name !== "string") {
          return Response.json({ error: "Invalid rename" }, { status: 400 });
        }
        await context.internalAdapter.updateUser(body.userId, { name: body.name });
      } else if (body.action === "revoke") {
        if (!body.token) return Response.json({ error: "Invalid token" }, { status: 400 });
        await context.internalAdapter.deleteSession(body.token);
      } else if (body.action === "api-key-rows") {
        if (!body.userId) return Response.json({ error: "Invalid owner" }, { status: 400 });
        const keys = await context.adapter.findMany({
          model: "apikey",
          where: [{ field: "referenceId", value: body.userId }],
        });
        return Response.json({
          keys: keys.map((key) => {
            const stored = database
              .query("SELECT metadata FROM apikey WHERE id = ?")
              .get(key.id as string) as { metadata: string | null } | null;
            if (!stored) throw new Error("Actual API-key row missing");
            return { ...key, storedMetadata: stored.metadata };
          }),
        });
      } else if (body.action === "rows") {
        if (!body.userId) return Response.json({ error: "Invalid owner" }, { status: 400 });
        const where = [{ field: "userId", value: body.userId }];
        return Response.json({
          users: await context.adapter.findMany({
            model: "user",
            where: [{ field: "id", value: body.userId }],
          }),
          accounts: await context.adapter.findMany({ model: "account", where }),
          sessions: await context.adapter.findMany({
            model: "session",
            where,
            sortBy: { field: "createdAt", direction: "asc" },
          }),
          verifications: await context.adapter.findMany({
            model: "verification",
            sortBy: { field: "createdAt", direction: "asc" },
          }),
        });
      } else if (body.action === "lookup") {
        if (typeof body.email !== "string") {
          return Response.json({ error: "Invalid lookup" }, { status: 400 });
        }
        return Response.json({
          user: await context.adapter.findOne({
            model: "user",
            where: [{ field: "email", value: body.email }],
          }),
        });
      } else if (body.action !== "state") {
        return Response.json({ error: "Unknown action" }, { status: 400 });
      }
      return Response.json({ events: state.events });
    },
  };
}
