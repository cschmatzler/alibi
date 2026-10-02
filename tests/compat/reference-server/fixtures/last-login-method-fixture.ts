import type { Database } from "bun:sqlite";

import { type BetterAuthOptions, betterAuth } from "better-auth";
import { getMigrations } from "better-auth/db/migration";
import {
  anonymous,
  emailOTP,
  lastLoginMethod,
  magicLink,
  multiSession,
  username,
} from "better-auth/plugins";
import { siwe } from "better-auth/plugins/siwe";

import { verifyFixtureEip191 } from "./siwe-fixture";

function callbackValue(value: any): any {
  if (typeof value === "number" && (!Number.isFinite(value) || Object.is(value, -0))) {
    return { $number: Object.is(value, -0) ? "-0" : String(value) };
  }

  if (Array.isArray(value)) {
    return value.map(callbackValue);
  }

  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([key, item]) => [key, callbackValue(item)]),
    );
  }

  return value;
}

/** Configured application callbacks observing the actual pinned plugin boundaries. */
export async function createLastLoginMethodFixture(base: BetterAuthOptions, database: Database) {
  const events: unknown[] = [];
  const deliveries = new Map<string, unknown>();
  const profiles = new Map<string, ReturnType<typeof betterAuth>>();
  let sequence = 0;

  for (const mode of [
    "default",
    "database",
    "custom",
    "denied",
    "cookie-error",
    "resolver-error",
    "update-error",
    "transform",
    "policy",
    "composition",
    "nan",
    "negative",
    "excess",
  ] as const) {
    const name = `last-login-${mode}`;
    const observe = (kind: string, ctx: any, method?: string) => {
      const event = {
        kind,
        path: ctx.path ?? "",
        params: ctx.params ?? {},
        requestPath: ctx.request
          ? new URL(ctx.request.url).pathname.slice(`/__test/profiles/${name}/api/auth`.length)
          : null,
        method: ctx.method ?? null,
        body: callbackValue(ctx.body ?? null),
        query: ctx.query ?? {},
        probe: ctx.headers?.get("x-last-login-probe") ?? null,
        newSession: ctx.context.newSession ?? null,
        loginMethod: method ?? null,
      };
      events.push(event);
      return event;
    };
    const options: BetterAuthOptions = {
      ...base,
      ...(mode === "policy"
        ? {
            advanced: {
              ...base.advanced,
              defaultCookieAttributes: { sameSite: "strict" },
            },
          }
        : {}),
      ...(mode === "transform"
        ? {
            databaseHooks: {
              user: {
                update: {
                  before: async (user) => ({
                    data: {
                      ...user,
                      ...(typeof user.lastLoginMethod === "string"
                        ? { lastLoginMethod: `stored:${user.lastLoginMethod}` }
                        : {}),
                    },
                  }),
                },
              },
            },
          }
        : {}),
      ...(mode === "composition"
        ? {
            databaseHooks: {
              session: {
                create: {
                  before: async (session) => ({
                    data: {
                      ...session,
                      token: `LastLoginMethodSession${String(++sequence).padStart(11, "0")}`,
                    },
                  }),
                },
              },
            },
          }
        : {}),
      basePath: `/__test/profiles/${name}/api/auth`,
      plugins: [
        ...base.plugins!.filter((plugin) => ["passkey", "generic-oauth"].includes(plugin.id)),
        siwe({
          domain: "last-login.fixture",
          getNonce: async () => `LastLoginMethodNonce${String(++sequence).padStart(16, "0")}`,
          verifyMessage: async (input) =>
            verifyFixtureEip191(input.message, input.signature, input.address),
        }),
        ...(mode === "composition" ? [multiSession()] : []),
        username(),
        anonymous({
          generateRandomEmail: () => `last-login-anonymous-${++sequence}@fixture.test`,
          generateName: () => "Anonymous Owner",
        }),
        magicLink({
          sendMagicLink: async ({ email, url, token, metadata }) => {
            deliveries.set(`magic:${email}`, {
              email,
              url,
              token,
              metadata: metadata ?? null,
            });
          },
        }),
        emailOTP({
          sendVerificationOTP: async ({ email, otp, type }) => {
            deliveries.set(`${type}:${email}`, { email, otp, type });
          },
        }),
        lastLoginMethod({
          storeInDatabase: mode !== "default",
          ...(mode === "custom"
            ? { cookieName: "fixture.last_login_method", maxAge: 123.9 }
            : mode === "policy"
              ? { cookieName: "policy.last_login_method", maxAge: 0 }
              : mode === "nan"
                ? { maxAge: Number.NaN }
                : mode === "negative"
                  ? { maxAge: Number.NEGATIVE_INFINITY }
                  : mode === "excess"
                    ? { maxAge: Number.POSITIVE_INFINITY }
                    : {}),
          customResolveMethod(ctx) {
            observe("resolve", ctx);

            if (
              mode === "resolver-error" &&
              ctx.headers?.get("x-last-login-resolver-error") === "true"
            ) {
              throw new Error("application resolver failed");
            }

            if (mode === "custom" && ctx.headers?.get("x-last-login-body") === "true") {
              return `body:${String(ctx.body.extra.overflow)}:${Object.is(ctx.body.extra.zero, -0) ? "-0" : "other"}`;
            }

            if (mode === "custom" || mode === "update-error") {
              return ctx.headers?.get("x-last-login-method") ?? null;
            }

            return null;
          },
          beforeStoreCookie: async (ctx, method) => {
            await Promise.resolve();
            const event = observe("cookie", ctx, method);

            if (ctx.headers?.get("x-last-login-body") === "true" && ctx.request) {
              Object.assign(event, {
                requestBody: await ctx.request.clone().text(),
              });
            }

            if (mode === "cookie-error") {
              throw new Error("application consent failed");
            }

            return mode !== "denied";
          },
        }),
      ],
    };

    if (mode === "database") {
      await (await getMigrations(options)).runMigrations();
    }

    profiles.set(name, betterAuth(options));
  }

  return {
    profiles,
    async handle(request: Request) {
      const url = new URL(request.url);

      if (url.pathname !== "/__test/last-login-method") {
        return null;
      }

      if (request.method === "GET") {
        return Response.json({
          events: [...events],
          users: database
            .query("SELECT id,email,name,lastLoginMethod FROM user ORDER BY email,id")
            .all(),
        });
      }

      const body = (await request.json()) as Record<string, unknown>;

      if (body.action === "clear") {
        events.length = 0;
      }

      if (body.action === "reset") {
        events.length = 0;
        sequence = 0;
        deliveries.clear();
      }

      if (body.action === "delivery") {
        return Response.json(deliveries.get(String(body.key)) ?? null);
      }

      if (body.action === "update-error") {
        database.exec(
          "CREATE TRIGGER last_login_update_error BEFORE UPDATE OF lastLoginMethod ON user BEGIN SELECT RAISE(ABORT,'application update rejected'); END",
        );
      }

      if (body.action === "restore-updates") {
        database.exec("DROP TRIGGER IF EXISTS last_login_update_error");
      }

      return Response.json({ changed: true });
    },
  };
}
