/** Installed Source policies exercised through actual authentication mutations. */
import { type BetterAuthOptions, betterAuth } from "better-auth";

export function createRateLimitFixture(base: BetterAuthOptions) {
  const shared = new Map<string, { value: string; expiresAt: number }>();
  const secondary = {
    async get(key: string) {
      const row = shared.get(key);
      return row && row.expiresAt > Date.now() ? row.value : null;
    },
    async set(key: string, value: string, ttl: number) {
      shared.set(key, { value, expiresAt: Date.now() + ttl * 1000 });
    },
    async delete(key: string) {
      shared.delete(key);
    },
    async increment(key: string, ttl: number) {
      const row = shared.get(key);
      const count = row && row.expiresAt > Date.now() ? Number(row.value) + 1 : 1;
      shared.set(key, {
        value: String(count),
        expiresAt: count === 1 ? Date.now() + ttl * 1000 : row!.expiresAt,
      });
      return count;
    },
  };
  const failureEvents: string[] = [];
  let failureMode = "normal";
  const failureStorage: NonNullable<BetterAuthOptions["secondaryStorage"]> = {
    async get(key) {
      failureEvents.push("get");
      return secondary.get(key);
    },
    async set(key, value, ttl) {
      failureEvents.push("set");
      return secondary.set(key, value, ttl ?? 60);
    },
    async delete(key) {
      failureEvents.push("delete");
      return secondary.delete(key);
    },
  };
  const failingIncrement = async (key: string, ttl?: number) => {
    failureEvents.push("increment");
    if (failureMode === "throws") throw new Error("Application counter unavailable");
    return secondary.increment(key, ttl ?? 60);
  };
  failureStorage.increment = failingIncrement;
  const profiles = new Map(
    ["ordered", "default", "secondary-a", "secondary-b", "secondary-failure"].map((name) => {
      const profile = `rate-limit-${name}`;
      return [
        profile,
        betterAuth({
          ...base,
          plugins: (base.plugins ?? []).filter((plugin) => plugin.id === "email-otp"),
          basePath: `/__test/profiles/${profile}/api/auth`,
          ...(name.startsWith("secondary-")
            ? { secondaryStorage: name === "secondary-failure" ? failureStorage : secondary }
            : {}),
          rateLimit: {
            enabled: true,
            storage: name.startsWith("secondary-") ? "secondary-storage" : "memory",
            window: 60,
            max: name === "ordered" ? 1 : 10000,
            ...(name.startsWith("secondary-")
              ? { customRules: { "/get-session": { window: 1, max: 2 }, "/list-sessions": false } }
              : {}),
            ...(name === "secondary-failure"
              ? {
                  customRules: {
                    "/sign-up/email": (request: Request) =>
                      request.headers.get("x-rate-bypass") === "yes"
                        ? false
                        : { window: 60, max: 2 },
                  },
                }
              : {}),
            ...(name === "ordered"
              ? {
                  customRules: {
                    "/sign-up/*": { window: 60, max: 2 },
                    "/sign-up/email": { window: 60, max: 4 },
                    "/get-session": async (request, inherited) =>
                      request.headers.get("x-rate-bypass") === "yes"
                        ? false
                        : {
                            ...inherited,
                            max: 1,
                            window:
                              request.headers.get("x-rate-zero") === "yes" ? 0 : inherited.window,
                          },
                    "/list-sessions": false,
                  },
                }
              : {}),
          },
        }),
      ] as const;
    }),
  );
  return {
    async handle(request: Request) {
      const url = new URL(request.url);
      if (url.pathname === "/__test/rate-limit-secondary/failure") {
        if (request.method === "POST") {
          failureMode = (await request.json()).mode;
          if (failureMode === "missing") delete failureStorage.increment;
          else failureStorage.increment = failingIncrement;
          failureEvents.length = 0;
        }
        return Response.json({ events: failureEvents.splice(0) });
      }
      if (url.pathname === "/__test/rate-limit-secondary/control")
        return Response.json({ value: await secondary.get(url.searchParams.get("key")!) });
      for (const [profile, auth] of profiles) {
        if (url.pathname.startsWith(`/__test/profiles/${profile}/api/auth/`)) {
          return auth.handler(request);
        }
      }
      return null;
    },
  };
}
