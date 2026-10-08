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
  const customRows = new Map<string, { count: number; lastRequest: number }>();
  let customFailure = false;
  const customStorage = {
    async consume(key: string, rule: { window: number; max: number }) {
      if (customFailure) throw new Error("Application quota storage failed");
      const now = Date.now();
      const row = customRows.get(key);
      if (row && now - row.lastRequest < rule.window * 1000 && row.count >= rule.max)
        return {
          allowed: false,
          retryAfter: Math.ceil((row.lastRequest + rule.window * 1000 - now) / 1000),
        };
      customRows.set(key, {
        count: row && now - row.lastRequest < rule.window * 1000 ? row.count + 1 : 1,
        lastRequest: now,
      });
      return { allowed: true, retryAfter: null };
    },
  };
  const profiles = new Map(
    ["ordered", "default", "secondary-a", "secondary-b", "custom", "custom-memory"].map((name) => {
      const profile = `rate-limit-${name}`;
      return [
        profile,
        betterAuth({
          ...base,
          plugins: (base.plugins ?? []).filter((plugin) => plugin.id === "email-otp"),
          basePath: `/__test/profiles/${profile}/api/auth`,
          ...(name.startsWith("secondary-") ? { secondaryStorage: secondary } : {}),
          rateLimit: {
            enabled: true,
            storage:
              name.startsWith("secondary-") || name === "custom" ? "secondary-storage" : "memory",
            ...(name === "custom" ? { customStorage } : {}),
            window: 60,
            max: name === "ordered" ? 1 : 10000,
            ...(name.startsWith("secondary-") || name.startsWith("custom")
              ? { customRules: { "/get-session": { window: 1, max: 2 }, "/list-sessions": false } }
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
      if (url.pathname === "/__test/rate-limit-custom/control") {
        if (request.method === "POST") customFailure = (await request.json()).failure;
        return Response.json({
          failure: customFailure,
          rows: [...customRows].map(([key, row]) => ({
            key,
            ...row,
            lastRequest: new Date(row.lastRequest).toISOString(),
          })),
        });
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
