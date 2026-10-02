/** Installed Source policies exercised through actual authentication mutations. */
import { betterAuth, type BetterAuthOptions } from "better-auth";

export function createRateLimitFixture(base: BetterAuthOptions) {
  const profiles = new Map(["ordered", "default"].map(name => {
    const profile = `rate-limit-${name}`;
    return [profile, betterAuth({
      ...base,
      plugins: (base.plugins ?? []).filter(plugin => plugin.id === "email-otp"),
      basePath: `/__test/profiles/${profile}/api/auth`,
      rateLimit: { enabled: true, storage: "memory", window: 60, max: name === "ordered" ? 1 : 10000,
        ...(name === "ordered" ? {customRules: {
          "/sign-up/*": {window: 60, max: 2},
          "/sign-up/email": {window: 60, max: 4},
          "/get-session": async (request, inherited) => request.headers.get("x-rate-bypass") === "yes" ? false : {...inherited, max:1, window:request.headers.get("x-rate-zero") === "yes" ? 0 : inherited.window},
          "/list-sessions": false,
        }} : {}),
      },
    })] as const;
  }));
  return {
    async handle(request: Request) {
      const url = new URL(request.url);
      for (const [profile, auth] of profiles) {
        if (url.pathname.startsWith(`/__test/profiles/${profile}/api/auth/`)) return auth.handler(request);
      }
      return null;
    },
  };
}
