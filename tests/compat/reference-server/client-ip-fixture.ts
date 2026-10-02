/** Real pinned IP policies; observations read persisted physical session rows. */
import { Database } from "bun:sqlite";
import { apiKey } from "@better-auth/api-key";
import { passkey } from "@better-auth/passkey";
import { type BetterAuthOptions, betterAuth } from "better-auth";
import { createAuthEndpoint } from "better-auth/api";
import { getMigrations } from "better-auth/db/migration";
import { admin, deviceAuthorization } from "better-auth/plugins";

export async function createClientIpFixture(base: BetterAuthOptions, database: Database) {
  const policies = {
    default: {},
    ordered: { ipAddressHeaders: ["X-Client-IP", "x-forwarded-for"] },
    trusted: { trustedProxies: ["10.0.0.0/8", "192.0.2.9"] },
    v6proxy: { trustedProxies: ["2001:db8:ffff::/48"] },
    mixed: { trustedProxies: ["bad-address", "10.0.0.0/8", "::ffff:192.0.2.9/32"] },
    invalid: {
      trustedProxies: ["10.0.0.1/33", "10.0.0.1/-1", "10.0.0.1/8x", "::ffff:192.0.2.9/128"],
    },
    full: { ipv6Subnet: 128 },
    excess: { ipv6Subnet: 129 },
    zero: { ipv6Subnet: 0 },
    negative: { ipv6Subnet: -1 },
    fractional: { ipv6Subnet: 65.9 },
    nan: { ipv6Subnet: NaN },
    disabled: { disableIpTracking: true },
    empty: { ipAddressHeaders: [] },
  };
  const profiles = new Map(
    Object.entries(policies).map(([name, policy]) => {
      const profile = `client-ip-${name}`;
      const auth = betterAuth({
        ...base,
        basePath: `/__test/profiles/${profile}/api/auth`,
        advanced: { ...base.advanced, ipAddress: policy },
        emailVerification: { ...base.emailVerification, autoSignInAfterVerification: true },
        plugins: [
          deviceAuthorization(),
          passkey(),
          admin(),
          apiKey({ enableSessionForAPIKeys: true }),
          {
            id: "client-ip-application",
            endpoints: {
              rateCheck: createAuthEndpoint(
                "/client-ip-rate-check",
                { method: "GET" },
                async (ctx) => ctx.json({ ok: true }),
              ),
              rateEmpty: createAuthEndpoint(
                "/client-ip-rate-empty",
                { method: "GET" },
                async (ctx) => ctx.json({ ok: true }),
              ),
              rateDuplicate: createAuthEndpoint(
                "/client-ip-rate-duplicate",
                { method: "GET" },
                async (ctx) => ctx.json({ ok: true }),
              ),
            },
          },
        ],
        rateLimit: {
          enabled: true,
          storage: "memory",
          window: 60,
          max: 10000,
          customRules: {
            "/client-ip-rate-check": { window: 60, max: 2 },
            "/client-ip-rate-empty": { window: 60, max: 2 },
            "/client-ip-rate-duplicate": { window: 60, max: 2 },
            "/sign-up/email": { window: 60, max: 10000 },
            "/sign-in/email": { window: 60, max: 10000 },
          },
        },
      });
      return [profile, auth] as const;
    }),
  );
  await (await getMigrations(profiles.get("client-ip-default")!.options)).runMigrations();
  return {
    profiles,
    async handle(request: Request) {
      const url = new URL(request.url);
      if (url.pathname === "/__test/client-ip/sessions") {
        const rows = database
          .query(
            "SELECT id,token,userId,expiresAt,createdAt,updatedAt,ipAddress,userAgent FROM session ORDER BY createdAt,id",
          )
          .all() as Array<Record<string, unknown>>;
        return Response.json(
          rows.map((row) => ({
            ...row,
            expiresAt: new Date(row.expiresAt as string).toISOString(),
            createdAt: new Date(row.createdAt as string).toISOString(),
            updatedAt: new Date(row.updatedAt as string).toISOString(),
          })),
        );
      }
      for (const [name, auth] of profiles) {
        const path = `/__test/profiles/${name}/api/auth`;
        if (url.pathname === path || url.pathname.startsWith(path + "/"))
          return auth.handler(request);
      }
      return null;
    },
  };
}
