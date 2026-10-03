import { expect } from "bun:test";

import { decodeJwt, decodeProtectedHeader, importJWK, jwtVerify } from "jose";

import keys from "../../../../fixtures/client-assertion-keys.json";
import { authProfilePath, type FixtureProfile } from "../../../support/profiles";
import { compatScenario, type ScenarioContext } from "../../../support/scenario";
async function state(ctx: ScenarioContext) {
  return (await ctx.rawRequest({ path: "/__test/social-provider/state" })).body as {
    users: any[];
    accounts: any[];
    sessions: any[];
  };
}
async function receipts(ctx: ScenarioContext): Promise<any[]> {
  return (await fetch(ctx.baseURL + "/__test/generic-token/receipts")).json();
}
async function save(ctx: ScenarioContext, name: string, value: unknown) {
  if (process.env.CLOSE188_EVIDENCE_DIR)
    await Bun.write(
      `${process.env.CLOSE188_EVIDENCE_DIR}/${Bun.hash(ctx.baseURL + name)}.json`,
      JSON.stringify({ name, baseURL: ctx.baseURL, value, receipts: await receipts(ctx) }, null, 2),
    );
}
const modes = [
  ...Object.keys(keys),
  "pem",
  "pem-ES256",
  "pem-ES384",
  "pem-ES512",
  "pem-EdDSA",
  "both",
  "empty-kid",
  "fractional",
  "embedded",
  "expired",
  "bad-key",
  "padded",
  "missing-crt",
  "duplicate-ops",
  "invalid-ext",
  "secret",
  "manual",
  "getter-error",
];
for (const mode of modes) {
  const name = `generic client assertion ${mode} authenticates code and refresh at bound endpoint`;
  compatScenario(
    name,
    async (ctx) => {
      const fixture = `generic-token-jwt-${mode}` as FixtureProfile;
      const actor = ctx.actor("owner", fixture);
      const deny = [
        "bad-key",
        "missing-crt",
        "duplicate-ops",
        "invalid-ext",
        "secret",
        "manual",
        "getter-error",
      ].includes(mode);
      await ctx.rawRequest({
        path: "/__test/generic-token/control",
        method: "POST",
        json: {
          profile: {
            id: ctx.uniqueToken("subject"),
            email: ctx.uniqueEmail("owner"),
            name: "Owner",
            email_verified: true,
          },
        },
      });
      const before = await state(ctx);
      const start = await actor.client.signIn.social({
        provider: "generic",
        callbackURL: "/dashboard",
      });
      expect(start.error).toBeNull();
      const url = new URL(start.data!.url!);
      const callback = await actor.fetch(
        ctx.baseURL +
          authProfilePath(fixture) +
          `/callback/generic?code=fixture-code&state=${encodeURIComponent(url.searchParams.get("state")!)}`,
        { redirect: "manual" },
      );
      expect(callback.status).toBe(302);
      if (deny) {
        expect(
          new URL(callback.headers.get("location")!, ctx.baseURL).searchParams.get("error"),
        ).toBe("invalid_code");
        expect(await state(ctx)).toEqual(before);
        expect(await receipts(ctx)).toEqual([]);
        // Explicit refresh reaches the same auth failure before any account mutation.
        expect(
          (
            await actor.client.signUp.email({
              email: ctx.uniqueEmail("refresh"),
              password: "Password123!",
              name: "Refresh",
            })
          ).error,
        ).toBeNull();
        const signed = await actor.client.getSession();
        const id = await ctx.seedOAuthAccount({
          email: signed.data!.user.email,
          providerId: "generic",
          accountId: ctx.uniqueToken("refresh-subject"),
          accessToken: "old",
          refreshToken: "refresh",
        });
        const seeded = await state(ctx);
        const refresh = await actor.client.refreshToken({ accountId: id });
        expect(refresh.error?.code).toBe("FAILED_TO_REFRESH_ACCESS_TOKEN");
        expect(await state(ctx)).toEqual(seeded);
        expect(await receipts(ctx)).toEqual([]);
        await save(ctx, name, { before, seeded, refresh });
        return {
          callback: { status: callback.status, location: callback.headers.get("location") },
          refresh: ctx.snapshot(refresh),
        };
      }
      expect(callback.headers.get("location")).toBe("/dashboard");
      const created = await state(ctx);
      const account = created.accounts.find((a) => a.providerId === "generic")!;
      expect(created.users).toHaveLength(1);
      expect(created.sessions).toHaveLength(1);
      expect(account.accessToken).toBe("generic-access");
      const refresh = await actor.client.refreshToken({ accountId: account.id });
      expect(refresh.error).toBeNull();
      const after = await state(ctx);
      expect(after.users).toEqual(created.users);
      expect(after.sessions).toEqual(created.sessions);
      expect(after.accounts).toHaveLength(created.accounts.length);
      const seen = await receipts(ctx);
      expect(seen).toHaveLength(2);
      let last = "";
      for (const [i, row] of seen.entries()) {
        const form = Object.fromEntries(row.body);
        expect(row.body).toHaveLength(Object.keys(form).length);
        expect(row.authorization).toBeNull();
        expect(form.client_secret).toBeUndefined();
        expect(form.client_id).toBe("client :+&");
        expect(form.client_assertion_type).toBe(
          "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        );
        expect(form.grant_type).toBe(i ? "refresh_token" : "authorization_code");
        const jwt = form.client_assertion;
        const h = decodeProtectedHeader(jwt);
        const claims = decodeJwt(jwt);
        const algorithm = mode.startsWith("pem-") ? mode.slice(4) : mode in keys ? mode : "RS256";
        expect(h).toEqual({
          alg: algorithm,
          typ: "JWT",
          ...(mode === "empty-kid"
            ? {}
            : { kid: mode === "embedded" ? "embedded-kid" : "configured-kid" }),
        });
        expect(claims.iss).toBe("client :+&");
        expect(claims.sub).toBe(claims.iss);
        expect(String(claims.aud)).toMatch(/^http:\/\/.*\/token$/);
        expect(claims.exp! - claims.iat!).toBe(
          mode === "expired" ? -1 : mode === "fractional" ? 17.5 : 120,
        );
        expect(Math.abs(Date.now() / 1000 - claims.iat!)).toBeLessThan(10);
        expect(claims.jti).toMatch(/^[0-9a-f-]{36}$/);
        expect(claims.jti).not.toBe(last);
        last = claims.jti!;
        // Verify every actual outbound signature independently, including intentionally
        // expired assertions: the fixture IdP accepts them, so use signing-time clock.
        const verified = await jwtVerify(
          jwt,
          await importJWK(keys[algorithm as keyof typeof keys].public, algorithm),
          {
            algorithms: [algorithm],
            issuer: "client :+&",
            audience: claims.aud as string,
            currentDate: new Date((claims.iat! + (mode === "expired" ? -2 : 0)) * 1000),
          },
        );
        expect(verified.payload).toEqual(claims);
      }
      await save(ctx, name, { before, created, after, refresh });
      return {
        callback: { status: callback.status, location: callback.headers.get("location") },
        refresh: ctx.snapshot(refresh),
        after,
      };
    },
    ["POST /sign-in/social", "GET /callback/{}", "POST /refresh-token"],
  );
}
compatScenario(
  "generic client assertion invalid options reject eagerly before a grant exists",
  async (ctx) => {
    const results = [];
    for (const mode of ["missing-key", "unsupported-alg", "jwk-alg", "conflicting-alg", "valid"]) {
      const r = await ctx.rawRequest({
        path: "/__test/generic-token/assertion-options",
        method: "POST",
        json: { mode },
      });
      expect(r.status).toBe(200);
      expect(r.body).toEqual({ accepted: mode === "valid" });
      results.push({ mode, ...r });
    }
    expect(await receipts(ctx)).toEqual([]);
    await save(ctx, "invalid-options", results);
    return results;
  },
  [],
);
