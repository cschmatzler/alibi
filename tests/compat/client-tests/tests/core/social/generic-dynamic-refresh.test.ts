import { expect } from "bun:test";

import { authProfilePath } from "../../../support/profiles";
import { compatScenario, type ScenarioContext } from "../../../support/scenario";

type Rows = {
  users: Record<string, unknown>[];
  accounts: Record<string, unknown>[];
  sessions: Record<string, unknown>[];
};
type Receipt = {
  kind?: string;
  tenant?: string;
  cookie?: string;
  method?: string;
  path: string;
  refreshToken?: string;
  raw?: string;
  body?: [string, string][];
  authorization?: string | null;
  contentType?: string;
};
async function rows(ctx: ScenarioContext): Promise<Rows> {
  return (await ctx.rawRequest({ path: "/__test/social-provider/state" })).body as Rows;
}
async function receipts(ctx: ScenarioContext): Promise<Receipt[]> {
  return (await ctx.rawRequest({ path: "/__test/generic-token/receipts" })).body as Receipt[];
}
const cases = [
  { mode: "dynamic", endpoint: "/refresh-token" },
  { mode: "dynamic", endpoint: "/get-access-token" },
  { mode: "dynamic", endpoint: "/account-info" },
  { mode: "dynamic-none", endpoint: "/refresh-token" },
  { mode: "dynamic-error", endpoint: "/refresh-token" },
  { mode: "dynamic-custom", endpoint: "/refresh-token" },
] as const;
for (const item of cases) {
  const name = `generic dynamic refresh ${item.mode} ${item.endpoint} preserves request context and account ownership`;
  compatScenario(
    name,
    async (ctx) => {
      const fixture = `generic-token-${item.mode}` as const;
      const basePath = authProfilePath(fixture);
      const owner = ctx.actor("owner", fixture);
      const foreign = ctx.actor("foreign", fixture);
      const email = ctx.uniqueEmail("owner");
      const signup = await owner.fetch(ctx.baseURL + basePath + "/sign-up/email", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ email, password: "Password123!", name: "Owner" }),
      });
      expect(signup.status).toBe(200);
      const cookie = signup.headers
        .getSetCookie()
        .map((c) => c.split(";")[0])
        .join("; ");
      expect(cookie).toContain("session_token=");
      expect(
        (
          await foreign.client.signUp.email({
            email: ctx.uniqueEmail("foreign"),
            password: "Password123!",
            name: "Foreign",
          })
        ).error,
      ).toBeNull();
      const id = await ctx.seedOAuthAccount({
        email,
        providerId: "generic",
        accountId: ctx.uniqueToken("subject"),
        accessToken: "old-access",
        refreshToken: "old-refresh",
        idToken: "retained-id",
        scope: "original scope",
        accessTokenExpiresAt: "2020-01-01T00:00:00.000Z",
        refreshTokenExpiresAt: "2099-01-01T00:00:00.000Z",
      });
      const before = await rows(ctx);
      const account = before.accounts.find((a) => a.id === id)!;
      const denied = await foreign.client.refreshToken({ accountId: id });
      expect(denied.error).toBeTruthy();
      expect(await receipts(ctx)).toEqual([]);
      expect(await rows(ctx)).toEqual(before);
      const rounds: unknown[] = [];
      for (const [index, tenant] of ["allowed-one", "allowed-two"].entries()) {
        const endpoint = index === 0 ? item.endpoint : "/refresh-token";
        const token = `rotated-access-${index}`;
        const refresh = `rotated-refresh-${index}`;
        expect(
          (
            await ctx.rawRequest({
              path: "/__test/generic-token/control",
              method: "POST",
              json: {
                profile: {
                  id: "generic-subject",
                  email: "generic@example.invalid",
                  name: "Generic Name",
                  email_verified: true,
                  picture: "https://images.example.invalid/generic.png",
                },
                tokenResponse: {
                  access_token: token,
                  refresh_token: refresh,
                  token_type: "Bearer",
                  expires_in: 3600,
                  scope: "response scope",
                },
              },
            })
          ).status,
        ).toBe(200);
        const method = endpoint === "/account-info" ? "GET" : "POST";
        const requestPath =
          basePath + endpoint + (method === "GET" ? `?accountId=${encodeURIComponent(id)}` : "");
        const response = await owner.fetch(ctx.baseURL + requestPath, {
          method,
          headers: {
            "content-type": "application/json",
            "x-refresh-tenant": tenant,
            cookie: `${cookie}; refresh_meta=meta-${index}`,
          },
          ...(method === "POST" ? { body: JSON.stringify({ accountId: id }) } : {}),
        });
        const body: unknown = await response.json();
        const after = await rows(ctx);
        const seen = await receipts(ctx);
        const current = seen.slice(
          index * (item.mode === "dynamic-error" || item.mode === "dynamic-custom" ? 1 : 2),
        );
        if (process.env.DYNAMIC_REFRESH_EVIDENCE_DIR) {
          await Bun.write(
            `${process.env.DYNAMIC_REFRESH_EVIDENCE_DIR}/${Bun.hash(ctx.baseURL + name)}-round-${index}.json`,
            JSON.stringify(
              {
                name,
                baseURL: ctx.baseURL,
                before,
                denied,
                request: { method, path: requestPath, tenant, metadataCookie: `meta-${index}` },
                status: response.status,
                body,
                after,
                rawReceipts: seen,
              },
              null,
              2,
            ),
          );
        }
        expect(current[0]).toEqual({
          kind: item.mode === "dynamic-custom" ? "custom" : "params",
          tenant,
          cookie: `meta-${index}`,
          method,
          path: basePath + endpoint,
          ...(item.mode === "dynamic-custom"
            ? { refreshToken: index === 0 ? "old-refresh" : "custom-refresh" }
            : {}),
        });
        if (item.mode === "dynamic-error") {
          expect(response.status).toBe(400);
          expect(after).toEqual(before);
          expect(current).toHaveLength(1);
        } else {
          expect(response.status).toBe(200);
          expect(after.users).toEqual(before.users);
          expect(after.sessions).toEqual(before.sessions);
          expect(after.accounts).toHaveLength(before.accounts.length);
          for (const row of before.accounts.filter((a) => a.id !== id)) {
            expect(after.accounts.find((a) => a.id === row.id)).toEqual(row);
          }
          const changed = after.accounts.find((a) => a.id === id)!;
          expect(changed).toMatchObject({
            ...account,
            accessToken: item.mode === "dynamic-custom" ? "custom-access" : token,
            refreshToken: item.mode === "dynamic-custom" ? "custom-refresh" : refresh,
            accessTokenExpiresAt: expect.any(String),
            updatedAt: expect.any(String),
          });
          if (item.mode === "dynamic-custom") {
            expect(current).toHaveLength(1);
          } else {
            expect(current).toHaveLength(2);
            const grant = current[1]!;
            expect(grant.contentType).toBe("application/x-www-form-urlencoded");
            expect(grant.authorization).toBeNull();
            const fields = Object.fromEntries(grant.body!);
            expect(grant.body).toHaveLength(Object.keys(fields).length);
            expect(fields).toEqual({
              grant_type: "refresh_token",
              refresh_token: index === 0 ? "old-refresh" : "rotated-refresh-0",
              client_id: "client :+&",
              client_secret: "secret :+&",
              ...(item.mode === "dynamic-none"
                ? {}
                : { resource: `tenant ${tenant} :+&=/%é`, scope: `profile ${tenant}` }),
            });
            if (item.mode === "dynamic") {
              expect(grant.raw).toContain(`resource=tenant+${tenant}+%3A%2B%26%3D%2F%25%C3%A9`);
            }
          }
        }
        rounds.push({
          status: response.status,
          body,
          after,
          receipts: current.map(({ raw: _, body: form, ...r }) => ({
            ...r,
            ...(form ? { body: Object.fromEntries(form) } : {}),
          })),
        });
      }
      const result = { before, denied: ctx.snapshot(denied), rounds };
      if (process.env.DYNAMIC_REFRESH_EVIDENCE_DIR) {
        await Bun.write(
          `${process.env.DYNAMIC_REFRESH_EVIDENCE_DIR}/${Bun.hash(ctx.baseURL + name)}.json`,
          JSON.stringify(
            { name, baseURL: ctx.baseURL, result, rawReceipts: await receipts(ctx) },
            null,
            2,
          ),
        );
      }
      return result;
    },
    ["POST /refresh-token", "POST /get-access-token", "GET /account-info"],
  );
}
