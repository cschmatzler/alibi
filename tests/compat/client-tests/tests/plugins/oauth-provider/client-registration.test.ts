import { expect } from "bun:test";
import { createHash } from "node:crypto";

import { Cookie } from "tough-cookie";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "Dynamic OAuth registration gates admission and persists owned and anonymous clients",
  async (ctx) => {
    const actor = ctx.actor();
    const control = (input: unknown) =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/oauth-provider-clients`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(input),
      });
    const signup = await control({
      action: "signup",
      body: {
        email: ctx.uniqueEmail("oauth-registration-owner"),
        name: "Owner",
        password: "password123",
      },
    });
    expect(signup.status).toBe(200);
    const owner = (await signup.json()) as any;
    const cookie = signup.headers
      .getSetCookie()
      .filter((raw) => Boolean(Cookie.parse(raw)?.value))
      .map((raw) => raw.split(";")[0])
      .join("; ");
    const rejected = [];
    for (const [mode, body, headers, status] of [
      ["default", { redirect_uris: ["https://app.fixture.test/callback"] }, {}, 403],
      ["dynamic", { redirect_uris: ["https://app.fixture.test/callback"] }, {}, 401],
      ["public", { grant_types: ["client_credentials"] }, {}, 400],
      [
        "public",
        { redirect_uris: ["https://app.fixture.test/callback"], scope: "forbidden" },
        {},
        400,
      ],
      [
        "public",
        { redirect_uris: ["https://app.fixture.test/callback"], skip_consent: true },
        {},
        400,
      ],
      [
        "public",
        { redirect_uris: ["https://app.fixture.test/callback"], subject_type: "pairwise" },
        {},
        400,
      ],
      ["public", { redirect_uris: ["https://app.fixture.test/callback"], resources: 42 }, {}, 400],
      ["dynamic", { client_name: 42 }, { cookie }, 400],
    ] as const) {
      const r = await control({ action: "register", mode, body, headers });
      expect(r.status).toBe(status);
      rejected.push({ status, body: await r.json() });
    }
    const clients = [];
    const rows = [];
    for (const [mode, publicClient, headers] of [
      ["dynamic", false, { cookie }],
      ["public", true, {}],
    ] as const) {
      const start = Math.floor(Date.now() / 1000);
      const r = await control({
        action: "register",
        mode,
        headers,
        body: {
          client_name: publicClient ? "Anonymous client" : "Owned dynamic client",
          redirect_uris: ["https://app.fixture.test/callback"],
          scope: "email",
          token_endpoint_auth_method: publicClient ? "none" : "client_secret_basic",
          user_id: "forged",
          client_id: "forged",
        },
      });
      expect(r.status).toBe(201);
      expect(r.headers.get("cache-control")).toBe("no-store");
      const value = (await r.json()) as any;
      expect(value.scope).toBe("openid profile email offline_access");
      expect(value.client_id_issued_at).toBeGreaterThanOrEqual(start);
      expect(value.client_id_issued_at).toBeLessThanOrEqual(Math.floor(Date.now() / 1000));
      expect(value.client_id).toMatch(/^[a-zA-Z]{32}$/);
      const row = (await (
        await control({ action: "row", clientId: value.client_id })
      ).json()) as any;
      if (publicClient) {
        expect(value).not.toHaveProperty("user_id");
        expect(value).not.toHaveProperty("client_secret");
        expect(row.userId).toBeNull();
        expect(row.client_secret).toBeNull();
      } else {
        expect(value.user_id).toBe(owner.user.id);
        expect(row.userId).toBe(owner.user.id);
        expect(value.client_secret).toMatch(/^[a-zA-Z]{32}$/);
        expect(row.client_secret).toBe(
          createHash("sha256").update(value.client_secret).digest("base64url"),
        );
      }
      clients.push(value);
      rows.push(row);
    }
    return { rejected, clients: ctx.snapshot(clients), rows: ctx.snapshot(rows) };
  },
);
