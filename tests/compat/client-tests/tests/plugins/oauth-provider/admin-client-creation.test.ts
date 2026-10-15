import { createHash } from "node:crypto";

import { Cookie } from "tough-cookie";
import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "Administrative OAuth creation persists operator fields without metadata forgery",
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
        email: ctx.uniqueEmail("oauth-admin-client-owner"),
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
    for (const [body, headers, status] of [
      [{ client_name: 42 }, { cookie }, 400],
      [{ redirect_uris: ["https://app.fixture.test/callback"] }, {}, 401],
      [
        {
          redirect_uris: ["https://app.fixture.test/callback"],
          client_credentials_scopes: ["email"],
        },
        { cookie },
        400,
      ],
      [
        { grant_types: ["client_credentials"], client_credentials_scopes: ["email"] },
        { cookie },
        400,
      ],
      [
        { redirect_uris: ["https://app.fixture.test/callback"], skip_consent: "yes" },
        { cookie },
        400,
      ],
    ] as const) {
      const r = await control({ action: "admin-create", body, headers });
      expect(r.status).toBe(status);
      if (status === 401) {
        expect(r.headers.get("cache-control")).toBe("no-store");
        expect(r.headers.get("pragma")).toBe("no-cache");
      }
      const text = await r.text();
      rejected.push({ status, body: text ? JSON.parse(text) : null });
    }
    const input = {
      client_name: "Operator client",
      redirect_uris: ["https://app.fixture.test/callback"],
      skip_consent: true,
      enable_end_session: true,
      require_pkce: false,
      subject_type: "public",
      client_secret_expires_at: 123,
      client_credentials_scopes: [],
      user_id: "forged",
      metadata: {
        custom_label: "billing",
        client_id: "forged",
        client_secret: "forged",
        client_name: "forged",
        userId: "forged",
        resources: ["forged"],
        client_credentials_scopes: ["forged"],
      },
    };
    const r = await control({ action: "admin-create", body: input, headers: { cookie } });
    expect(r.status).toBe(201);
    expect(r.headers.get("cache-control")).toBe("no-store");
    const value = (await r.json()) as any;
    expect(value.user_id).toBe(owner.user.id);
    expect(value.client_name).toBe("Operator client");
    expect(value.custom_label).toBe("billing");
    expect(value.skip_consent).toBe(true);
    expect(value.enable_end_session).toBe(true);
    expect(value.require_pkce).toBe(false);
    expect(value.subject_type).toBe("public");
    expect(value.client_credentials_scopes).toEqual([]);
    expect(value.client_secret_expires_at).toBe(0);
    expect(value).not.toHaveProperty("userId");
    expect(value).not.toHaveProperty("resources");
    expect(value.client_id).toMatch(/^[a-zA-Z]{32}$/);
    expect(value.client_secret).toMatch(/^[a-zA-Z]{32}$/);
    const row = (await (await control({ action: "row", clientId: value.client_id })).json()) as any;
    expect(row.client_secret).toBe(
      createHash("sha256").update(value.client_secret).digest("base64url"),
    );
    const read = (await (
      await control({ action: "get", query: { client_id: value.client_id }, headers: { cookie } })
    ).json()) as any;
    const { client_secret, client_credentials_scopes, ...expected } = value;
    expect(read).toEqual(expected);
    expect(client_secret).toBeTruthy();
    expect(client_credentials_scopes).toEqual([]);
    const physical = (await (
      await control({ action: "admin-http", body: input, headers: { cookie } })
    ).json()) as any;
    expect(physical.status).toBe(404);
    return {
      rejected,
      created: ctx.snapshot(value),
      read: ctx.snapshot(read),
      row: ctx.snapshot(row),
      physical,
    };
  },
);
