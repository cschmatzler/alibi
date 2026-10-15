import { createHash } from "node:crypto";

import { Cookie } from "tough-cookie";
import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "OAuth client secret rotation replaces the durable protected secret for its owner",
  async (ctx) => {
    const actor = ctx.actor();
    const control = (input: unknown) =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/oauth-provider-clients`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(input),
      });
    const signup = async (label: string) => {
      const r = await control({
        action: "signup",
        body: { email: ctx.uniqueEmail(label), name: label, password: "password123" },
      });
      expect(r.status).toBe(200);
      return r.headers
        .getSetCookie()
        .filter((raw) => Boolean(Cookie.parse(raw)?.value))
        .map((raw) => raw.split(";")[0])
        .join("; ");
    };
    const owner = await signup("oauth-rotation-owner");
    const other = await signup("oauth-rotation-other");
    const clients: any[] = [];
    for (const publicClient of [false, true]) {
      const r = await control({
        headers: { cookie: owner },
        body: {
          client_name: "Rotation client",
          redirect_uris: ["https://app.fixture.test/callback"],
          ...(publicClient ? { token_endpoint_auth_method: "none" } : {}),
        },
      });
      expect(r.status).toBe(201);
      clients.push(await r.json());
    }
    const denied = [];
    for (const [id, cookie, status] of [
      [clients[0].client_id, other, 401],
      [clients[0].client_id, "", 401],
      [clients[1].client_id, owner, 400],
      ["missing-client", owner, 404],
    ] as const) {
      const r = await control({ action: "rotate", body: { client_id: id }, headers: { cookie } });
      expect(r.status).toBe(status);
      const text = await r.text();
      denied.push({ status, body: text ? JSON.parse(text) : null });
    }
    const oldRow = (await (
      await control({ action: "row", clientId: clients[0].client_id })
    ).json()) as any;
    const r = await control({
      action: "rotate",
      body: { client_id: clients[0].client_id },
      headers: { cookie: owner },
    });
    expect(r.status).toBe(200);
    expect(r.headers.get("cache-control")).toBe("no-store");
    expect(r.headers.get("pragma")).toBe("no-cache");
    const rotated = (await r.json()) as any;
    expect(rotated.client_secret).toMatch(/^[a-zA-Z]{32}$/);
    expect(rotated.client_secret).not.toBe(clients[0].client_secret);
    expect(rotated).toEqual({ ...clients[0], client_secret: rotated.client_secret });
    const row = (await (
      await control({ action: "row", clientId: clients[0].client_id })
    ).json()) as any;
    expect(row.client_secret).toBe(
      createHash("sha256").update(rotated.client_secret).digest("base64url"),
    );
    expect(row.client_secret).not.toBe(oldRow.client_secret);
    expect(row).toEqual({ ...oldRow, client_secret: row.client_secret });
    const publicRow = (await (
      await control({ action: "row", clientId: clients[1].client_id })
    ).json()) as any;
    expect(publicRow.client_secret).toBeNull();
    return {
      denied,
      rotated: ctx.snapshot(rotated),
      row: ctx.snapshot(row),
      publicRow: ctx.snapshot(publicRow),
    };
  },
);
