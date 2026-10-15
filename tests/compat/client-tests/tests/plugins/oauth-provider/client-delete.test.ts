import { Cookie } from "tough-cookie";
import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "OAuth client deletion enforces ownership and retires only the selected client",
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
    const owner = await signup("oauth-delete-owner");
    const other = await signup("oauth-delete-other");
    const ids: string[] = [];
    for (const cookie of [owner, owner, other]) {
      const r = await control({
        headers: { cookie },
        body: { redirect_uris: ["https://app.fixture.test/callback"] },
      });
      expect(r.status).toBe(201);
      ids.push(((await r.json()) as any).client_id);
    }
    const denied = [];
    for (const [id, cookie, status] of [
      [ids[0], other, 401],
      [ids[0], "", 401],
      ["missing-client", owner, 404],
    ] as const) {
      const r = await control({ action: "delete", body: { client_id: id }, headers: { cookie } });
      expect(r.status).toBe(status);
      const text = await r.text();
      denied.push({ status, body: text ? JSON.parse(text) : null });
      const row = await control({ action: "row", clientId: ids[0] });
      expect(await row.json()).not.toBeNull();
    }
    const deleted = await control({
      action: "delete",
      body: { client_id: ids[0] },
      headers: { cookie: owner },
    });
    expect(deleted.status).toBe(200);
    expect(await deleted.text()).toBe("");
    const rows = [];
    for (const [i, id] of ids.entries()) {
      const r = await control({ action: "row", clientId: id });
      const row = await r.json();
      if (i === 0) {
        expect(row).toBeNull();
      } else {
        expect(row).not.toBeNull();
      }
      rows.push(row);
    }
    const replay = await control({
      action: "delete",
      body: { client_id: ids[0] },
      headers: { cookie: owner },
    });
    expect(replay.status).toBe(404);
    return { denied, rows: ctx.snapshot(rows), replay: await replay.json() };
  },
);
