import { expect } from "bun:test";

import { Cookie } from "tough-cookie";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "Administrative OAuth updates replace operator metadata and preserve credentials",
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
    const owner = await signup("oauth-admin-update-owner");
    const other = await signup("oauth-admin-update-other");
    const created = await control({
      action: "admin-create",
      headers: { cookie: owner },
      body: {
        client_name: "Before operator update",
        redirect_uris: ["https://app.fixture.test/callback"],
        skip_consent: true,
        enable_end_session: true,
        metadata: { old_label: "old" },
      },
    });
    expect(created.status).toBe(201);
    const original = (await created.json()) as any;
    const { client_secret, ...expected } = original;
    expect(client_secret).toBeTruthy();
    const old = (await (
      await control({ action: "row", clientId: original.client_id })
    ).json()) as any;
    const rejected = [];
    for (const [id, update, cookie, status] of [
      [original.client_id, { skip_consent: "yes" }, owner, 400],
      [original.client_id, { client_name: "foreign" }, other, 401],
      [original.client_id, { client_name: "guest" }, "", 401],
      [original.client_id, { client_credentials_scopes: ["email"] }, owner, 400],
      ["missing-client", {}, owner, 404],
    ] as const) {
      const r = await control({
        action: "admin-update",
        body: { client_id: id, update },
        headers: { cookie },
      });
      expect(r.status).toBe(status);
      const text = await r.text();
      if (status === 401) {
        expect(text).toBe("");
      }
      rejected.push({ status, body: text ? JSON.parse(text) : null });
      expect(await (await control({ action: "row", clientId: original.client_id })).json()).toEqual(
        old,
      );
    }
    const unchanged = await control({
      action: "admin-update",
      body: {
        client_id: original.client_id,
        update: { user_id: "forged", token_endpoint_auth_method: "none" },
      },
      headers: { cookie: owner },
    });
    expect(unchanged.status).toBe(200);
    expect(await unchanged.json()).toEqual(expected);
    const patch = {
      client_name: "After operator update",
      skip_consent: false,
      enable_end_session: false,
      dpop_bound_access_tokens: true,
      client_secret_expires_at: "1893456000",
      metadata: {
        new_label: "new",
        client_id: "forged",
        client_secret: "forged",
        user_id: "forged",
      },
    };
    const r = await control({
      action: "admin-update",
      body: { client_id: original.client_id, update: patch },
      headers: { cookie: owner },
    });
    expect(r.status).toBe(200);
    const value = await r.json();
    delete expected.old_label;
    expect(value).toEqual({
      ...expected,
      client_name: "After operator update",
      skip_consent: false,
      enable_end_session: false,
      dpop_bound_access_tokens: true,
      client_secret_expires_at: 0,
      new_label: "new",
    });
    const row = (await (
      await control({ action: "row", clientId: original.client_id })
    ).json()) as any;
    expect(row).toEqual({ ...old, clientName: "After operator update" });
    const physical = await control({
      action: "admin-http",
      operation: "update",
      body: { client_id: original.client_id, update: patch },
      headers: { cookie: owner },
    });
    expect(await physical.json()).toEqual({ status: 404 });
    return { rejected, updated: ctx.snapshot(value), row: ctx.snapshot(row) };
  },
);
