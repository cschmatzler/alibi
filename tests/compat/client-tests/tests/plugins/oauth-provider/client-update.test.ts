import { Cookie } from "tough-cookie";
import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "OAuth client update persists owned metadata and preserves credentials",
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
    const owner = await signup("oauth-update-owner");
    const other = await signup("oauth-update-other");
    const r = await control({
      headers: { cookie: owner },
      body: {
        client_name: "Before update",
        redirect_uris: ["https://app.fixture.test/callback"],
        scope: "openid email",
      },
    });
    expect(r.status).toBe(201);
    const original = (await r.json()) as any;
    const { client_secret, ...expected } = original;
    expect(client_secret).toMatch(/^[a-zA-Z]{32}$/);
    const old = (await (
      await control({ action: "row", clientId: original.client_id })
    ).json()) as any;
    const rejected = [];
    for (const [id, update, cookie, status] of [
      [original.client_id, { client_name: 42 }, owner, 400],
      [original.client_id, { scope: "forbidden" }, owner, 400],
      [
        original.client_id,
        { redirect_uris: ["https://app.fixture.test/callback#fragment"] },
        owner,
        400,
      ],
      [original.client_id, { client_name: "Foreign edit" }, other, 401],
      [original.client_id, { client_name: "Guest edit" }, "", 401],
      ["missing-client", {}, owner, 404],
    ] as const) {
      const response = await control({
        action: "update",
        body: { client_id: id, update },
        headers: { cookie },
      });
      expect(response.status).toBe(status);
      const text = await response.text();
      rejected.push({ status, body: text ? JSON.parse(text) : null });
      expect(await (await control({ action: "row", clientId: original.client_id })).json()).toEqual(
        old,
      );
    }
    const unchanged = await control({
      action: "update",
      body: {
        client_id: original.client_id,
        update: { user_id: "forged", token_endpoint_auth_method: "none" },
      },
      headers: { cookie: owner },
    });
    expect(unchanged.status).toBe(200);
    expect(await unchanged.json()).toEqual(expected);
    const response = await control({
      action: "update",
      body: {
        client_id: original.client_id,
        update: {
          client_name: "After update",
          scope: "email",
          redirect_uris: ["\uFEFF HTTPS://NEW.fixture.test:443/a/../callback \u00a0"],
          post_logout_redirect_uris: ["\u2028https://new.fixture.test/logout\uFEFF"],
          backchannel_logout_uri: " \uFEFFhttps://new.fixture.test/backchannel\t ",
          client_uri: " https://new.fixture.test/about ",
          contacts: ["support@fixture.test"],
          client_secret: "forged",
          user_id: "forged",
        },
      },
      headers: { cookie: owner },
    });
    expect(response.status).toBe(200);
    const updated = await response.json();
    expect(updated).toEqual({
      ...expected,
      client_name: "After update",
      scope: "email",
      redirect_uris: ["HTTPS://NEW.fixture.test:443/a/../callback"],
      post_logout_redirect_uris: ["https://new.fixture.test/logout"],
      backchannel_logout_uri: "https://new.fixture.test/backchannel",
      client_uri: " https://new.fixture.test/about ",
      contacts: ["support@fixture.test"],
    });
    const row = (await (
      await control({ action: "row", clientId: original.client_id })
    ).json()) as any;
    expect(row).toEqual({
      ...old,
      clientName: "After update",
      redirectUris: ["HTTPS://NEW.fixture.test:443/a/../callback"],
    });
    const read = await control({
      action: "get",
      query: { client_id: original.client_id },
      headers: { cookie: owner },
    });
    expect(read.status).toBe(200);
    const persisted = await read.json();
    expect(persisted).toEqual(updated);
    return {
      rejected,
      updated: ctx.snapshot(updated),
      persisted: ctx.snapshot(persisted),
      row: ctx.snapshot(row),
    };
  },
);
