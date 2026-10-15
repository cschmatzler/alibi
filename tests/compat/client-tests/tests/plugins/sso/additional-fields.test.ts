import { Cookie } from "tough-cookie";
import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "Declared SSO provider fields validate, persist and filter across restart",
  async (ctx) => {
    const actor = ctx.actor();
    const control = (input: Record<string, unknown>) =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/sso`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ mode: "additional-fields", ...input }),
      });
    const owner = await control({
      action: "signup",
      body: { email: ctx.uniqueEmail("extra-owner"), name: "Owner", password: "password123" },
    });
    expect(owner.status).toBe(200);
    const cookie = owner.headers
      .getSetCookie()
      .filter((raw) => Boolean(Cookie.parse(raw)?.value))
      .map((raw) => raw.split(";")[0])
      .join("; ");
    const headers = { cookie };
    const body = {
      providerId: "extra-provider",
      issuer: "https://idp.example.com",
      domain: "company.test",
      label: "Initial",
      privateNote: "private",
      tags: ["one", "two"],
      settings: { enabled: true, nested: [1, null] },
      oidcConfig: {
        clientId: "client",
        clientSecret: "secret",
        skipDiscovery: true,
        pkce: true,
        authorizationEndpoint: "https://idp.example.com/authorize",
        tokenEndpoint: "https://idp.example.com/token",
        jwksEndpoint: "https://idp.example.com/jwks",
      },
    };
    for (const [field, value, message] of [
      ["label", 3, "[body.label] Invalid input: expected string, received number"],
      ["tags", ["one", 3], "[body.tags.1] Invalid input: expected string, received number"],
      ["managed", false, "managed is not allowed to be set"],
      ["managed", null, "managed is not allowed to be set"],
    ] as const) {
      const response = await control({ headers, body: { ...body, [field]: value } });
      expect(response.status).toBe(400);
      expect(((await response.json()) as any).message).toBe(message);
      expect(await (await control({ action: "row", providerId: body.providerId })).json()).toBe(
        null,
      );
    }
    const created = await control({ headers, body });
    expect(created.status).toBe(200);
    const registered = (await created.json()) as any;
    expect(registered.label).toBe("Initial");
    expect(registered.managed).toBe(false);
    expect(registered.tier).toBe(2);
    expect(registered).not.toHaveProperty("privateNote");
    const stored = (await (
      await control({ action: "row", providerId: body.providerId })
    ).json()) as any;
    expect(stored.privateNote).toBe("private");
    expect(stored.settings).toEqual(body.settings);
    expect(stored.tags).toEqual(body.tags);
    const updated = await control({
      action: "update",
      headers,
      body: {
        providerId: body.providerId,
        label: "Changed",
        privateNote: "new private",
        tier: 4,
        tags: [],
        settings: null,
      },
    });
    expect(updated.status).toBe(200);
    const changed = (await updated.json()) as any;
    expect(changed.label).toBe("Changed");
    expect(changed.tier).toBe(4);
    expect(changed.tags).toEqual([]);
    expect(changed).not.toHaveProperty("privateNote");
    await control({ action: "restart" });
    const read = await control({ action: "get", headers, query: { providerId: body.providerId } });
    expect(read.status).toBe(200);
    expect(await read.json()).toEqual(changed);
    const listed = await control({ action: "list", headers });
    expect(listed.status).toBe(200);
    expect(((await listed.json()) as any).providers).toEqual([changed]);
    const persisted = (await (
      await control({ action: "row", providerId: body.providerId })
    ).json()) as any;
    expect(persisted.privateNote).toBe("new private");
    expect(persisted.settings).toBe(null);
    expect(JSON.parse(persisted.oidcConfig).clientSecret).toBe("secret");
    expect(registered.redirectURI).toBe(`${ctx.baseURL}/api/auth/sso/callback/${body.providerId}`);
    const project = (row: any) => ({ ...row, oidcConfig: JSON.parse(row.oidcConfig) });
    return {
      registered: { ...registered, redirectURI: new URL(registered.redirectURI).pathname },
      changed,
      stored: project(stored),
      persisted: project(persisted),
    };
  },
);
