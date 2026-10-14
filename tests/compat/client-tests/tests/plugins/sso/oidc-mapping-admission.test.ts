import { expect } from "bun:test";

import { Cookie } from "tough-cookie";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "OIDC mapping admission validates identity fields before registration and updates",
  async (ctx) => {
    const actor = ctx.actor();
    const control = (input: Record<string, unknown>) =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/sso`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(input),
      });
    const owner = await control({
      action: "signup",
      body: {
        email: ctx.uniqueEmail("mapping-owner"),
        name: "Mapping owner",
        password: "password123",
      },
    });
    expect(owner.status).toBe(200);
    const cookie = owner.headers
      .getSetCookie()
      .filter((raw) => Boolean(Cookie.parse(raw)?.value))
      .map((raw) => raw.split(";")[0])
      .join("; ");
    const headers = { cookie };
    const input = {
      providerId: "mapping-provider",
      issuer: "https://idp.example.com",
      domain: "company.test",
      oidcConfig: {
        clientId: "client",
        clientSecret: "secret",
        skipDiscovery: true,
        authorizationEndpoint: "https://idp.example.com/authorize",
        tokenEndpoint: "https://idp.example.com/token",
        jwksEndpoint: "https://idp.example.com/jwks",
        mapping: {
          email: "mail",
          name: "label",
          image: "avatar",
          extraFields: { department: "dept" },
        },
      },
    };
    const created = await control({ headers, body: input });
    expect(created.status).toBe(200);
    const row = (await (
      await control({ action: "row", providerId: input.providerId })
    ).json()) as any;
    expect(JSON.parse(row.oidcConfig).mapping).toEqual(input.oidcConfig.mapping);
    const cases: [Record<string, unknown>, string][] = [
      [
        { email: "mail" },
        "[body.oidcConfig.mapping.name] Invalid input: expected string, received undefined",
      ],
      [
        { name: "label" },
        "[body.oidcConfig.mapping.email] Invalid input: expected string, received undefined",
      ],
      [
        { email: 3, name: "label" },
        "[body.oidcConfig.mapping.email] Invalid input: expected string, received number",
      ],
      [
        { email: "mail", name: "label", image: false },
        "[body.oidcConfig.mapping.image] Invalid input: expected string, received boolean",
      ],
      [
        { email: "mail", name: "label", extraFields: [] },
        "[body.oidcConfig.mapping.extraFields] Invalid input: expected record, received array",
      ],
      [
        { email: "mail", name: "label", unknown: "field" },
        '[body.oidcConfig.mapping] Unrecognized key: "unknown"',
      ],
    ];
    const observations = [];
    for (const [index, [mapping, message]] of cases.entries()) {
      const providerId = `invalid-mapping-${index}`;
      const registered = await control({
        headers,
        body: { ...input, providerId, oidcConfig: { ...input.oidcConfig, mapping } },
      });
      expect(registered.status).toBe(400);
      expect(await registered.json()).toEqual({ code: "VALIDATION_ERROR", message });
      expect(await (await control({ action: "row", providerId })).json()).toBe(null);
      const updated = await control({
        action: "update",
        headers,
        body: { providerId: input.providerId, oidcConfig: { mapping } },
      });
      expect(updated.status).toBe(400);
      expect(await updated.json()).toEqual({ code: "VALIDATION_ERROR", message });
      expect(await (await control({ action: "row", providerId: input.providerId })).json()).toEqual(
        row,
      );
      observations.push({ message, rejected: true });
    }
    return observations;
  },
);
