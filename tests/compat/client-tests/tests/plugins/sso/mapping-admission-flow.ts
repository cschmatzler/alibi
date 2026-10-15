import { readFile as readFixtureFile } from "node:fs/promises";

import { Cookie } from "tough-cookie";
import { expect } from "vitest";

import type { ScenarioContext } from "../../../support/scenario";
export async function mappingAdmissionFlow(ctx: ScenarioContext, saml = false, scopes = false) {
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
  const protocol = saml ? "samlConfig" : "oidcConfig";
  const config: Record<string, any> = saml
    ? {
        entryPoint: "https://idp.example.test/sso",
        cert: await readFixtureFile(
          new URL("../../../../fixtures/salesforce-transport/leaf.pem", import.meta.url),
          "utf8",
        ),
        idpMetadata: { entityID: "https://idp.example.test/entity" },
        mapping: {
          email: "mail",
          name: "label",
          firstName: "given",
          lastName: "surname",
          extraFields: { department: "dept" },
        },
      }
    : input.oidcConfig;
  const registration: Record<string, any> = { ...input, [protocol]: config };
  if (saml) {
    delete registration.oidcConfig;
  }
  const field = scopes ? "scopes" : "mapping";
  if (scopes) config.scopes = ["openid", "email"];
  const created = await control({ headers, body: registration });
  expect(created.status).toBe(200);
  const row = (await (
    await control({ action: "row", providerId: input.providerId })
  ).json()) as any;
  expect(JSON.parse(row[protocol])[field]).toEqual(config[field]);
  const cases: [unknown, string][] = scopes
    ? [
        [null, "[body.oidcConfig.scopes] Invalid input: expected array, received null"],
        ["openid", "[body.oidcConfig.scopes] Invalid input: expected array, received string"],
        [12, "[body.oidcConfig.scopes] Invalid input: expected array, received number"],
        [{}, "[body.oidcConfig.scopes] Invalid input: expected array, received object"],
        [
          ["openid", false],
          "[body.oidcConfig.scopes.1] Invalid input: expected string, received boolean",
        ],
        [
          [null, 12],
          "[body.oidcConfig.scopes.0] Invalid input: expected string, received null; [body.oidcConfig.scopes.1] Invalid input: expected string, received number",
        ],
      ]
    : [
        [null, "[body.oidcConfig.mapping] Invalid input: expected object, received null"],
        [[], "[body.oidcConfig.mapping] Invalid input: expected object, received array"],
        ["mapping", "[body.oidcConfig.mapping] Invalid input: expected object, received string"],
        [12, "[body.oidcConfig.mapping] Invalid input: expected object, received number"],
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
          { email: "mail", name: "label", [saml ? "firstName" : "image"]: false },
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
  for (const [index, [mapping, oidcMessage]] of cases.entries()) {
    const message = oidcMessage
      .replace("oidcConfig", protocol)
      .replace(".image]", saml ? ".firstName]" : ".image]");
    const providerId = `invalid-mapping-${index}`;
    const registered = await control({
      headers,
      body: { ...registration, providerId, [protocol]: { ...config, [field]: mapping } },
    });
    expect(registered.status).toBe(400);
    expect(await registered.json()).toEqual({ code: "VALIDATION_ERROR", message });
    expect(await (await control({ action: "row", providerId })).json()).toBe(null);
    const updated = await control({
      action: "update",
      headers,
      body: { providerId: input.providerId, [protocol]: { [field]: mapping } },
    });
    expect(updated.status).toBe(400);
    expect(await updated.json()).toEqual({ code: "VALIDATION_ERROR", message });
    expect(await (await control({ action: "row", providerId: input.providerId })).json()).toEqual(
      row,
    );
    observations.push({ message, rejected: true });
  }
  if (scopes) {
    for (const values of [[], ["openid", "", "email", "openid"]]) {
      const updated = await control({
        action: "update",
        headers,
        body: { providerId: input.providerId, oidcConfig: { scopes: values } },
      });
      expect(updated.status).toBe(200);
      const persisted = (await (
        await control({ action: "row", providerId: input.providerId })
      ).json()) as any;
      expect(JSON.parse(persisted.oidcConfig).scopes).toEqual(values);
      observations.push({ scopes: values });
    }
  }
  return observations;
}
