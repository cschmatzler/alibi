import { expect } from "bun:test";

import { Cookie } from "tough-cookie";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "SAML SP metadata validates declared fields before registration or update and drops unknown fields",
  async (ctx) => {
    const actor = ctx.actor();
    const control = (input: Record<string, unknown>) =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/sso`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(input),
        redirect: "manual",
      });
    const owner = await control({
      action: "signup",
      body: { email: ctx.uniqueEmail("sp-schema-owner"), name: "Owner", password: "password123" },
    });
    expect(owner.status).toBe(200);
    const headers = {
      cookie: owner.headers
        .getSetCookie()
        .filter((raw) => Boolean(Cookie.parse(raw)?.value))
        .map((raw) => raw.split(";")[0])
        .join("; "),
    };
    const cert = await Bun.file(
      new URL("../../../../fixtures/salesforce-transport/leaf.pem", import.meta.url),
    ).text();
    const base = {
      providerId: "sp-schema-provider",
      issuer: "https://sp.example.test/entity",
      domain: "company.test",
      samlConfig: {
        entryPoint: "https://idp.example.test/sso",
        cert,
        idpMetadata: { entityID: "https://idp.example.test/entity" },
        wantAssertionsSigned: true,
      },
    };
    expect((await control({ headers, body: base })).status).toBe(200);
    const original = await (
      await control({ action: "row", providerId: "sp-schema-provider" })
    ).json();
    const cases = [
      ["metadata", 41, "string", "number"],
      ["entityID", false, "string", "boolean"],
      ["binding", null, "string", "null"],
      ["privateKey", true, "string", "boolean"],
      ["privateKeyPass", 2, "string", "number"],
      ["isAssertionEncrypted", "true", "boolean", "string"],
      ["encPrivateKey", [], "string", "array"],
      ["encPrivateKeyPass", {}, "string", "object"],
    ] as const;
    const observed = [];
    for (const update of [false, true]) {
      for (const [index, [field, value, expected, received]] of cases.entries()) {
        const providerId = update ? "sp-schema-provider" : `invalid-sp-${index}`;
        const spMetadata = { [field]: value };
        const response = await control({
          headers,
          ...(update ? { action: "update" } : {}),
          body: update
            ? { providerId, samlConfig: { spMetadata } }
            : { ...base, providerId, samlConfig: { ...base.samlConfig, spMetadata } },
        });
        expect(response.status).toBe(400);
        const error = await response.json();
        expect(error).toEqual({
          code: "VALIDATION_ERROR",
          message: `[body.samlConfig.spMetadata.${field}] Invalid input: expected ${expected}, received ${received}`,
        });
        const row = await (await control({ action: "row", providerId })).json();
        if (update) {
          expect(row).toEqual(original);
        } else {
          expect(row).toBe(null);
        }
        observed.push({ update, field, error });
      }
    }
    const spMetadata = {
      privateKeyPass: "accepted-pass",
      isAssertionEncrypted: false,
      ignored: "must-not-persist",
    };
    expect(
      (
        await control({
          headers,
          body: {
            ...base,
            providerId: "clean-sp-provider",
            samlConfig: { ...base.samlConfig, spMetadata },
          },
        })
      ).status,
    ).toBe(200);
    const clean = (await (
      await control({ action: "row", providerId: "clean-sp-provider" })
    ).json()) as any;
    expect(JSON.parse(clean.samlConfig).spMetadata).toEqual({
      privateKeyPass: "accepted-pass",
      isAssertionEncrypted: false,
    });
    expect(
      (
        await control({
          action: "update",
          headers,
          body: { providerId: "sp-schema-provider", samlConfig: { spMetadata } },
        })
      ).status,
    ).toBe(200);
    const updated = (await (
      await control({ action: "row", providerId: "sp-schema-provider" })
    ).json()) as any;
    expect(JSON.parse(updated.samlConfig).spMetadata).toEqual({
      privateKeyPass: "accepted-pass",
      isAssertionEncrypted: false,
    });
    return observed;
  },
);
