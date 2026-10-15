import { readFile as readFixtureFile } from "node:fs/promises";

import { Cookie } from "tough-cookie";
import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "SAML algorithm admission rejects unknown names and preserves accepted aliases",
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
      body: { email: ctx.uniqueEmail("algorithm-owner"), name: "Owner", password: "password123" },
    });
    expect(owner.status).toBe(200);
    const cookie = owner.headers
      .getSetCookie()
      .filter((raw) => Boolean(Cookie.parse(raw)?.value))
      .map((raw) => raw.split(";")[0])
      .join("; ");
    const headers = { cookie };
    const cert = await readFixtureFile(
      new URL("../../../../fixtures/salesforce-transport/leaf.pem", import.meta.url),
      "utf8",
    );
    const input = {
      providerId: "algorithm-provider",
      issuer: "https://idp.example.test/entity",
      domain: "company.test",
      samlConfig: {
        entryPoint: "https://idp.example.test/sso",
        cert,
        idpMetadata: { entityID: "https://idp.example.test/entity" },
      },
    };
    const created = await control({ headers, body: input });
    expect(created.status).toBe(200);
    const original = await (await control({ action: "row", providerId: input.providerId })).json();
    const observations = [];
    for (const [field, label] of [
      ["signatureAlgorithm", "signature"],
      ["digestAlgorithm", "digest"],
    ] as const) {
      for (const [index, value] of [
        "md5",
        "https://idp.example.test/unknown-algorithm",
        "SHA256 ",
        "http://www.w3.org/2001/04/xmlenc#SHA256",
      ].entries()) {
        const message = `SAML ${label} algorithm not recognized: ${value}`;
        const providerId = `invalid-${field}-${index}`;
        for (const [action, body] of [
          [
            "register",
            { ...input, providerId, samlConfig: { ...input.samlConfig, [field]: value } },
          ],
          ["update", { providerId: input.providerId, samlConfig: { [field]: value } }],
        ]) {
          const response = await control({ action, headers, body });
          expect(response.status).toBe(400);
          expect(await response.json()).toEqual({ code: "SAML_UNKNOWN_ALGORITHM", message });
        }
        expect(await (await control({ action: "row", providerId })).json()).toBe(null);
        expect(
          await (await control({ action: "row", providerId: input.providerId })).json(),
        ).toEqual(original);
        observations.push({ field, value, rejected: true });
      }
    }
    for (const [index, [signature, digest]] of [
      ["RSA-SHA256", "SHA256"],
      ["ecdsa-sha384", "sha384"],
      [
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512",
        "http://www.w3.org/2001/04/xmlenc#sha512",
      ],
      ["sha1", "sha1"],
      ["", ""],
    ].entries()) {
      const providerId = `valid-algorithm-${index}`;
      const created = await control({
        headers,
        body: {
          ...input,
          providerId,
          samlConfig: {
            ...input.samlConfig,
            signatureAlgorithm: signature,
            digestAlgorithm: digest,
          },
        },
      });
      expect(created.status).toBe(200);
      const updated = await control({
        action: "update",
        headers,
        body: {
          providerId: input.providerId,
          samlConfig: { signatureAlgorithm: signature, digestAlgorithm: digest },
        },
      });
      expect(updated.status).toBe(200);
      for (const id of [providerId, input.providerId]) {
        const row = (await (await control({ action: "row", providerId: id })).json()) as any;
        const config = JSON.parse(row.samlConfig);
        expect(config.signatureAlgorithm).toBe(signature);
        expect(config.digestAlgorithm).toBe(digest);
      }
      observations.push({ signature, digest });
    }
    return observations;
  },
);
