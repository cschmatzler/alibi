import { expect } from "bun:test";

import { Cookie } from "tough-cookie";

import { compatScenario } from "../../../support/scenario";
for (const mode of [
  "algorithm-strict",
  "algorithm-reject",
  "algorithm-override",
  "algorithm-empty",
]) {
  compatScenario(`SAML ${mode} signing policy governs registration and updates`, async (ctx) => {
    const actor = ctx.actor();
    const control = (input: Record<string, unknown>) =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/sso`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ mode, ...input }),
      });
    const owner = await control({
      action: "signup",
      body: { email: ctx.uniqueEmail(mode), name: "Owner", password: "password123" },
    });
    expect(owner.status).toBe(200);
    const cookie = owner.headers
      .getSetCookie()
      .filter((raw) => Boolean(Cookie.parse(raw)?.value))
      .map((raw) => raw.split(";")[0])
      .join("; ");
    const headers = { cookie };
    const cert = await Bun.file(
      new URL("../../../../fixtures/salesforce-transport/leaf.pem", import.meta.url),
    ).text();
    const providerId = `${mode}-provider`;
    const input = {
      providerId,
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
    const original = await (await control({ action: "row", providerId })).json();
    const rejected =
      mode === "algorithm-strict"
        ? ["sha384", "sha1"]
        : mode === "algorithm-reject"
          ? ["sha1"]
          : ["sha256"];
    const observations = [];
    for (const [field, label] of [
      ["signatureAlgorithm", "signature"],
      ["digestAlgorithm", "digest"],
    ] as const) {
      for (const [index, value] of rejected.entries()) {
        const code =
          mode === "algorithm-reject"
            ? "SAML_DEPRECATED_CONFIG_ALGORITHM"
            : "SAML_ALGORITHM_NOT_ALLOWED";
        const message =
          mode === "algorithm-reject"
            ? `SAML config uses deprecated ${label} algorithm: ${value}. Consider using SHA-256 or stronger.`
            : `SAML ${label} algorithm not in allow-list: ${value}`;
        const rejectedId = `${mode}-${field}-${index}`;
        for (const [action, body] of [
          [
            "register",
            {
              ...input,
              providerId: rejectedId,
              samlConfig: { ...input.samlConfig, [field]: value },
            },
          ],
          ["update", { providerId, samlConfig: { [field]: value } }],
        ]) {
          const response = await control({ action, headers, body });
          expect(response.status).toBe(400);
          expect(await response.json()).toEqual({ code, message });
        }
        expect(await (await control({ action: "row", providerId: rejectedId })).json()).toBe(null);
        expect(await (await control({ action: "row", providerId })).json()).toEqual(original);
        observations.push({ field, value, code });
      }
    }
    const [signature, digest] =
      mode === "algorithm-override"
        ? ["RSA-SHA1", "SHA1"]
        : mode === "algorithm-empty"
          ? ["", ""]
          : ["RSA-SHA256", "SHA256"];
    const acceptedId = `${mode}-accepted`;
    const accepted = await control({
      headers,
      body: {
        ...input,
        providerId: acceptedId,
        samlConfig: { ...input.samlConfig, signatureAlgorithm: signature, digestAlgorithm: digest },
      },
    });
    expect(accepted.status).toBe(200);
    const updated = await control({
      action: "update",
      headers,
      body: { providerId, samlConfig: { signatureAlgorithm: signature, digestAlgorithm: digest } },
    });
    expect(updated.status).toBe(200);
    for (const id of [providerId, acceptedId]) {
      const row = (await (await control({ action: "row", providerId: id })).json()) as any;
      const config = JSON.parse(row.samlConfig);
      expect(config.signatureAlgorithm).toBe(signature);
      expect(config.digestAlgorithm).toBe(digest);
    }
    return { observations, signature, digest };
  });
}
