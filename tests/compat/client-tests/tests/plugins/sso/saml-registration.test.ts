import { expect } from "bun:test";

import { Cookie } from "tough-cookie";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "SAML registration persists owned configuration and requires a certificate source",
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
        email: ctx.uniqueEmail("saml-provider-owner"),
        name: "Native owner",
        password: "password123",
      },
    });
    expect(owner.status).toBe(200);
    const ownerBody = (await owner.json()) as any;
    const cookie = owner.headers
      .getSetCookie()
      .filter((raw) => Boolean(Cookie.parse(raw)?.value))
      .map((raw) => raw.split(";")[0])
      .join("; ");
    const cert = await Bun.file(
      new URL("../../../../fixtures/salesforce-transport/leaf.pem", import.meta.url),
    ).text();
    const input = {
      providerId: "enterprise-saml",
      issuer: "https://sp.example.test",
      domain: "company.test",
      samlConfig: {
        entryPoint: "https://idp.example.test/sso",
        cert,
        idpMetadata: { entityID: "https://idp.example.test/entity" },
        wantAssertionsSigned: true,
        signatureAlgorithm: "rsa-sha256",
        digestAlgorithm: "sha256",
        mapping: { email: "mail", name: "displayName" },
        ignoredField: "discard",
      },
    };
    const created = await control({ body: input, headers: { cookie } });
    expect(created.status, await created.clone().text()).toBe(200);
    const provider = (await created.json()) as any;
    expect(provider.userId).toBe(ownerBody.user.id);
    expect(provider.oidcConfig).toBe(null);
    expect(provider.samlConfig).toEqual({
      issuer: "https://sp.example.test",
      entryPoint: "https://idp.example.test/sso",
      cert,
      idpMetadata: { entityID: "https://idp.example.test/entity" },
      wantAssertionsSigned: true,
      signatureAlgorithm: "rsa-sha256",
      digestAlgorithm: "sha256",
      mapping: { email: "mail", name: "displayName" },
    });
    expect((await control({ action: "restart" })).status).toBe(200);
    const persisted = (await (
      await control({ action: "row", providerId: input.providerId })
    ).json()) as any;
    expect(persisted.id).toBe(provider.id);
    expect(persisted.userId).toBe(ownerBody.user.id);
    expect(JSON.parse(persisted.samlConfig)).toEqual(provider.samlConfig);
    const noCert: Partial<typeof input.samlConfig> = { ...input.samlConfig };
    delete noCert.cert;
    const rejected = await control({
      body: { ...input, providerId: "saml-without-cert", samlConfig: noCert },
      headers: { cookie },
    });
    expect(rejected.status).toBe(400);
    const error = (await rejected.json()) as any;
    expect(error.code).toBe("CERT_SOURCE_MISSING");
    expect(await (await control({ action: "row", providerId: "saml-without-cert" })).json()).toBe(
      null,
    );
    return { provider, persisted, error };
  },
);
