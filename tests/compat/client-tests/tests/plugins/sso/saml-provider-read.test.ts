import { readFile as readFixtureFile } from "node:fs/promises";

import { Cookie } from "tough-cookie";
import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";

compatScenario(
  "SAML provider reads and lists redact keys and project actual certificate authority",
  async (ctx) => {
    const actor = ctx.actor();
    const control = (input: Record<string, unknown>) =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/sso`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(input),
      });
    const cookies = (response: Response) =>
      response.headers
        .getSetCookie()
        .filter((raw) => Boolean(Cookie.parse(raw)?.value))
        .map((raw) => raw.split(";")[0])
        .join("; ");
    const owner = await control({
      action: "signup",
      body: {
        email: ctx.uniqueEmail("saml-reader"),
        name: "Native owner",
        password: "password123",
      },
    });
    expect(owner.status).toBe(200);
    const foreign = await control({
      action: "signup",
      body: {
        email: ctx.uniqueEmail("saml-reader-foreign"),
        name: "Native owner",
        password: "password123",
      },
    });
    expect(foreign.status).toBe(200);
    const headers = { cookie: cookies(owner) };
    const cert = await readFixtureFile(
      new URL("../../../../fixtures/salesforce-transport/leaf.pem", import.meta.url),
      "utf8",
    );
    const created = await control({
      headers,
      body: {
        providerId: "saml-read-provider",
        issuer: "https://sp.example.test/entity",
        domain: "company.test",
        samlConfig: {
          entryPoint: "https://idp.example.test/sso",
          cert: "fallback-cert",
          privateKey: "private-sp-secret",
          idpMetadata: {
            entityID: "https://idp.example.test/entity",
            cert: [cert, "malformed-cert"],
            privateKey: "private-idp-secret",
            privateKeyPass: "idp-passphrase",
          },
          spMetadata: { privateKey: "nested-sp-secret", encPrivateKey: "decryption-secret" },
          wantAssertionsSigned: true,
          authnRequestsSigned: false,
          audience: "urn:read:audience",
        },
      },
    });
    expect(created.status, await created.clone().text()).toBe(200);
    const response = await control({
      action: "get",
      query: { providerId: "saml-read-provider" },
      headers,
    });
    expect(response.status, await response.clone().text()).toBe(200);
    const projected = (await response.json()) as any;
    expect(projected).toEqual({
      providerId: "saml-read-provider",
      type: "saml",
      issuer: "https://sp.example.test/entity",
      domain: "company.test",
      organizationId: null,
      domainVerified: false,
      spMetadataUrl: `${ctx.baseURL}/api/auth/sso/saml2/sp/metadata?providerId=saml-read-provider`,
      samlConfig: {
        entryPoint: "https://idp.example.test/sso",
        wantAssertionsSigned: true,
        authnRequestsSigned: false,
        audience: "urn:read:audience",
        certificate: [
          {
            fingerprintSha256:
              "46:51:AA:26:63:79:35:81:81:8D:96:A4:13:DA:03:1F:B3:5E:B5:0C:7E:A9:0A:2C:E7:E2:55:21:48:C4:63:27",
            notBefore: "Oct  8 09:44:25 2026 GMT",
            notAfter: "Oct  5 09:44:25 2036 GMT",
            publicKeyAlgorithm: "RSA",
          },
          { error: "Failed to parse certificate" },
        ],
      },
    });
    const listing = await control({ action: "list", headers });
    expect(listing.status).toBe(200);
    expect(await listing.json()).toEqual({ providers: [projected] });
    const denied = await control({
      action: "get",
      query: { providerId: "saml-read-provider" },
      headers: { cookie: cookies(foreign) },
    });
    expect(denied.status).toBe(403);
    const row = (await (
      await control({ action: "row", providerId: "saml-read-provider" })
    ).json()) as any;
    const stored = JSON.parse(row.samlConfig);
    expect(stored.privateKey).toBe("private-sp-secret");
    expect(stored.idpMetadata.privateKey).toBe("private-idp-secret");
    expect(stored.spMetadata.encPrivateKey).toBe("decryption-secret");
    projected.spMetadataUrl =
      new URL(projected.spMetadataUrl).pathname + new URL(projected.spMetadataUrl).search;
    return { projected, denied: denied.status };
  },
);
