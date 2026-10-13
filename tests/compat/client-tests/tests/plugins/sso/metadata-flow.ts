import { expect } from "bun:test";

import { XMLParser, XMLValidator } from "fast-xml-parser";
import { Cookie } from "tough-cookie";

import type { ScenarioContext } from "../../../support/scenario";
export async function samlMetadataFlow(ctx: ScenarioContext, slo: boolean) {
  const actor = ctx.actor();
  const control = (input: Record<string, unknown>) =>
    actor.fetch(`${ctx.baseURL}/__test/server-api/sso`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ ...input, mode: slo ? "slo" : "default" }),
    });
  const owner = await control({
    action: "signup",
    body: {
      email: ctx.uniqueEmail("saml-metadata-owner"),
      name: "Native owner",
      password: "password123",
    },
  });
  expect(owner.status).toBe(200);
  const cookie = owner.headers
    .getSetCookie()
    .filter((raw) => Boolean(Cookie.parse(raw)?.value))
    .map((raw) => raw.split(";")[0])
    .join("; ");
  const cert = await Bun.file(
    new URL("../../../../fixtures/salesforce-transport/leaf.pem", import.meta.url),
  ).text();
  const input = {
    providerId: "metadata-provider",
    issuer: "https://sp.example.test/issuer",
    domain: "company.test",
    samlConfig: {
      entryPoint: "https://idp.example.test/sso",
      cert,
      idpMetadata: { entityID: "https://idp.example.test/entity" },
      spMetadata: { entityID: "https://sp.example.test/metadata?tenant=engineering&region=eu" },
      wantAssertionsSigned: true,
      authnRequestsSigned: true,
    },
  };
  expect((await control({ body: input, headers: { cookie } })).status).toBe(200);
  const response = await control({
    action: "sp-metadata",
    query: { providerId: "metadata-provider" },
    headers: {},
  });
  expect(response.status).toBe(200);
  expect(response.headers.get("content-type")).toBe("application/xml");
  const xml = await response.text();
  expect(XMLValidator.validate(xml)).toBe(true);
  const parsed = new XMLParser({ ignoreAttributes: false, parseAttributeValue: false }).parse(xml);
  const entity = parsed.EntityDescriptor;
  expect(entity["@_xmlns"]).toBe("urn:oasis:names:tc:SAML:2.0:metadata");
  expect(entity["@_entityID"]).toBe(
    "https://sp.example.test/metadata?tenant=engineering&region=eu",
  );
  const sp = entity.SPSSODescriptor;
  expect(sp["@_WantAssertionsSigned"]).toBe("true");
  expect(sp["@_AuthnRequestsSigned"]).toBe("true");
  expect(sp["@_protocolSupportEnumeration"]).toBe("urn:oasis:names:tc:SAML:2.0:protocol");
  expect(sp.NameIDFormat).toBe("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress");
  const acs = sp.AssertionConsumerService;
  expect(acs["@_Location"]).toBe(`${ctx.baseURL}/api/auth/sso/saml2/sp/acs/metadata-provider`);
  expect(acs["@_Binding"]).toBe("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");
  expect(acs["@_index"]).toBe("0");
  if (slo) {
    expect(sp.SingleLogoutService).toHaveLength(2);
    expect(sp.SingleLogoutService.map((service: any) => service["@_Binding"])).toEqual([
      "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
      "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
    ]);
    for (const service of sp.SingleLogoutService) {
      expect(service["@_Location"]).toBe(
        `${ctx.baseURL}/api/auth/sso/saml2/sp/slo/metadata-provider`,
      );
      service["@_Location"] = new URL(service["@_Location"]).pathname;
    }
  } else {
    expect(sp.SingleLogoutService).toBeUndefined();
  }
  expect(sp.KeyDescriptor).toBeUndefined();
  expect(xml).not.toContain("BEGIN CERTIFICATE");
  const missing = await control({
    action: "sp-metadata",
    query: { providerId: "missing-provider" },
    headers: {},
  });
  expect(missing.status).toBe(404);
  const missingBody = await missing.json();
  acs["@_Location"] = new URL(acs["@_Location"]).pathname;
  return { parsed, missing: missingBody };
}
