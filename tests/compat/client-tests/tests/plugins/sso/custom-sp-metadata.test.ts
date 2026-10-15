import { readFile as readFixtureFile } from "node:fs/promises";
import { inflateRawSync } from "node:zlib";

import { XMLParser } from "fast-xml-parser";
import { Cookie } from "tough-cookie";
import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";

compatScenario(
  "Custom SP metadata drives SAML login and protects effective identity",
  async (ctx) => {
    const actor = ctx.actor();
    const control = (input: Record<string, unknown>) =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/sso`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(input),
        redirect: "manual",
      });
    const cookies = (response: Response) =>
      response.headers
        .getSetCookie()
        .filter((raw) => Boolean(Cookie.parse(raw)?.value))
        .map((raw) => raw.split(";")[0])
        .join("; ");
    const owner = await control({
      action: "signup",
      body: { email: ctx.uniqueEmail("custom-sp-owner"), name: "Owner", password: "password123" },
    });
    expect(owner.status).toBe(200);
    const headers = { cookie: cookies(owner) };
    const cert = await readFixtureFile(
      new URL("../../../../fixtures/salesforce-transport/leaf.pem", import.meta.url),
      "utf8",
    );
    const acs = `${ctx.baseURL}/api/auth/sso/saml2/sp/acs/custom-sp-provider?from=metadata`;
    const metadata = `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sp.example.test/from-xml"><md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol" WantAssertionsSigned="true" AuthnRequestsSigned="false"><md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat><md:AssertionConsumerService index="0" Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="${acs}"/></md:SPSSODescriptor></md:EntityDescriptor>`;
    const registration = {
      providerId: "custom-sp-provider",
      issuer: "https://sp.example.test/unused-issuer",
      domain: "company.test",
      samlConfig: {
        entryPoint: "https://idp.example.test/sso",
        cert,
        idpMetadata: { entityID: "https://idp.example.test/entity" },
        spMetadata: { entityID: "https://sp.example.test/unused-field", metadata },
        identifierFormat: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
        wantAssertionsSigned: false,
      },
    };
    const created = await control({ body: registration, headers });
    expect(created.status).toBe(200);
    const output = await control({
      action: "sp-metadata",
      query: { providerId: "custom-sp-provider" },
    });
    expect(output.status).toBe(200);
    expect(output.headers.get("content-type")).toBe("application/xml");
    expect(await output.text()).toBe(metadata);
    const started = await control({
      action: "sign-in",
      body: { providerId: "custom-sp-provider", callbackURL: `${ctx.baseURL}/complete` },
    });
    expect(started.status).toBe(200);
    const authorization = ((await started.json()) as any).url;
    const url = new URL(authorization);
    const xml = inflateRawSync(
      Buffer.from(url.searchParams.get("SAMLRequest")!, "base64"),
    ).toString();
    const request = new XMLParser({ ignoreAttributes: false, removeNSPrefix: true }).parse(
      xml,
    ).AuthnRequest;
    expect(request["@_AssertionConsumerServiceURL"]).toBe(acs);
    expect(request.Issuer).toBe("https://sp.example.test/from-xml");
    expect(request.NameIDPolicy["@_Format"]).toBe(
      "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
    );
    const email = ctx.uniqueEmail("custom-sp-employee");
    const grant = await (await control({ action: "saml-grant", authorization, email })).json();
    const completed = await control({
      action: "acs",
      params: { providerId: "custom-sp-provider" },
      body: grant,
    });
    expect(completed.status).toBe(302);
    expect(completed.headers.get("location")).toBe(`${ctx.baseURL}/complete`);
    const session = (await (
      await control({ action: "session", headers: { cookie: cookies(completed) } })
    ).json()) as any;
    expect(session.user.email).toBe(email);
    expect(
      await (
        await control({ action: "account-row", providerId: "custom-sp-provider", accountId: email })
      ).json(),
    ).not.toBe(null);
    const original = await (
      await control({ action: "row", providerId: "custom-sp-provider" })
    ).json();
    for (const changed of [
      metadata.replace("https://sp.example.test/from-xml", "https://sp.example.test/changed"),
      metadata.replace("?from=metadata", "?from=changed"),
      metadata.replace('WantAssertionsSigned="true"', 'WantAssertionsSigned="false"'),
    ]) {
      const rejected = await control({
        action: "update",
        headers,
        body: {
          providerId: "custom-sp-provider",
          samlConfig: { spMetadata: { metadata: changed } },
        },
      });
      expect(rejected.status).toBe(409);
      expect(
        await (await control({ action: "row", providerId: "custom-sp-provider" })).json(),
      ).toEqual(original);
    }
    for (const [index, xml, code] of [
      [0, "<broken>", "SAML_INVALID_SP_METADATA"],
      [
        1,
        metadata.replace("urn:oasis:names:tc:SAML:2.0:metadata", "urn:wrong"),
        "SAML_INVALID_SP_METADATA",
      ],
      [2, metadata.replace("HTTP-POST", "HTTP-Redirect"), "SAML_INVALID_SP_METADATA"],
      [
        3,
        metadata.replace('WantAssertionsSigned="true"', 'WantAssertionsSigned="false"'),
        "SAML_SP_METADATA_ASSERTION_SIGNATURE_MISMATCH",
      ],
    ] as const) {
      const rejected = await control({
        headers,
        body: {
          ...registration,
          providerId: `invalid-sp-${index}`,
          samlConfig: {
            ...registration.samlConfig,
            wantAssertionsSigned: true,
            spMetadata: { ...registration.samlConfig.spMetadata, metadata: xml },
          },
        },
      });
      expect(rejected.status).toBe(400);
      expect(((await rejected.json()) as any).code).toBe(code);
      expect(
        await (await control({ action: "row", providerId: `invalid-sp-${index}` })).json(),
      ).toBe(null);
    }
    const oversized = await control({
      headers,
      body: {
        ...registration,
        providerId: "oversized-sp",
        samlConfig: {
          ...registration.samlConfig,
          spMetadata: { metadata: "x".repeat(102401) },
        },
      },
    });
    expect(oversized.status).toBe(400);
    expect(await oversized.json()).toEqual({
      message: "SP metadata exceeds maximum allowed size (102400 bytes)",
    });
    expect(await (await control({ action: "row", providerId: "oversized-sp" })).json()).toBe(null);
    return {
      entity: request.Issuer,
      nameID: request.NameIDPolicy["@_Format"],
      acsPath: new URL(acs).pathname,
      loggedIn: true,
    };
  },
);
