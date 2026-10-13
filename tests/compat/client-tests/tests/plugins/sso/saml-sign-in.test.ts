import { expect } from "bun:test";
import { createHash, createHmac, createVerify } from "node:crypto";
import { inflateRawSync } from "node:zlib";

import { XMLParser, XMLValidator } from "fast-xml-parser";
import { Cookie } from "tough-cookie";

import { compatScenario } from "../../../support/scenario";
for (const signed of [false, true]) {
  compatScenario(
    `SAML ${signed ? "signed" : "unsigned"} redirect request has durable bound relay and request proofs`,
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
          email: ctx.uniqueEmail("saml-sign-in-owner"),
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
      const privateKey = await Bun.file(
        new URL("../../../../fixtures/salesforce-transport/key.pem", import.meta.url),
      ).text();
      const providerId = signed ? "signed-saml-provider" : "unsigned-saml-provider";
      const config = {
        entryPoint: "https://idp.example.test/sso",
        cert,
        privateKey,
        idpMetadata: { entityID: "https://idp.example.test/entity" },
        authnRequestsSigned: signed,
        wantAssertionsSigned: true,
      };
      const created = await control({
        body: {
          providerId,
          issuer: "https://sp.example.test/entity",
          domain: "company.test",
          samlConfig: config,
        },
        headers: { cookie },
      });
      expect(created.status).toBe(200);
      const provider = (await created.json()) as any;
      const input = {
        providerId,
        providerType: "saml",
        callbackURL: `${ctx.baseURL}/complete`,
        errorCallbackURL: `${ctx.baseURL}/failed`,
      };
      const before = Date.now();
      const response = await control({ action: "sign-in", body: input });
      const after = Date.now();
      expect(response.status, await response.clone().text()).toBe(200);
      const result = (await response.json()) as any;
      expect(result.redirect).toBe(true);
      const url = new URL(result.url);
      expect(url.origin).toBe("https://idp.example.test");
      expect(url.pathname).toBe("/sso");
      const relay = url.searchParams.get("RelayState")!;
      expect(relay).toHaveLength(32);
      expect(url.searchParams.getAll("SAMLRequest")).toHaveLength(1);
      const xml = inflateRawSync(
        Buffer.from(url.searchParams.get("SAMLRequest")!, "base64"),
      ).toString();
      expect(XMLValidator.validate(xml)).toBe(true);
      const namespaced = new XMLParser({
        ignoreAttributes: false,
        parseAttributeValue: false,
      }).parse(xml)["samlp:AuthnRequest"];
      expect(namespaced["@_xmlns:samlp"]).toBe("urn:oasis:names:tc:SAML:2.0:protocol");
      expect(namespaced["@_xmlns:saml"]).toBe("urn:oasis:names:tc:SAML:2.0:assertion");
      const request = new XMLParser({
        ignoreAttributes: false,
        parseAttributeValue: false,
        removeNSPrefix: true,
      }).parse(xml).AuthnRequest;
      expect(request["@_Version"]).toBe("2.0");
      expect(request["@_Destination"]).toBe("https://idp.example.test/sso");
      expect(request["@_ProtocolBinding"]).toBe("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");
      expect(request["@_AssertionConsumerServiceURL"]).toBe(
        `${ctx.baseURL}/api/auth/sso/saml2/sp/acs/${providerId}`,
      );
      expect(request.Issuer).toBe("https://sp.example.test/entity");
      expect(request.NameIDPolicy).toEqual({
        "@_Format": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        "@_AllowCreate": "true",
      });
      expect(request["@_ID"]).toMatch(/^_[0-9a-f-]{36}$/);
      expect(Date.parse(request["@_IssueInstant"])).toBeGreaterThanOrEqual(before);
      expect(Date.parse(request["@_IssueInstant"])).toBeLessThanOrEqual(after);
      const relayRow = (await (
        await control({ action: "proof", identifier: `auth-state:${relay}` })
      ).json()) as any;
      const payload = JSON.parse(relayRow.value);
      expect(payload.oauthState).toBe(relay);
      expect(payload.callbackURL).toBe(input.callbackURL);
      expect(payload.errorURL).toBe(input.errorCallbackURL);
      expect(payload.codeVerifier).toHaveLength(128);
      expect(Date.parse(relayRow.expiresAt)).toBeGreaterThanOrEqual(before + 600000);
      expect(Date.parse(relayRow.expiresAt)).toBeLessThanOrEqual(after + 600000);
      const reference = payload.serverContext.ssoProviderReference;
      expect(reference.providerId).toBe(providerId);
      expect(reference.source).toEqual({ type: "persisted", recordId: provider.id });
      const canonical = (value: any): string =>
        value === null || typeof value !== "object"
          ? JSON.stringify(value)
          : Array.isArray(value)
            ? `[${value.map(canonical).join(",")}]`
            : `{${Object.keys(value)
                .sort()
                .map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`)
                .join(",")}}`;
      const publicConfig: Partial<typeof config> = { ...config };
      delete publicConfig.privateKey;
      const expected = {
        domain: "company.test",
        issuer: "https://sp.example.test/entity",
        organizationId: null,
        samlConfig: { ...publicConfig, issuer: "https://sp.example.test/entity" },
      };
      expect(reference.authenticationConfigurationFingerprint).toBe(
        createHash("sha256").update(canonical(expected)).digest("base64url"),
      );
      const requestRow = (await (
        await control({ action: "proof", identifier: `saml-authn-request:${request["@_ID"]}` })
      ).json()) as any;
      const proof = JSON.parse(requestRow.value);
      expect(proof.id).toBe(request["@_ID"]);
      expect(proof.providerId).toBe(providerId);
      expect(proof.providerReference).toEqual(reference);
      expect(Date.parse(requestRow.expiresAt)).toBe(proof.expiresAt);
      expect(proof.createdAt).toBeGreaterThanOrEqual(before);
      expect(proof.createdAt).toBeLessThanOrEqual(after);
      expect(proof.expiresAt - proof.createdAt).toBeGreaterThanOrEqual(300000);
      expect(proof.expiresAt - proof.createdAt).toBeLessThanOrEqual(300200);
      const relayCookie = response.headers
        .getSetCookie()
        .find((cookie) => cookie.startsWith("better-auth.relay_state="));
      expect(relayCookie).toBeDefined();
      expect(relayCookie).toContain("Max-Age=300");
      const value = decodeURIComponent(
        relayCookie!.split(";")[0]!.slice("better-auth.relay_state=".length),
      );
      expect(value).toBe(
        `${relay}.${createHmac("sha256", ["compat", "test", "only", "key", "not", "real", "minimum", "32chars"].join("-")).update(relay).digest("base64")}`,
      );
      if (signed) {
        expect(url.searchParams.get("SigAlg")).toBe(
          "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
        );
        const message = ["SAMLRequest", "RelayState", "SigAlg"]
          .map((name) => {
            expect(url.searchParams.getAll(name)).toHaveLength(1);
            return url.search
              .slice(1)
              .split("&")
              .find((pair) => pair.startsWith(`${name}=`))!;
          })
          .join("&");
        expect(
          createVerify("RSA-SHA256")
            .update(message)
            .verify(privateKey, Buffer.from(url.searchParams.get("Signature")!, "base64")),
        ).toBe(true);
      } else {
        expect(url.searchParams.has("SigAlg")).toBe(false);
        expect(url.searchParams.has("Signature")).toBe(false);
      }
      const rejected = await control({
        action: "sign-in",
        body: { ...input, additionalParams: { prompt: "login" } },
      });
      expect(rejected.status).toBe(400);
      const error = (await rejected.json()) as any;
      expect(error.message).toBe(
        "additionalParams is not supported for SAML providers; the SAML AuthnRequest is signed and cannot carry caller-supplied query parameters.",
      );
      return {
        signed,
        redirect: result.redirect,
        version: request["@_Version"],
        destination: request["@_Destination"],
        issuer: request.Issuer,
        acs: new URL(request["@_AssertionConsumerServiceURL"]).pathname,
        nameIdPolicy: request.NameIDPolicy,
        fingerprint: reference.authenticationConfigurationFingerprint,
        requestTTL: Math.round((proof.expiresAt - proof.createdAt) / 1000),
        error,
      };
    },
  );
}
