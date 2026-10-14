import { expect } from "bun:test";
import { inflateRawSync, deflateRawSync } from "node:zlib";

import { XMLParser, XMLValidator } from "fast-xml-parser";
import { Cookie } from "tough-cookie";

import type { ScenarioContext } from "../../../support/scenario";
import { idpXMLMetadata } from "./idp-metadata-input";
import { customSPMetadata } from "./sp-metadata-input";

export async function samlLogoutFlow(
  ctx: ScenarioContext,
  complete: boolean,
  signed = false,
  rollover = false,
  binding:
    | "post"
    | "redirect"
    | "post-optional-signature"
    | "custom-sp"
    | "xml-idp"
    | "local-api"
    | "local-http"
    | "local-disabled" = "post",
) {
  const providerId =
    binding === "local-http"
      ? "logout-http-provider"
      : binding === "local-disabled"
        ? "logout-disabled-provider"
        : "logout-provider";
  const actor = ctx.actor();
  const control = (input: Record<string, unknown>) =>
    actor.fetch(`${ctx.baseURL}/__test/server-api/sso`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ mode: signed ? "signed-slo" : "slo", ...input }),
      redirect: "manual",
    });
  const pairs = (response: Response) =>
    response.headers
      .getSetCookie()
      .filter((raw) => Boolean(Cookie.parse(raw)?.value))
      .map((raw) => raw.split(";")[0])
      .join("; ");
  const owner = await control({
    action: "signup",
    body: {
      email: ctx.uniqueEmail("saml-logout-owner"),
      name: "Native owner",
      password: "password123",
    },
  });
  expect(owner.status).toBe(200);
  const cert = await Bun.file(
    new URL("../../../../fixtures/salesforce-transport/leaf.pem", import.meta.url),
  ).text();
  const created = await control({
    body: {
      providerId,
      issuer: "https://sp.example.test/entity",
      domain: "company.test",
      samlConfig: {
        ...(binding === "custom-sp"
          ? { spMetadata: customSPMetadata(ctx.baseURL, providerId) }
          : {}),
        entryPoint:
          binding === "xml-idp"
            ? "https://unused.example.test/sso"
            : "https://idp.example.test/sso",
        cert:
          binding === "xml-idp"
            ? undefined
            : rollover
              ? [
                  await Bun.file(
                    new URL("../../../../fixtures/passkey-attestation/ca.pem", import.meta.url),
                  ).text(),
                  cert,
                ]
              : cert,
        idpMetadata:
          binding === "xml-idp"
            ? idpXMLMetadata(cert)
            : {
                entityID: "https://idp.example.test/entity",
                singleLogoutService: [
                  {
                    Binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
                    Location: "https://idp.example.test/logout",
                  },
                ],
              },
        wantAssertionsSigned: true,
      },
    },
    headers: { cookie: pairs(owner) },
  });
  expect(created.status).toBe(200);
  const started = await control({
    action: "sign-in",
    body: { providerId, callbackURL: `${ctx.baseURL}/complete` },
  });
  expect(started.status).toBe(200);
  const email = ctx.uniqueEmail("saml-logout-user");
  const grant = (await (
    await control({
      action: "saml-grant",
      authorization: ((await started.json()) as any).url,
      email,
    })
  ).json()) as any;
  const completed = await control({
    action: "acs",
    params: { providerId },
    body: grant,
    headers: {},
  });
  expect(completed.status).toBe(302);
  expect(completed.headers.get("location")).toBe(`${ctx.baseURL}/complete`);
  const cookie = pairs(completed);
  const authenticated = (await (
    await control({ action: "session", headers: { cookie } })
  ).json()) as any;
  expect(authenticated.user.email).toBe(email);
  const session = authenticated.session;
  const key = `saml-session:${providerId}:${email}`;
  const lookup = `saml-session-by-id:${session.id}`;
  const row = (await (await control({ action: "proof", identifier: key })).json()) as any;
  expect(row).not.toBe(null);
  const data = JSON.parse(row.value);
  expect(data.sessionId).toBe(session.id);
  expect(data.sessionToken).toBe(session.token);
  expect(data.sessionIndex).toBe("session-index");
  expect(data.nameID).toBe(email);
  expect(
    ((await (await control({ action: "proof", identifier: lookup })).json()) as any).value,
  ).toBe(key);
  if (["local-api", "local-http", "local-disabled"].includes(binding)) {
    const signedOut = await control({
      action: binding === "local-http" ? "sign-out-http" : "sign-out-api",
      ...(binding === "local-disabled" ? { mode: "default" } : {}),
      headers: { cookie, ...(binding === "local-http" ? { origin: ctx.baseURL } : {}) },
      body: {},
    });
    expect(signedOut.status).toBe(200);
    expect(await signedOut.json()).toEqual({ success: true });
    const tracking = await (await control({ action: "proof", identifier: key })).json();
    const reverse = (await (await control({ action: "proof", identifier: lookup })).json()) as any;
    if (binding === "local-disabled") {
      expect(tracking).toEqual(row);
      expect(reverse.value).toBe(key);
    } else {
      expect(tracking).toBe(null);
      expect(reverse).toBe(null);
    }
    expect(await (await control({ action: "session", headers: { cookie } })).json()).toBe(null);
    const retained = (await (
      await control({ action: "session", headers: { cookie: pairs(owner) } })
    ).json()) as any;
    expect(retained.user.email).toBe(((await owner.clone().json()) as any).user.email);
    return { binding, retired: true };
  }
  const before = Date.now();
  const output = await control({
    action: "initiate-slo",
    params: { providerId },
    body: { callbackURL: `${ctx.baseURL}/logged-out` },
    headers: { cookie },
  });
  const after = Date.now();
  expect(output.status, await output.clone().text()).toBe(302);
  const url = new URL(output.headers.get("location")!);
  expect(url.origin).toBe("https://idp.example.test");
  expect(url.pathname).toBe("/logout");
  expect(url.searchParams.has("RelayState")).toBe(false);
  const xml = inflateRawSync(
    Buffer.from(url.searchParams.get("SAMLRequest")!, "base64"),
  ).toString();
  expect(XMLValidator.validate(xml)).toBe(true);
  const request = new XMLParser({
    ignoreAttributes: false,
    parseAttributeValue: false,
    removeNSPrefix: true,
  }).parse(xml).LogoutRequest;
  expect(request["@_Destination"]).toBe("https://idp.example.test/logout");
  expect(request["@_Version"]).toBe("2.0");
  expect(request["@_ID"]).toMatch(/^_[0-9a-f-]{36}$/);
  expect(Date.parse(request["@_IssueInstant"])).toBeGreaterThanOrEqual(before);
  expect(Date.parse(request["@_IssueInstant"])).toBeLessThanOrEqual(after);
  expect(request.Issuer).toBe(
    binding === "custom-sp" ? "https://sp.example.test/from-xml" : "https://sp.example.test/entity",
  );
  expect(request.NameID["@_Format"]).toBe(
    binding === "custom-sp"
      ? "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
      : "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
  );
  expect(request.NameID["#text"]).toBe(email);
  expect(request.SessionIndex).toBe("session-index");
  const proof = (await (
    await control({ action: "proof", identifier: `saml-logout-request:${request["@_ID"]}` })
  ).json()) as any;
  expect(proof.value).toBe("logout-provider");
  expect(Date.parse(proof.expiresAt)).toBeGreaterThanOrEqual(before + 300000);
  expect(Date.parse(proof.expiresAt)).toBeLessThanOrEqual(after + 300000);
  expect(await (await control({ action: "proof", identifier: key })).json()).toBe(null);
  expect(await (await control({ action: "proof", identifier: lookup })).json()).toBe(null);
  expect(await (await control({ action: "session", headers: { cookie } })).json()).toBe(null);
  expect(
    output.headers
      .getSetCookie()
      .some((raw) => raw.startsWith("better-auth.session_token=") && raw.includes("Max-Age=0")),
  ).toBe(true);
  if (complete) {
    const responseXml = `<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_idp-logout-response" Version="2.0" IssueInstant="${new Date().toISOString()}" InResponseTo="${request["@_ID"]}"><saml:Issuer>https://idp.example.test/entity</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status></samlp:LogoutResponse>`;
    let response = Buffer.from(responseXml).toString("base64");
    if (signed) {
      const sign = async (wrongKey: boolean) =>
        (
          (await (
            await control({ action: "sign-saml-logout", xml: responseXml, wrongKey })
          ).json()) as any
        ).SAMLResponse as string;
      for (const rejectedResponse of [response, await sign(true)]) {
        const rejected = await control({
          action: "slo",
          params: { providerId },
          body: { SAMLResponse: rejectedResponse },
          headers: {},
        });
        expect(rejected.status).toBe(400);
        expect(
          await (
            await control({ action: "proof", identifier: `saml-logout-request:${request["@_ID"]}` })
          ).json(),
        ).toEqual(proof);
      }
      response = await sign(false);
      const rejectedRedirect = await control({
        action: "slo-http",
        method: "GET",
        params: { providerId },
        query: {
          SAMLResponse: deflateRawSync(Buffer.from(response, "base64")).toString("base64"),
          SigAlg: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
          Signature: "AA==",
        },
        headers: { origin: "https://idp.example.test" },
      });
      expect(rejectedRedirect.status).toBe(400);
      expect(
        await (
          await control({ action: "proof", identifier: `saml-logout-request:${request["@_ID"]}` })
        ).json(),
      ).toEqual(proof);
    }
    if (binding === "post-optional-signature") {
      response = (
        (await (
          await control({ action: "sign-saml-logout", xml: responseXml, wrongKey: true })
        ).json()) as any
      ).SAMLResponse;
    }
    const completeInput =
      binding === "redirect"
        ? {
            action: "slo-http",
            method: "GET",
            params: { providerId },
            query: {
              SAMLResponse: deflateRawSync(responseXml).toString("base64"),
              RelayState: "https://attacker.example/steal",
              SigAlg: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
              Signature: "AA==",
            },
            headers: { origin: "https://idp.example.test" },
          }
        : {
            action: "slo",
            params: { providerId },
            body: { SAMLResponse: response, RelayState: "https://attacker.example/steal" },
            headers: {},
          };
    const completedLogout = await control(completeInput);
    expect(completedLogout.status).toBe(302);
    expect(completedLogout.headers.get("location")).toBe(ctx.baseURL);
    expect(
      await (
        await control({ action: "proof", identifier: `saml-logout-request:${request["@_ID"]}` })
      ).json(),
    ).toBe(null);
    const repeated = await control(completeInput);
    expect(repeated.status).toBe(302);
  }
  return {
    issuer: request.Issuer,
    version: request["@_Version"],
    destination: request["@_Destination"],
    nameID: request.NameID,
    index: request.SessionIndex,
    retired: true,
  };
}
