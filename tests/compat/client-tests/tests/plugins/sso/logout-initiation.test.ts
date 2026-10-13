import { expect } from "bun:test";
import { inflateRawSync } from "node:zlib";

import { XMLParser, XMLValidator } from "fast-xml-parser";
import { Cookie } from "tough-cookie";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "SAML logout uses ACS session indexes and retires the actual session",
  async (ctx) => {
    const actor = ctx.actor();
    const control = (input: Record<string, unknown>) =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/sso`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ ...input, mode: "slo" }),
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
        providerId: "logout-provider",
        issuer: "https://sp.example.test/entity",
        domain: "company.test",
        samlConfig: {
          entryPoint: "https://idp.example.test/sso",
          cert,
          idpMetadata: {
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
      body: { providerId: "logout-provider", callbackURL: `${ctx.baseURL}/complete` },
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
      params: { providerId: "logout-provider" },
      body: grant,
      headers: {},
    });
    expect(completed.status).toBe(302);
    const cookie = pairs(completed);
    const authenticated = (await (
      await control({ action: "session", headers: { cookie } })
    ).json()) as any;
    expect(authenticated.user.email).toBe(email);
    const session = authenticated.session;
    const key = `saml-session:logout-provider:${email}`;
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
    const before = Date.now();
    const output = await control({
      action: "initiate-slo",
      params: { providerId: "logout-provider" },
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
    expect(request.Issuer).toBe("https://sp.example.test/entity");
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
    return {
      issuer: request.Issuer,
      version: request["@_Version"],
      destination: request["@_Destination"],
      nameID: request.NameID,
      index: request.SessionIndex,
      retired: true,
    };
  },
);
