import { expect } from "bun:test";

import { XMLParser } from "fast-xml-parser";
import { Cookie } from "tough-cookie";

import type { ScenarioContext } from "../../../support/scenario";
export async function idpLogoutFlow(
  ctx: ScenarioContext,
  signature: "absent" | "required" | "ignored",
  http = false,
) {
  const signed = signature === "required";
  const actor = ctx.actor();
  const control = (input: Record<string, unknown>) =>
    actor.fetch(`${ctx.baseURL}/__test/server-api/sso`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ ...input, mode: signed ? "signed-request-slo" : "slo" }),
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
      email: ctx.uniqueEmail("idp-logout-owner"),
      name: "Native owner",
      password: "password123",
    },
  });
  expect(owner.status).toBe(200);
  const cert = await Bun.file(
    new URL("../../../../fixtures/salesforce-transport/leaf.pem", import.meta.url),
  ).text();
  expect(
    (
      await control({
        body: {
          providerId: "idp-logout-provider",
          issuer: "https://sp.example.test/entity",
          domain: "company.test",
          samlConfig: {
            entryPoint: "https://idp.example.test/sso",
            cert,
            idpMetadata: {
              entityID: "https://idp.example.test/entity",
              singleLogoutService: [
                {
                  Binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
                  Location: "https://idp.example.test/logout-post",
                },
              ],
            },
            wantAssertionsSigned: true,
          },
        },
        headers: { cookie: pairs(owner) },
      })
    ).status,
  ).toBe(200);
  const observations = [];
  for (const matching of [true, false]) {
    const email = ctx.uniqueEmail(matching ? "matched-logout" : "mismatched-logout");
    const started = await control({
      action: "sign-in",
      body: { providerId: "idp-logout-provider", callbackURL: `${ctx.baseURL}/complete` },
    });
    expect(started.status).toBe(200);
    const grant = (await (
      await control({
        action: "saml-grant",
        authorization: ((await started.json()) as any).url,
        email,
      })
    ).json()) as any;
    const loggedIn = await control({
      action: "acs",
      params: { providerId: "idp-logout-provider" },
      body: grant,
      headers: {},
    });
    expect(loggedIn.status).toBe(302);
    const cookie = pairs(loggedIn);
    const session = (
      (await (await control({ action: "session", headers: { cookie } })).json()) as any
    ).session;
    const requestId = matching ? "_idp-matching-request" : "_idp-mismatched-request";
    const index = matching ? "session-index" : "another-session";
    const xml = `<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="${requestId}" Version="2.0" IssueInstant="${new Date().toISOString()}"><saml:Issuer>https://idp.example.test/entity</saml:Issuer><saml:NameID>${email}</saml:NameID><samlp:SessionIndex>${index}</samlp:SessionIndex></samlp:LogoutRequest>`;
    let encodedRequest = Buffer.from(xml).toString("base64");
    if (signed) {
      const tracking = await (
        await control({ action: "proof", identifier: `saml-session:idp-logout-provider:${email}` })
      ).json();
      const sign = async (wrongKey: boolean) =>
        ((await (await control({ action: "sign-saml-logout", xml, wrongKey })).json()) as any)
          .SAMLResponse as string;
      for (const rejectedData of [encodedRequest, await sign(true)]) {
        const rejected = await control({
          action: "slo",
          params: { providerId: "idp-logout-provider" },
          body: { SAMLRequest: rejectedData },
          headers: {},
        });
        expect(rejected.status).toBe(400);
        expect(
          await (
            await control({
              action: "proof",
              identifier: `saml-session:idp-logout-provider:${email}`,
            })
          ).json(),
        ).toEqual(tracking);
        const retained = (await (
          await control({ action: "session", headers: { cookie } })
        ).json()) as any;
        expect(retained.session.id).toBe(session.id);
      }
      encodedRequest = await sign(false);
    }
    if (signature === "ignored") {
      encodedRequest = (
        (await (await control({ action: "sign-saml-logout", xml, wrongKey: true })).json()) as any
      ).SAMLResponse;
    }
    const response = await control({
      action: http ? "slo-http" : "slo",
      params: { providerId: "idp-logout-provider" },
      body: { SAMLRequest: encodedRequest, RelayState: "opaque-relay" },
      headers: http ? { origin: "https://idp.example.test" } : {},
    });
    expect(response.status, await response.clone().text()).toBe(200);
    expect(response.headers.get("content-type")).toBe("text/html");
    const html = await response.text();
    expect(html).toContain('action="https://idp.example.test/logout-post"');
    expect(html).toContain('name="RelayState" value="opaque-relay"');
    const encoded = html.split('name="SAMLResponse" value="')[1]!.split('"')[0]!;
    const parsed = new XMLParser({
      ignoreAttributes: false,
      parseAttributeValue: false,
      removeNSPrefix: true,
    }).parse(Buffer.from(encoded, "base64").toString()).LogoutResponse;
    expect(parsed["@_InResponseTo"]).toBe(requestId);
    expect(parsed["@_Destination"]).toBe("https://idp.example.test/logout-post");
    const current = await (await control({ action: "session", headers: { cookie } })).json();
    expect(current === null).toBe(matching);
    expect(
      await (
        await control({
          action: "proof",
          identifier: `saml-session:idp-logout-provider:${email}`,
        })
      ).json(),
    ).toBe(null);
    expect(
      (await (
        await control({ action: "proof", identifier: `saml-session-by-id:${session.id}` })
      ).json()) === null,
    ).toBe(matching);
    observations.push({
      matching,
      retired: current === null,
      responseTo: parsed["@_InResponseTo"],
      issuer: parsed.Issuer,
      destination: parsed["@_Destination"],
      status: parsed.Status,
    });
  }
  return observations;
}
