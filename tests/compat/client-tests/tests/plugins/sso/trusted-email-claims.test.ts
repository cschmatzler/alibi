import { expect } from "bun:test";

import { Cookie } from "tough-cookie";

import { compatScenario } from "../../../support/scenario";

compatScenario(
  "Trusted SSO verification accepts only exact true claims from UserInfo and signed ID tokens",
  async (ctx) => {
    const actor = ctx.actor();
    const control = (input: Record<string, unknown>) =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/sso`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ ...input, mode: "trusted-claims" }),
        redirect: "manual",
      });
    const cookies = (response: Response) =>
      response.headers
        .getSetCookie()
        .filter((raw) => Boolean(Cookie.parse(raw)?.value))
        .map((raw) => raw.split(";")[0])
        .join("; ");
    const idp = (await (await control({ action: "idp" })).json()) as any;
    const owner = await control({
      action: "signup",
      body: {
        email: ctx.uniqueEmail("trusted-claims-owner"),
        name: "Native owner",
        password: "password123",
      },
    });
    expect(owner.status).toBe(200);
    const cases: Array<[unknown, boolean]> = [
      [true, true],
      ["true", true],
      [false, false],
      ["false", false],
      ["TRUE", false],
      [1, false],
      [[true], false],
      [{}, false],
    ];
    const observed = [];
    for (const jwt of [false, true]) {
      const providerId = jwt ? "trusted-id-token-provider" : "trusted-userinfo-provider";
      const oidcConfig: any = {
        clientId: "enterprise-client",
        clientSecret: "stored-secret",
        skipDiscovery: true,
        authorizationEndpoint: `${idp.base}/authorize`,
        tokenEndpoint: `${idp.base}/token`,
        jwksEndpoint: `${idp.base}/jwks`,
      };
      if (!jwt) oidcConfig.userInfoEndpoint = `${idp.base}/userinfo`;
      expect(
        (
          await control({
            headers: { cookie: cookies(owner) },
            body: { providerId, issuer: idp.base, domain: "example.test", oidcConfig },
          })
        ).status,
      ).toBe(200);
      for (const [index, [claim, expected]] of cases.entries()) {
        const email = ctx.uniqueEmail(`trusted-${jwt}-${index}`);
        await control({
          action: "idp",
          idTokenCase: jwt ? "valid" : "none",
          profile: {
            sub: `trusted-${jwt}-${index}`,
            email,
            name: "SSO employee",
            email_verified: claim,
          },
        });
        const started = await control({
          action: "sign-in",
          body: { providerId, callbackURL: `${ctx.baseURL}/complete` },
        });
        expect(started.status).toBe(200);
        const grant = await fetch(((await started.json()) as any).url, { redirect: "manual" });
        expect(grant.status).toBe(302);
        const query = Object.fromEntries(new URL(grant.headers.get("location")!).searchParams);
        const completed = await control({
          action: "callback",
          params: { providerId },
          query,
          headers: { cookie: cookies(started) },
        });
        expect(completed.status).toBe(302);
        expect(completed.headers.get("location")).toBe(`${ctx.baseURL}/complete`);
        const session = (await (
          await control({ action: "session", headers: { cookie: cookies(completed) } })
        ).json()) as any;
        expect(session.user.email).toBe(email);
        expect(session.user.emailVerified).toBe(expected);
        observed.push({ jwt, index, verified: session.user.emailVerified });
      }
    }
    return observed;
  },
);
