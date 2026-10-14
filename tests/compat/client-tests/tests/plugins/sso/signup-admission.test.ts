import { expect } from "bun:test";

import { Cookie } from "tough-cookie";

import { compatScenario } from "../../../support/scenario";

compatScenario(
  "SSO signup admission blocks implicit identity and honors only protected OIDC requests",
  async (ctx) => {
    const actor = ctx.actor();
    const control = (input: Record<string, unknown>, mode = "default") =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/sso`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ ...input, mode }),
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
      body: {
        email: ctx.uniqueEmail("signup-policy-owner"),
        name: "Native owner",
        password: "password123",
      },
    });
    expect(owner.status).toBe(200);
    const cert = await Bun.file(
      new URL("../../../../fixtures/salesforce-transport/leaf.pem", import.meta.url),
    ).text();
    const observed = [];
    for (const saml of [false, true]) {
      const providerId = saml ? "signup-saml-provider" : "signup-oidc-provider";
      const idp = (await (await control({ action: "idp" })).json()) as any;
      const body = saml
        ? {
            providerId,
            issuer: "https://sp.example.test/entity",
            domain: "example.test",
            samlConfig: {
              entryPoint: "https://idp.example.test/sso",
              cert,
              idpMetadata: { entityID: "https://idp.example.test/entity" },
              wantAssertionsSigned: true,
            },
          }
        : {
            providerId,
            issuer: idp.base,
            domain: "example.test",
            oidcConfig: {
              clientId: "enterprise-client",
              clientSecret: "stored-secret",
              skipDiscovery: true,
              authorizationEndpoint: `${idp.base}/authorize`,
              tokenEndpoint: `${idp.base}/token`,
              jwksEndpoint: `${idp.base}/jwks`,
              userInfoEndpoint: `${idp.base}/userinfo`,
            },
          };
      expect((await control({ body, headers: { cookie: cookies(owner) } })).status).toBe(200);
      const existingEmail = ctx.uniqueEmail(`signup-existing-${saml}`);
      for (let index = 0; index < 4; index++) {
        const mode = index === 0 ? "default" : "no-signup";
        const requestSignUp = index === 3;
        const email = index <= 1 ? existingEmail : ctx.uniqueEmail(`signup-${saml}-${index}`);
        const accountId = saml ? email : `signup-${saml}-${index <= 1 ? 0 : index}`;
        await control(
          {
            action: "idp",
            profile: { sub: accountId, email, email_verified: true, name: "SSO employee" },
          },
          mode,
        );
        const started = await control(
          {
            action: "sign-in",
            body: {
              providerId,
              callbackURL: `${ctx.baseURL}/complete`,
              errorCallbackURL: `${ctx.baseURL}/failed`,
              requestSignUp,
            },
          },
          mode,
        );
        expect(started.status).toBe(200);
        let input: any;
        if (saml) {
          const grant = await (
            await control(
              { action: "saml-grant", authorization: ((await started.json()) as any).url, email },
              mode,
            )
          ).json();
          input = { action: "acs", params: { providerId }, body: grant };
        } else {
          const grant = await fetch(((await started.json()) as any).url, { redirect: "manual" });
          expect(grant.status).toBe(302);
          const query = Object.fromEntries(new URL(grant.headers.get("location")!).searchParams);
          query.requestSignUp = "true";
          input = { action: "callback", params: { providerId }, query };
        }
        const completed = await control({ ...input, headers: { cookie: cookies(started) } }, mode);
        expect(completed.status).toBe(302);
        const location = new URL(completed.headers.get("location")!);
        const denied = index === 2 || (saml && index === 3);
        if (denied) {
          expect(location.searchParams.get("error")).toBe(
            saml ? "signup_disabled" : "signup disabled",
          );
          expect(location.pathname).toBe(saml ? "/complete" : "/failed");
          expect(
            await (await control({ action: "account-row", providerId, accountId }, mode)).json(),
          ).toBe(null);
          expect(await (await control({ action: "user-row", email }, mode)).json()).toBe(null);
          expect(
            completed.headers
              .getSetCookie()
              .some(
                (raw) =>
                  raw.startsWith("better-auth.session_token=") && Boolean(Cookie.parse(raw)?.value),
              ),
          ).toBe(false);
        } else {
          expect(location.searchParams.has("error")).toBe(false);
          const session = (await (
            await control({ action: "session", headers: { cookie: cookies(completed) } }, mode)
          ).json()) as any;
          expect(session.user.email).toBe(email);
          expect(
            await (await control({ action: "account-row", providerId, accountId }, mode)).json(),
          ).not.toBe(null);
        }
        observed.push({
          saml,
          index,
          path: location.pathname,
          error: location.searchParams.get("error"),
        });
      }
    }
    return observed;
  },
);
