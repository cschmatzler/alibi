import { expect } from "bun:test";

import { Cookie } from "tough-cookie";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "SSO provisioning observes first and every successful OIDC and SAML login",
  async (ctx) => {
    const actor = ctx.actor();
    const cookies = (response: Response) =>
      response.headers
        .getSetCookie()
        .filter((raw) => Boolean(Cookie.parse(raw)?.value))
        .map((raw) => raw.split(";")[0])
        .join("; ");
    const cert = await Bun.file(
      new URL("../../../../fixtures/salesforce-transport/leaf.pem", import.meta.url),
    ).text();
    const observed = [];
    for (const every of [false, true]) {
      const control = (input: Record<string, unknown>) =>
        actor.fetch(`${ctx.baseURL}/__test/server-api/sso`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ ...input, mode: every ? "provisioning-every" : "provisioning" }),
          redirect: "manual",
        });
      const owner = await control({
        action: "signup",
        body: {
          email: ctx.uniqueEmail(`provision-owner-${every}`),
          name: "Owner",
          password: "password123",
        },
      });
      expect(owner.status).toBe(200);
      for (const saml of [false, true]) {
        await control({ action: "provisioning-reset" });
        const providerId = `provision-${every}-${saml}`;
        const email = ctx.uniqueEmail(providerId);
        const idp = (await (await control({ action: "idp", email })).json()) as any;
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
        expect(await (await control({ action: "provisioning-events" })).json()).toEqual([]);
        let userId = "";
        for (const index of [0, 1]) {
          const started = await control({
            action: "sign-in",
            body: { providerId, callbackURL: `${ctx.baseURL}/complete` },
          });
          expect(started.status).toBe(200);
          expect(await (await control({ action: "provisioning-events" })).json()).toHaveLength(
            index === 0 ? 0 : 1,
          );
          const authorization = ((await started.json()) as any).url;
          let input: any;
          if (saml) {
            input = {
              action: "acs",
              params: { providerId },
              body: await (await control({ action: "saml-grant", authorization, email })).json(),
            };
          } else {
            const grant = await fetch(authorization, { redirect: "manual" });
            expect(grant.status).toBe(302);
            input = {
              action: "callback",
              params: { providerId },
              query: Object.fromEntries(new URL(grant.headers.get("location")!).searchParams),
            };
          }
          const completed = await control({ ...input, headers: { cookie: cookies(started) } });
          expect(completed.status).toBe(302);
          expect(new URL(completed.headers.get("location")!).pathname).toBe("/complete");
          const session = (await (
            await control({ action: "session", headers: { cookie: cookies(completed) } })
          ).json()) as any;
          expect(session.user.email).toBe(email);
          if (index === 0) {
            userId = session.user.id;
          } else {
            expect(session.user.id).toBe(userId);
          }
          const events = (await (await control({ action: "provisioning-events" })).json()) as any[];
          expect(events).toHaveLength(every ? index + 1 : 1);
          for (const event of events) {
            expect(event.userId).toBe(userId);
            expect(event.email).toBe(email);
            expect(event.providerId).toBe(providerId);
            expect(event.userInfo.id).toBe(saml ? email : "employee-subject");
            expect(event.userInfo.email).toBe(email);
            expect(event.userInfo.name).toBe("SSO employee");
            expect(event.tokenPresent).toBe(!saml);
            if (saml) {
              expect(event.accessToken).toBe(null);
            } else {
              expect(event.accessToken.length).toBeGreaterThan(0);
            }
          }
          expect(
            await (
              await control({
                action: "account-row",
                providerId,
                accountId: saml ? email : "employee-subject",
              })
            ).json(),
          ).not.toBe(null);
        }
        observed.push({
          every,
          saml,
          count: ((await (await control({ action: "provisioning-events" })).json()) as any[])
            .length,
        });
      }
    }
    return observed;
  },
);
