import { readFile as readFixtureFile } from "node:fs/promises";

import { Cookie } from "tough-cookie";
import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";

compatScenario(
  "SSO validates protocol provenance before creating or admitting identity",
  async (ctx) => {
    const actor = ctx.actor();
    const control = (input: Record<string, unknown>) =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/sso`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ ...input, mode: "validation" }),
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
        email: ctx.uniqueEmail("sso-validation-owner"),
        name: "Native owner",
        password: "password123",
      },
    });
    expect(owner.status).toBe(200);
    const cert = await readFixtureFile(
      new URL("../../../../fixtures/salesforce-transport/leaf.pem", import.meta.url),
      "utf8",
    );
    const observed = [];
    for (const saml of [false, true]) {
      await control({ action: "validation-reset" });
      const providerId = saml ? "validation-saml-provider" : "validation-oidc-provider";
      const email = ctx.uniqueEmail(saml ? "saml-validation-user" : "oidc-validation-user");
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
      let established = "";
      for (const deny of [false, true]) {
        await control({ action: "validation-deny", enabled: deny });
        const started = await control({
          action: "sign-in",
          body: {
            providerId,
            callbackURL: `${ctx.baseURL}/complete`,
            errorCallbackURL: `${ctx.baseURL}/failed`,
          },
        });
        expect(started.status).toBe(200);
        let input: any;
        if (saml) {
          const grant = await (
            await control({
              action: "saml-grant",
              authorization: ((await started.json()) as any).url,
              email,
            })
          ).json();
          input = { action: "acs", params: { providerId }, body: grant };
        } else {
          const grant = await fetch(((await started.json()) as any).url, { redirect: "manual" });
          expect(grant.status).toBe(302);
          input = {
            action: "callback",
            params: { providerId },
            query: Object.fromEntries(new URL(grant.headers.get("location")!).searchParams),
          };
        }
        const completed = await control({ ...input, headers: { cookie: cookies(started) } });
        expect(completed.status).toBe(302);
        const location = new URL(completed.headers.get("location")!);
        if (deny) {
          expect(location.pathname).toBe("/failed");
          expect(location.searchParams.get("error")).toBe("sso_validation_denied");
          expect(location.searchParams.get("error_description")).toBe("SSO identity rejected");
        } else {
          expect(location.pathname).toBe("/complete");
          established = cookies(completed);
        }
        const session = (await (
          await control({ action: "session", headers: { cookie: established } })
        ).json()) as any;
        expect(session.user.name).toBe("Policy SSO user");
      }
      const events = (await (await control({ action: "validation-events" })).json()) as any[];
      expect(events).toHaveLength(2);
      for (const [index, action] of ["create-user", "sign-in"].entries()) {
        const event = events[index];
        expect(event.source.method).toBe(saml ? "sso-saml" : "sso-oidc");
        expect(event.source.action).toBe(action);
        expect(event.source.sso.providerId).toBe(providerId);
        expect(event.source.oauth).toBeUndefined();
        expect(event.source.sso.profile.email).toBe(email);
        expect(event.name).toBe("SSO employee");
        expect(event.requestPresent).toBe(false);
        expect(event.path).toBe(
          saml ? "/sso/saml2/sp/acs/:providerId" : "/sso/callback/:providerId",
        );
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
      observed.push(events);
    }
    return observed;
  },
);
