import { Cookie } from "tough-cookie";
import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "Configured SSO providers bind OIDC and SAML login without provider rows",
  async (ctx) => {
    const actor = ctx.actor();
    const control = (input: Record<string, unknown>) =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/sso`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ ...input, mode: "configured" }),
        redirect: "manual",
      });
    const cookies = (response: Response) =>
      response.headers
        .getSetCookie()
        .filter((raw) => Boolean(Cookie.parse(raw)?.value))
        .map((raw) => raw.split(";")[0])
        .join("; ");
    const observed = [];
    for (const saml of [false, true]) {
      const providerId = saml ? "configured-saml" : "configured-oidc";
      expect(await (await control({ action: "row", providerId })).json()).toBe(null);
      const email = `${ctx.uniqueEmail(`configured-${saml}`).split("@")[0]}@engineering.${saml ? "saml" : "oidc"}.company.test`;
      await control({
        action: "idp",
        profile: {
          sub: "configured-subject",
          email,
          email_verified: false,
          name: "Configured employee",
        },
      });
      for (const byDomain of [false, true]) {
        const started = await control({
          action: "sign-in",
          body: {
            callbackURL: `${ctx.baseURL}/complete`,
            errorCallbackURL: `${ctx.baseURL}/failed`,
            ...(byDomain ? { email } : { providerId }),
          },
        });
        expect(started.status).toBe(200);
        const authorization = ((await started.json()) as any).url;
        let input: any;
        let state: string;
        if (saml) {
          const grant = (await (
            await control({ action: "saml-grant", authorization, email })
          ).json()) as any;
          state = grant.RelayState;
          input = { action: "acs", params: { providerId }, body: grant };
        } else {
          const grant = await fetch(authorization, { redirect: "manual" });
          expect(grant.status).toBe(302);
          const query = Object.fromEntries(new URL(grant.headers.get("location")!).searchParams);
          state = query.state!;
          input = { action: "callback", params: { providerId }, query };
        }
        const proof = (await (
          await control({ action: "proof", identifier: `auth-state:${state}` })
        ).json()) as any;
        const payload = JSON.parse(proof.value);
        expect(payload.serverContext.ssoProviderReference.source).toEqual({ type: "configured" });
        const completed = await control({ ...input, headers: { cookie: cookies(started) } });
        expect(completed.status).toBe(302);
        expect(completed.headers.get("location")).toBe(`${ctx.baseURL}/complete`);
        const session = (await (
          await control({ action: "session", headers: { cookie: cookies(completed) } })
        ).json()) as any;
        expect(session.user.email).toBe(email);
        expect(
          await (
            await control({
              action: "account-row",
              providerId,
              accountId: saml ? email : "configured-subject",
            })
          ).json(),
        ).not.toBe(null);
        expect(await (await control({ action: "row", providerId })).json()).toBe(null);
        observed.push({
          saml,
          byDomain,
          source: payload.serverContext.ssoProviderReference.source,
        });
      }
      if (saml) {
        const metadata = await control({ action: "sp-metadata", query: { providerId } });
        expect(metadata.status).toBe(200);
        expect(await metadata.text()).toContain("https://sp.example.test/entity");
      }
    }
    const owner = await control({
      action: "signup",
      body: { email: ctx.uniqueEmail("configured-owner"), name: "Owner", password: "password123" },
    });
    expect(owner.status).toBe(200);
    const idp = (await (await control({ action: "idp" })).json()) as any;
    const rejected = await control({
      headers: { cookie: cookies(owner) },
      body: {
        providerId: "configured-oidc",
        issuer: idp.base,
        domain: "oidc.company.test",
        oidcConfig: {
          clientId: "enterprise-client",
          clientSecret: "stored-secret",
          skipDiscovery: true,
        },
      },
    });
    expect(rejected.status).toBe(422);
    expect(await rejected.json()).toEqual({
      message: "This providerId is reserved and cannot be used for an SSO provider",
    });
    return observed;
  },
);
