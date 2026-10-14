import { expect } from "bun:test";

import { Cookie } from "tough-cookie";

import { compatScenario } from "../../../support/scenario";

compatScenario(
  "SSO verified domain links existing subdomain accounts and denies foreign email",
  async (ctx) => {
    const actor = ctx.actor();
    const control = (input: Record<string, unknown>) =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/sso`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ ...input, mode: "domain" }),
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
        email: ctx.uniqueEmail("domain-link-owner"),
        name: "Owner",
        password: "password123",
      },
    });
    expect(owner.status).toBe(200);
    const cert = await Bun.file(
      new URL("../../../../fixtures/salesforce-transport/leaf.pem", import.meta.url),
    ).text();
    const observed = [];
    for (const saml of [false, true]) {
      const providerId = saml ? "domain-link-saml" : "domain-link-oidc";
      const idp = (await (await control({ action: "idp" })).json()) as any;
      const body = saml
        ? {
            providerId,
            issuer: "https://sp.example.test/entity",
            domain: "company.test",
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
            domain: "company.test",
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
      const created = await control({ body, headers: { cookie: cookies(owner) } });
      expect(created.status).toBe(200);
      const token = ((await created.json()) as any).domainVerificationToken;
      expect(
        (
          await control({
            action: "dns-records",
            records: [[`_better-auth-token-${providerId}=${token}`]],
          })
        ).status,
      ).toBe(200);
      const verified = await control({
        action: "verify-domain",
        body: { providerId },
        headers: { cookie: cookies(owner) },
      });
      expect(verified.status).toBe(204);
      expect(
        ((await (await control({ action: "row", providerId })).json()) as any).domainVerified,
      ).toBe(true);
      for (const [index, domain] of [
        "company.test",
        "engineering.company.test",
        "notcompany.test",
      ].entries()) {
        const email = `${ctx.uniqueEmail(`domain-link-${saml}-${index}`).split("@")[0]}@${domain}`;
        const existing = await control({
          action: "signup",
          body: { email, name: "Existing employee", password: "password123" },
        });
        expect(existing.status).toBe(200);
        const existingId = ((await existing.json()) as any).user.id;
        const accountId = saml ? email : `domain-link-${index}`;
        await control({
          action: "idp",
          profile: { sub: accountId, email, email_verified: false, name: "SSO employee" },
        });
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
        const account = (await (
          await control({ action: "account-row", providerId, accountId })
        ).json()) as any;
        if (index === 2) {
          expect(location.searchParams.get("error")).toBe(
            saml ? "account_not_linked" : "account not linked",
          );
          expect(account).toBe(null);
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
            await control({ action: "session", headers: { cookie: cookies(completed) } })
          ).json()) as any;
          expect(session.user.id).toBe(existingId);
          expect(account.userId).toBe(existingId);
        }
        observed.push({ saml, index, error: location.searchParams.get("error") });
      }
    }
    return observed;
  },
);
