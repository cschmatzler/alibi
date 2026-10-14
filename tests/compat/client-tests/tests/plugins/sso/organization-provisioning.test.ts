import { expect } from "bun:test";

import { Cookie } from "tough-cookie";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "SSO organization provisioning honors role policies and pending invitations",
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
    for (const mode of ["dynamic", "default", "admin", "disabled", "invitation"]) {
      const control = (input: Record<string, unknown>) =>
        actor.fetch(`${ctx.baseURL}/__test/server-api/sso`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            ...input,
            mode: `org-${mode}`,
          }),
          redirect: "manual",
        });
      const owner = await control({
        action: "signup",
        body: {
          email: ctx.uniqueEmail(`org-owner-${mode}`),
          name: "Owner",
          password: "password123",
        },
      });
      expect(owner.status).toBe(200);
      const headers = { cookie: cookies(owner) };
      const organizationResponse = await control({
        action: "org-create",
        headers,
        body: { name: "SSO company", slug: `sso-${mode}` },
      });
      expect(organizationResponse.status).toBe(200);
      const organizationId = ((await organizationResponse.json()) as any).id;
      for (const saml of [false, true]) {
        await control({ action: "role-reset" });
        const providerId = `org-${mode}-${saml}`;
        const email = ctx.uniqueEmail(providerId);
        const idp = (await (await control({ action: "idp", email })).json()) as any;
        if (mode === "invitation") {
          const invitation = await control({
            action: "org-invite",
            headers,
            body: { organizationId, email, role: "admin" },
          });
          expect(invitation.status).toBe(200);
          expect(((await invitation.json()) as any).status).toBe("pending");
        }
        const body = saml
          ? {
              providerId,
              organizationId,
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
              organizationId,
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
        expect((await control({ body, headers })).status).toBe(200);
        let memberId = "";
        let firstUserId = "";
        for (const index of [0, 1]) {
          const started = await control({
            action: "sign-in",
            body: { providerId, callbackURL: `${ctx.baseURL}/complete` },
          });
          expect(started.status).toBe(200);
          const authorization = ((await started.json()) as any).url;
          let callback: any;
          if (saml) {
            callback = {
              action: "acs",
              params: { providerId },
              body: await (await control({ action: "saml-grant", authorization, email })).json(),
            };
          } else {
            const grant = await fetch(authorization, { redirect: "manual" });
            expect(grant.status).toBe(302);
            callback = {
              action: "callback",
              params: { providerId },
              query: Object.fromEntries(new URL(grant.headers.get("location")!).searchParams),
            };
          }
          const completed = await control({ ...callback, headers: { cookie: cookies(started) } });
          expect(completed.status).toBe(302);
          expect(new URL(completed.headers.get("location")!).pathname).toBe("/complete");
          const session = (await (
            await control({ action: "session", headers: { cookie: cookies(completed) } })
          ).json()) as any;
          expect(session.user.email).toBe(email);
          const userId = session.user.id;
          if (index === 0) {
            firstUserId = userId;
          } else {
            expect(userId).toBe(firstUserId);
          }
          const member = (await (
            await control({ action: "member-row", organizationId, userId })
          ).json()) as any;
          if (mode === "disabled" || mode === "invitation") {
            expect(member).toBe(null);
          } else if (index === 0) {
            expect(member.role).toBe(["admin", "dynamic"].includes(mode) ? "admin" : "member");
            memberId = member.id;
            expect(
              (
                await control({
                  action: "org-role",
                  headers,
                  body: { organizationId, memberId, role: "owner" },
                })
              ).status,
            ).toBe(200);
          } else {
            expect(member.id).toBe(memberId);
            expect(member.role).toBe("owner");
          }
          const roles = (await (await control({ action: "role-events" })).json()) as any[];
          expect(roles).toHaveLength(mode === "dynamic" ? 1 : 0);
          for (const event of roles) {
            expect(event.userId).toBe(userId);
            expect(event.email).toBe(email);
            expect(event.providerId).toBe(providerId);
            expect(event.organizationId).toBe(organizationId);
            expect(event.profile.email).toBe(email);
            expect(event.profile[saml ? "displayName" : "name"]).toBe("SSO employee");
            expect(event.tokenPresent).toBe(!saml);
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
        observed.push({ mode, saml, assigned: mode !== "disabled" && mode !== "invitation" });
      }
    }
    return observed;
  },
);
