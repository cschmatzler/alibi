import { Cookie } from "tough-cookie";
import { expect } from "vitest";

import type { ScenarioContext } from "../../../support/scenario";
export async function socialDomainMembershipFlow(ctx: ScenarioContext, http: boolean) {
  const transport = http ? "http" : "api";
  const actor = ctx.actor();
  const cookies = (response: Response) =>
    response.headers
      .getSetCookie()
      .filter((raw) => Boolean(Cookie.parse(raw)?.value))
      .map((raw) => raw.split(";")[0])
      .join("; ");
  const observed = [];
  for (const [index, caseName] of ["verified", "unverified", "disabled", "ambiguous"].entries()) {
    const control = (input: Record<string, unknown>) =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/sso`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          ...input,
          mode: caseName === "disabled" ? "org-domain-disabled" : "org-domain",
        }),
        redirect: "manual",
      });
    const owner = await control({
      action: "signup",
      body: {
        email: ctx.uniqueEmail(`domain-owner-${caseName}`),
        name: "Owner",
        password: "password123",
      },
    });
    expect(owner.status).toBe(200);
    const headers = { cookie: cookies(owner) };
    const domain = `${caseName}-${transport}.company.test`;
    const idp = (await (await control({ action: "idp" })).json()) as any;
    const organizations = [];
    for (let target = 0; target < (caseName === "ambiguous" ? 2 : 1); target++) {
      const organizationResponse = await control({
        action: "org-create",
        headers,
        body: { name: "Domain company", slug: `domain-${caseName}-${transport}-${target}` },
      });
      expect(organizationResponse.status).toBe(200);
      const organizationId = ((await organizationResponse.json()) as any).id;
      const providerId = `domain-${caseName}-${transport}-${target}`;
      const registered = await control({
        headers,
        body: {
          providerId,
          organizationId,
          issuer: idp.base,
          domain,
          oidcConfig: {
            clientId: "enterprise-client",
            clientSecret: "stored-secret",
            skipDiscovery: true,
            pkce: true,
          },
        },
      });
      expect(registered.status).toBe(200);
      const token = ((await registered.json()) as any).domainVerificationToken;
      await control({
        action: "dns-records",
        records: [[`_better-auth-token-${providerId}=${token}`]],
      });
      expect(
        (await control({ action: "verify-domain", headers, body: { providerId } })).status,
      ).toBe(204);
      organizations.push(organizationId);
    }
    const email = `${ctx.uniqueEmail(`domain-employee-${caseName}`).split("@")[0]}@${domain}`;
    const subject = (http ? 810 : 710) + index;
    await control({
      action: "idp",
      email,
      profile: {
        id: subject,
        email,
        email_verified: caseName !== "unverified",
        name: "Domain employee",
        state: "active",
        locked: false,
      },
    });
    const started = await control({
      action: "social-start",
      body: { provider: "gitlab", callbackURL: `${ctx.baseURL}/complete`, disableRedirect: true },
    });
    expect(started.status).toBe(200);
    const grant = await fetch(((await started.json()) as any).url, { redirect: "manual" });
    expect(grant.status).toBe(302);
    const query = Object.fromEntries(new URL(grant.headers.get("location")!).searchParams);
    const completed = await control({
      action: http ? "social-callback-http" : "social-callback",
      query,
      headers: { cookie: cookies(started) },
    });
    expect(completed.status).toBe(302);
    expect(new URL(completed.headers.get("location")!).pathname).toBe("/complete");
    const session = (await (
      await control({ action: "session", headers: { cookie: cookies(completed) } })
    ).json()) as any;
    expect(session.user.email).toBe(email);
    expect(session.user.emailVerified).toBe(caseName !== "unverified");
    expect(
      await (
        await control({ action: "account-row", providerId: "gitlab", accountId: String(subject) })
      ).json(),
    ).not.toBe(null);
    for (const organizationId of organizations) {
      const member = (await (
        await control({ action: "member-row", organizationId, userId: session.user.id })
      ).json()) as any;
      if (caseName === "verified") {
        expect(member.role).toBe("member");
      } else {
        expect(member).toBe(null);
      }
    }
    observed.push({
      caseName,
      assigned: caseName === "verified",
      organizations: organizations.length,
    });
  }
  return observed;
}
