import { expect } from "bun:test";

import { Cookie } from "tough-cookie";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "SSO DNS confirmation joins TXT chunks and commits actual domain ownership",
  async (ctx) => {
    const actor = ctx.actor();
    const control = (input: Record<string, unknown>) =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/sso`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ mode: "domain", ...input }),
      });
    const owner = await control({
      action: "signup",
      body: {
        email: ctx.uniqueEmail("sso-verify-owner"),
        name: "Native owner",
        password: "password123",
      },
    });
    expect(owner.status).toBe(200);
    const cookie = owner.headers
      .getSetCookie()
      .filter((raw) => Boolean(Cookie.parse(raw)?.value))
      .map((raw) => raw.split(";")[0])
      .join("; ");
    const headers = { cookie };
    const created = await control({
      headers,
      body: {
        providerId: "verify-provider",
        issuer: "https://idp.example.com",
        domain: "company.com",
        oidcConfig: {
          clientId: "enterprise-client",
          clientSecret: "stored-secret",
          skipDiscovery: true,
          pkce: true,
        },
      },
    });
    expect(created.status).toBe(200);
    const token = ((await created.json()) as any).domainVerificationToken;
    const input = { action: "verify-domain", body: { providerId: "verify-provider" }, headers };
    expect((await control({ action: "dns-records", records: [["wrong-proof"]] })).status).toBe(200);
    const denied = await control(input);
    expect(denied.status).toBe(502);
    const error = await denied.json();
    expect(error).toEqual({
      code: "DOMAIN_VERIFICATION_FAILED",
      message: "Unable to verify domain ownership for company.com. Try again later",
    });
    expect(
      ((await (await control({ action: "row", providerId: "verify-provider" })).json()) as any)
        .domainVerified,
    ).toBe(false);
    expect(
      (
        await control({
          action: "dns-records",
          records: [[" _better-auth-token-verify-provider=", `${token} `]],
        })
      ).status,
    ).toBe(200);
    const verified = await control(input);
    expect(verified.status).toBe(204);
    expect(verified.headers.get("content-type")).toBe("application/json");
    expect(await verified.text()).toBe("");
    expect(
      ((await (await control({ action: "row", providerId: "verify-provider" })).json()) as any)
        .domainVerified,
    ).toBe(true);
    const queries = (await (await control({ action: "dns-queries" })).json()) as string[];
    expect(queries.length).toBeGreaterThan(0);
    expect(
      queries.every((query) => query === "_better-auth-token-verify-provider.company.com"),
    ).toBe(true);
    const repeated = await control(input);
    expect(repeated.status).toBe(409);
    expect(await repeated.json()).toEqual({
      code: "DOMAIN_VERIFIED",
      message: "Domain has already been verified",
    });
    const request = await control({
      action: "request-domain",
      body: { providerId: "verify-provider" },
      headers,
    });
    expect(request.status).toBe(409);
    return {
      error,
      verified: verified.status,
      queries: [...new Set(queries)],
      repeated: repeated.status,
      request: request.status,
    };
  },
);
