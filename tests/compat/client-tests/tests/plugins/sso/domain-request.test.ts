import { Cookie } from "tough-cookie";
import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "SSO verification requests reuse a real live proof and replace expired proof",
  async (ctx) => {
    const actor = ctx.actor();
    const control = (input: Record<string, unknown>) =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/sso`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ mode: "domain", ...input }),
      });
    const signup = async (name: string) => {
      const response = await control({
        action: "signup",
        body: { email: ctx.uniqueEmail(name), name: "Native owner", password: "password123" },
      });
      expect(response.status).toBe(200);
      return response.headers
        .getSetCookie()
        .filter((raw) => Boolean(Cookie.parse(raw)?.value))
        .map((raw) => raw.split(";")[0])
        .join("; ");
    };
    const owner = await signup("sso-domain-owner");
    const foreign = await signup("sso-domain-foreign");
    const headers = { cookie: owner };
    const registered = await control({
      headers,
      body: {
        providerId: "request-provider",
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
    expect(registered.status).toBe(200);
    const provider = (await registered.json()) as any;
    const input = { action: "request-domain", body: { providerId: "request-provider" }, headers };
    const requested = await control(input);
    expect(requested.status).toBe(201);
    const token = ((await requested.json()) as any).domainVerificationToken;
    expect(token).toMatch(/^[a-zA-Z0-9_-]{24}$/);
    expect(provider.domainVerificationToken).toBe(token);
    expect(provider.domainVerified).toBe(false);
    const identifier = "_better-auth-token-request-provider";
    const proof = (await (await control({ action: "proof", identifier })).json()) as any;
    expect(proof.value).toBe(token);
    expect(Date.parse(proof.expiresAt)).toBeGreaterThan(Date.now() + 6 * 86400000);
    expect(Date.parse(proof.expiresAt)).toBeLessThanOrEqual(Date.now() + 7 * 86400000);
    const repeated = await control(input);
    expect(repeated.status).toBe(201);
    expect(((await repeated.json()) as any).domainVerificationToken).toBe(token);
    const same = (await (await control({ action: "proof", identifier })).json()) as any;
    expect(same.id).toBe(proof.id);
    expect(same.expiresAt).toBe(proof.expiresAt);
    const denied = await control({ ...input, headers: { cookie: foreign } });
    expect(denied.status).toBe(403);
    const anonymous = await control({ ...input, headers: {} });
    expect(anonymous.status).toBe(401);
    const preserved = (await (await control({ action: "proof", identifier })).json()) as any;
    expect(preserved.id).toBe(proof.id);
    expect(preserved.value).toBe(token);
    expect((await control({ action: "expire-proof", identifier })).status).toBe(200);
    const renewed = await control(input);
    expect(renewed.status).toBe(201);
    const next = ((await renewed.json()) as any).domainVerificationToken;
    expect(next).toMatch(/^[a-zA-Z0-9_-]{24}$/);
    expect(next).not.toBe(token);
    const fresh = (await (await control({ action: "proof", identifier })).json()) as any;
    expect(fresh.value).toBe(next);
    expect(fresh.id).not.toBe(proof.id);
    expect(Date.parse(fresh.expiresAt)).toBeGreaterThan(Date.now() + 6 * 86400000);
    return {
      tokenLength: token.length,
      nextTokenLength: next.length,
      proof: { ...proof, value: proof.value.length },
      same: { ...same, value: same.value.length },
      fresh: { ...fresh, value: fresh.value.length },
      denied: denied.status,
      anonymous: anonymous.status,
    };
  },
);
