import { expect } from "bun:test";

import { Cookie } from "tough-cookie";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "SSO signing-key resolver admits persisted clients and resolves each real exchange",
  async (ctx) => {
    const actor = ctx.actor();
    const control = (input: Record<string, unknown>) =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/sso`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ ...input, mode: "key-resolver" }),
        redirect: "manual",
      });
    const cookies = (response: Response) =>
      response.headers
        .getSetCookie()
        .filter((raw) => Boolean(Cookie.parse(raw)?.value))
        .map((raw) => raw.split(";")[0])
        .join("; ");
    expect((await control({ action: "key-reset" })).status).toBe(200);
    const owner = await control({
      action: "signup",
      body: {
        email: ctx.uniqueEmail("key-resolver-owner"),
        name: "Owner",
        password: "password123",
      },
    });
    expect(owner.status).toBe(200);
    const idp = (await (await control({ action: "idp" })).json()) as any;
    const created = await control({
      headers: { cookie: cookies(owner) },
      body: {
        providerId: "resolved-jwt",
        issuer: idp.base,
        domain: "company.test",
        oidcConfig: {
          clientId: "enterprise-client",
          skipDiscovery: true,
          pkce: true,
          authorizationEndpoint: `${idp.base}/authorize`,
          tokenEndpoint: `${idp.base}/token-jwt`,
          jwksEndpoint: `${idp.base}/jwks`,
          userInfoEndpoint: `${idp.base}/userinfo`,
          tokenEndpointAuthentication: "private_key_jwt",
          privateKeyId: "sso-key",
          privateKeyAlgorithm: "RS256",
        },
      },
    });
    expect(created.status).toBe(200);
    expect(await (await control({ action: "key-events" })).json()).toEqual([]);
    const updated = await control({
      action: "update",
      headers: { cookie: cookies(owner) },
      body: { providerId: "resolved-jwt", oidcConfig: { clientSecret: "must-not-send" } },
    });
    expect(updated.status).toBe(200);
    expect(await (await control({ action: "key-events" })).json()).toEqual([]);
    const original = (await (
      await control({ action: "row", providerId: "resolved-jwt" })
    ).json()) as any;
    const observed = [];
    for (const [index, enabled] of [
      [0, true],
      [1, true],
      [2, false],
    ] as const) {
      await control({ action: "key-reset" });
      await control({ action: "key-enabled", enabled });
      const email = ctx.uniqueEmail(`key-resolver-${index}`);
      const accountId = `resolver-subject-${index}`;
      await control({
        action: "idp",
        email,
        profile: { sub: accountId, email, email_verified: false, name: "Resolved key employee" },
      });
      const started = await control({
        action: "sign-in",
        body: {
          providerId: "resolved-jwt",
          callbackURL: `${ctx.baseURL}/complete`,
          errorCallbackURL: `${ctx.baseURL}/failed`,
        },
      });
      expect(started.status).toBe(200);
      expect(await (await control({ action: "key-events" })).json()).toEqual([]);
      const grant = await fetch(((await started.json()) as any).url, { redirect: "manual" });
      expect(grant.status).toBe(302);
      const query = Object.fromEntries(new URL(grant.headers.get("location")!).searchParams);
      const completed = await control({
        action: "callback",
        params: { providerId: "resolved-jwt" },
        query,
        headers: { cookie: cookies(started) },
      });
      expect(completed.status).toBe(302);
      expect(await (await control({ action: "key-events" })).json()).toEqual([
        { providerId: "resolved-jwt", keyId: "sso-key", issuer: idp.base },
      ]);
      const location = new URL(completed.headers.get("location")!);
      const exchanges = (await (await control({ action: "idp-exchanges" })).json()) as any[];
      if (enabled) {
        expect(location.pathname).toBe("/complete");
        const session = (await (
          await control({ action: "session", headers: { cookie: cookies(completed) } })
        ).json()) as any;
        expect(session.user.email).toBe(email);
        expect(exchanges).toHaveLength(1);
        expect(exchanges[0].authorization).toBe(null);
        expect(exchanges[0].form.client_secret).toBeUndefined();
        expect(
          await (
            await control({ action: "account-row", providerId: "resolved-jwt", accountId })
          ).json(),
        ).not.toBe(null);
      } else {
        expect(location.pathname).toBe("/failed");
        expect(location.searchParams.get("error_description")).toBe("no_private_key_available");
        expect(exchanges).toEqual([]);
        expect(await (await control({ action: "user-row", email })).json()).toBe(null);
        expect(
          await (
            await control({ action: "account-row", providerId: "resolved-jwt", accountId })
          ).json(),
        ).toBe(null);
      }
      expect(await (await control({ action: "row", providerId: "resolved-jwt" })).json()).toEqual(
        original,
      );
      expect(original.oidcConfig).not.toContain("PRIVATE KEY");
      observed.push({ enabled, path: location.pathname });
    }
    return observed;
  },
);
