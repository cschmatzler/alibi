import { Cookie } from "tough-cookie";
import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";

compatScenario(
  "SSO verifies ID token authority, claims and UserInfo subject before session creation",
  async (ctx) => {
    const actor = ctx.actor();
    const control = (input: Record<string, unknown>) =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/sso`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(input),
        redirect: "manual",
      });
    const cookies = (response: Response) =>
      response.headers
        .getSetCookie()
        .filter((raw) => Boolean(Cookie.parse(raw)?.value))
        .map((raw) => raw.split(";")[0])
        .join("; ");
    const idp = (await (await control({ action: "idp" })).json()) as any;
    const owner = await control({
      action: "signup",
      body: {
        email: ctx.uniqueEmail("id-token-owner"),
        name: "Native owner",
        password: "password123",
      },
    });
    expect(owner.status).toBe(200);
    for (const userinfo of [false, true]) {
      const providerId = userinfo ? "id-token-userinfo-provider" : "id-token-provider";
      const oidcConfig: any = {
        clientId: "enterprise-client",
        clientSecret: "stored-secret",
        skipDiscovery: true,
        pkce: true,
        authorizationEndpoint: `${idp.base}/authorize`,
        tokenEndpoint: `${idp.base}/token`,
        jwksEndpoint: `${idp.base}/jwks`,
      };
      if (userinfo) oidcConfig.userInfoEndpoint = `${idp.base}/userinfo`;
      expect(
        (
          await control({
            headers: { cookie: cookies(owner) },
            body: { providerId, issuer: idp.base, domain: "example.test", oidcConfig },
          })
        ).status,
      ).toBe(200);
    }
    const cases: Array<[string, string | null]> = [
      ["issuer", "token_not_verified"],
      ["audience", "token_not_verified"],
      ["expired", "token_not_verified"],
      ["signature", "token_not_verified"],
      ["authorized-party", "token_not_verified"],
      ["multi-audience", "token_not_verified"],
      ["subject", "token_not_verified"],
      ["empty-subject", "id_token_subject_missing"],
      ["missing-exp", "token_not_verified"],
      ["missing-iat", "token_not_verified"],
      ["skewed-expiry", null],
      ["userinfo-mismatch", "id_token_userinfo_subject_mismatch"],
      ["valid", null],
      ["valid-multi-audience", null],
    ];
    const observed = [];
    for (const [idTokenCase, description] of cases) {
      await control({
        action: "idp",
        idTokenCase,
        email: ctx.uniqueEmail(`id-token-${idTokenCase}`),
      });
      const providerId =
        idTokenCase === "userinfo-mismatch" ? "id-token-userinfo-provider" : "id-token-provider";
      const started = await control({
        action: "sign-in",
        body: {
          providerId,
          callbackURL: `${ctx.baseURL}/complete`,
          errorCallbackURL: `${ctx.baseURL}/failed`,
        },
      });
      expect(started.status).toBe(200);
      // The independent IdP mints its own random authorization code.
      const granted = await fetch(((await started.json()) as any).url, {
        redirect: "manual",
      });
      expect(granted.status).toBe(302);
      const callback = new URL(granted.headers.get("location")!);
      const query = Object.fromEntries(callback.searchParams);
      const output = await control({
        action: "callback",
        params: { providerId },
        query,
        headers: { cookie: cookies(started) },
      });
      expect(output.status).toBe(302);
      const redirect = new URL(output.headers.get("location")!);
      expect(
        await (await control({ action: "proof", identifier: `auth-state:${query.state}` })).json(),
      ).toBe(null);
      if (description) {
        expect(redirect.pathname).toBe("/failed");
        expect(redirect.searchParams.get("error")).toBe("invalid_provider");
        expect(redirect.searchParams.get("error_description")).toBe(description);
        for (const accountId of ["employee-subject", "other-subject"]) {
          expect(
            await (await control({ action: "account-row", providerId, accountId })).json(),
          ).toBe(null);
        }
      } else {
        expect(redirect.pathname).toBe("/complete");
        const session = (await (
          await control({ action: "session", headers: { cookie: cookies(output) } })
        ).json()) as any;
        expect(session.session).not.toBe(null);
        expect(session.user.emailVerified).toBe(false);
        const account = (await (
          await control({
            action: "id-token-account-row",
            providerId,
            accountId: "employee-subject",
          })
        ).json()) as any;
        expect(account.idToken).toBeTypeOf("string");
        expect(account.idToken.length).toBeGreaterThan(0);
      }
      observed.push({
        idTokenCase,
        path: redirect.pathname,
        error: redirect.searchParams.get("error_description"),
      });
    }
    return observed;
  },
);
