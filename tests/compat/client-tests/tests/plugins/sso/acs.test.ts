import { expect } from "bun:test";

import { Cookie } from "tough-cookie";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "SAML ACS redeems signed requests, rejects wrong keys and prevents replay",
  async (ctx) => {
    const actor = ctx.actor();
    const control = (input: Record<string, unknown>) =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/sso`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(input),
        redirect: "manual",
      });
    const pairs = (response: Response) =>
      response.headers
        .getSetCookie()
        .filter((raw) => Boolean(Cookie.parse(raw)?.value))
        .map((raw) => raw.split(";")[0])
        .join("; ");
    const owner = await control({
      action: "signup",
      body: {
        email: ctx.uniqueEmail("saml-acs-owner"),
        name: "Native owner",
        password: "password123",
      },
    });
    expect(owner.status).toBe(200);
    const cert = await Bun.file(
      new URL("../../../../fixtures/salesforce-transport/leaf.pem", import.meta.url),
    ).text();
    const created = await control({
      body: {
        providerId: "acs-provider",
        issuer: "https://sp.example.test/entity",
        domain: "company.test",
        samlConfig: {
          entryPoint: "https://idp.example.test/sso",
          cert,
          idpMetadata: { entityID: "https://idp.example.test/entity" },
          wantAssertionsSigned: true,
          callbackUrl: `${ctx.baseURL}/complete`,
        },
      },
      headers: { cookie: pairs(owner) },
    });
    expect(created.status).toBe(200);
    const observations = [];
    for (const [http, wrongKey] of [
      [false, false],
      [true, false],
      [false, true],
      [true, true],
    ]) {
      const email = ctx.uniqueEmail(wrongKey ? "wrong-key-user" : "saml-employee");
      const started = await control({
        action: "sign-in",
        body: {
          providerId: "acs-provider",
          providerType: "saml",
          callbackURL: `${ctx.baseURL}/complete`,
          errorCallbackURL: `${ctx.baseURL}/failed`,
        },
      });
      expect(started.status).toBe(200);
      const authorization = ((await started.json()) as any).url;
      const grant = (await (
        await control({ action: "saml-grant", authorization, email, wrongKey })
      ).json()) as any;
      const input = {
        action: http ? "acs-http" : "acs",
        params: { providerId: "acs-provider" },
        body: { SAMLResponse: grant.SAMLResponse, RelayState: grant.RelayState },
        headers: http ? { origin: "https://idp.example.test", cookie: pairs(owner) } : {},
      };
      const completed = await control(input);
      expect(completed.status, await completed.clone().text()).toBe(302);
      const location = new URL(completed.headers.get("location")!);
      expect(
        await (
          await control({ action: "proof", identifier: `auth-state:${grant.RelayState}` })
        ).json(),
      ).toBe(null);
      const request = await (
        await control({ action: "proof", identifier: `saml-authn-request:${grant.requestId}` })
      ).json();
      const used = (await (
        await control({ action: "proof", identifier: `saml-used-assertion:${grant.assertionId}` })
      ).json()) as any;
      const account = (await (
        await control({ action: "saml-account-row", providerId: "acs-provider", accountId: email })
      ).json()) as any;
      if (wrongKey) {
        expect(location.pathname).toBe("/failed");
        expect(location.searchParams.get("error")).toBe("saml_error");
        expect(location.searchParams.get("error_description")).toBe("Invalid SAML response");
        expect(request).not.toBe(null);
        expect(used).toBe(null);
        expect(account).toBe(null);
        expect(
          completed.headers
            .getSetCookie()
            .some((cookie) => cookie.startsWith("better-auth.session_token=")),
        ).toBe(false);
        observations.push({ http, wrongKey, error: Object.fromEntries(location.searchParams) });
      } else {
        expect(location.toString()).toBe(`${ctx.baseURL}/complete`);
        const session = (await (
          await control({ action: "session", headers: { cookie: pairs(completed) } })
        ).json()) as any;
        expect(session.user.email).toBe(email);
        expect(session.user.name).toBe("SSO employee");
        expect(session.user.emailVerified).toBe(false);
        expect(account.userId).toBe(session.user.id);
        expect(account.accessToken).toBe("");
        expect(account.refreshToken).toBe("");
        expect(request).toBe(null);
        expect(used).not.toBe(null);
        const proof = JSON.parse(used.value);
        expect(proof.assertionId).toBe(grant.assertionId);
        expect(proof.issuer).toBe("https://idp.example.test/entity");
        expect(proof.providerId).toBe("acs-provider");
        const replay = await control(input);
        expect(replay.status).toBe(302);
        const rejected = new URL(replay.headers.get("location")!);
        expect(rejected.searchParams.get("error")).toBe("invalid_saml_response");
        expect(rejected.searchParams.get("error_description")).toBe(
          "Unknown or expired request ID",
        );
        observations.push({
          wrongKey,
          session,
          account,
          replay: Object.fromEntries(rejected.searchParams),
        });
      }
    }
    const rejected = await control({
      action: "sign-out-http",
      headers: { origin: "https://idp.example.test", cookie: pairs(owner) },
    });
    expect(rejected.status).toBe(403);
    const ownerSession = (await (
      await control({ action: "session", headers: { cookie: pairs(owner) } })
    ).json()) as any;
    expect(ownerSession.user.email).toBe(((await owner.clone().json()) as any).user.email);
    return observations;
  },
);
