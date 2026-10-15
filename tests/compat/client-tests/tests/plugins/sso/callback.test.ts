import { Cookie } from "tough-cookie";
import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";
for (const mode of ["default", "shared", "default-pkce", "discovery", "runtime-discovery"]) {
  compatScenario(
    `SSO ${mode} callback redeems a real PKCE code and creates a usable session`,
    async (ctx) => {
      const actor = ctx.actor();
      const control = (input: Record<string, unknown>) =>
        actor.fetch(`${ctx.baseURL}/__test/server-api/sso`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ ...input, mode }),
          redirect: "manual",
        });
      const pairs = (response: Response) =>
        response.headers
          .getSetCookie()
          .filter((raw) => Boolean(Cookie.parse(raw)?.value))
          .map((raw) => raw.split(";")[0])
          .join("; ");
      const email = ctx.uniqueEmail("sso-employee");
      const idp = (await (await control({ action: "idp", email })).json()) as any;
      const owner = await control({
        action: "signup",
        body: {
          email: ctx.uniqueEmail("sso-callback-owner"),
          name: "Native owner",
          password: "password123",
        },
      });
      expect(owner.status).toBe(200);
      const registration = {
        headers: { cookie: pairs(owner) },
        body: {
          providerId: "callback-provider",
          issuer: idp.base,
          domain: "example.test",
          oidcConfig: {
            clientId: "enterprise-client",
            clientSecret: "stored-secret",
            skipDiscovery: true,
            ...(mode === "default-pkce" || mode === "discovery" || mode === "runtime-discovery"
              ? {}
              : { pkce: true }),
            scopes: ["openid", "email"],
            authorizationEndpoint: `${idp.base}/authorize`,
            tokenEndpoint: `${idp.base}/token`,
            userInfoEndpoint: `${idp.base}/userinfo`,
            jwksEndpoint: `${idp.base}/jwks`,
          },
        },
      };
      if (mode === "runtime-discovery") {
        const config = registration.body.oidcConfig as any;
        for (const field of [
          "authorizationEndpoint",
          "tokenEndpoint",
          "jwksEndpoint",
          "userInfoEndpoint",
        ]) {
          delete config[field];
        }
      }
      if (mode === "discovery") {
        const config = registration.body.oidcConfig as any;
        for (const field of [
          "skipDiscovery",
          "authorizationEndpoint",
          "tokenEndpoint",
          "jwksEndpoint",
          "userInfoEndpoint",
        ]) {
          delete config[field];
        }
        await control({ action: "idp", discoveryCase: "missing" });
        const rejected = await control({
          ...registration,
          body: { ...registration.body, providerId: "incomplete-discovery-provider" },
        });
        expect(rejected.status).toBe(400);
        expect(((await rejected.json()) as any).code).toBe("discovery_incomplete");
        expect(
          await (
            await control({ action: "row", providerId: "incomplete-discovery-provider" })
          ).json(),
        ).toBe(null);
        await control({ action: "idp", discoveryCase: "valid" });
      }
      const created = await control(registration);
      expect(created.status).toBe(200);
      if (mode === "discovery") {
        const row = (await (
          await control({ action: "row", providerId: "callback-provider" })
        ).json()) as any;
        const config = JSON.parse(row.oidcConfig);
        for (const [field, path] of [
          ["authorizationEndpoint", "authorize"],
          ["tokenEndpoint", "token"],
          ["jwksEndpoint", "jwks"],
          ["userInfoEndpoint", "userinfo"],
        ]) {
          expect(config[field!]).toBe(`${idp.base}/${path}`);
        }
        expect(config.pkce).toBe(true);
        expect(config.tokenEndpointAuthentication).toBe("client_secret_basic");
      }
      if (mode === "runtime-discovery") {
        await control({ action: "idp", discoveryCase: "missing" });
        const denied = await control({
          action: "sign-in",
          body: { providerId: "callback-provider", callbackURL: `${ctx.baseURL}/complete` },
        });
        expect(denied.status).toBe(400);
        expect(((await denied.json()) as any).code).toBe("discovery_incomplete");
        await control({ action: "idp", discoveryCase: "valid" });
        const extra = await control({
          action: "sign-in",
          body: {
            providerId: "callback-provider",
            callbackURL: `${ctx.baseURL}/complete`,
            errorCallbackURL: `${ctx.baseURL}/failed`,
          },
        });
        expect(extra.status).toBe(200);
        const grant = await fetch(((await extra.json()) as any).url, { redirect: "manual" });
        expect(grant.status).toBe(302);
        const query = Object.fromEntries(new URL(grant.headers.get("location")!).searchParams);
        await control({ action: "idp", discoveryCase: "missing" });
        const failed = await control({
          action: "callback",
          params: { providerId: "callback-provider" },
          query,
          headers: { cookie: pairs(extra) },
        });
        expect(failed.status).toBe(302);
        const location = new URL(failed.headers.get("location")!);
        expect(location.pathname).toBe("/failed");
        expect(location.searchParams.get("error")).toBe("discovery_failed");
        expect(location.searchParams.get("error_description")).toBe(
          "Discovery document is missing required fields: jwks_uri",
        );
        expect(
          await (
            await control({ action: "proof", identifier: `auth-state:${query.state}` })
          ).json(),
        ).toBe(null);
        expect(
          await (
            await control({
              action: "account-row",
              providerId: "callback-provider",
              accountId: "employee-subject",
            })
          ).json(),
        ).toBe(null);
        expect(await (await control({ action: "idp-exchanges" })).json()).toHaveLength(0);
        await control({ action: "idp", discoveryCase: "valid" });
      }
      const started = await control({
        action: "sign-in",
        body: {
          providerId: "callback-provider",
          callbackURL: `${ctx.baseURL}/complete`,
          errorCallbackURL: `${ctx.baseURL}/failed`,
        },
      });
      expect(started.status, await started.clone().text()).toBe(200);
      const authorization = ((await started.json()) as any).url;
      // The independent IdP mints a unique code; compare Alibi and Better Auth, not IdP randomness.
      const granted = await fetch(authorization, { redirect: "manual" });
      expect(granted.status).toBe(302);
      const callback = new URL(granted.headers.get("location")!);
      const query = Object.fromEntries(callback.searchParams);
      const state = query.state;
      const proof = (await (
        await control({ action: "proof", identifier: `auth-state:${state}` })
      ).json()) as any;
      const payload = JSON.parse(proof.value);
      const input = {
        action: mode === "shared" ? "shared-callback" : "callback",
        params: {
          providerId: mode === "shared" ? "untrusted-route-provider" : "callback-provider",
        },
        query,
        headers: { cookie: pairs(started) },
      };
      const unbound = await control({ ...input, headers: {} });
      expect(unbound.status).toBe(302);
      expect(unbound.headers.get("location")).toBe(`${ctx.baseURL}/failed?error=state_mismatch`);
      expect(
        await (await control({ action: "proof", identifier: `auth-state:${state}` })).json(),
      ).not.toBe(null);
      expect(await (await control({ action: "idp-exchanges" })).json()).toHaveLength(0);
      const completed = await control(input);
      expect(completed.status).toBe(302);
      expect(completed.headers.get("location")).toBe(`${ctx.baseURL}/complete`);
      const session = await control({ action: "session", headers: { cookie: pairs(completed) } });
      expect(session.status).toBe(200);
      const authenticated = (await session.json()) as any;
      expect(authenticated.user.email).toBe(email);
      expect(authenticated.user.name).toBe("SSO employee");
      expect(authenticated.user.emailVerified).toBe(false);
      expect(
        await (await control({ action: "proof", identifier: `auth-state:${state}` })).json(),
      ).toBe(null);
      const account = (await (
        await control({
          action: "account-row",
          providerId: "callback-provider",
          accountId: "employee-subject",
        })
      ).json()) as any;
      expect(account).not.toBe(null);
      expect(account.userId).toBe(authenticated.user.id);
      const exchanges = (await (await control({ action: "idp-exchanges" })).json()) as any[];
      expect(exchanges).toHaveLength(1);
      expect(exchanges[0].form.code_verifier).toBe(payload.codeVerifier);
      expect(exchanges[0].form.redirect_uri).toBe(
        mode === "shared"
          ? `${ctx.baseURL}/api/auth/sso/callback`
          : `${ctx.baseURL}/api/auth/sso/callback/callback-provider`,
      );
      expect(exchanges[0].authorization).toBe("Basic ZW50ZXJwcmlzZS1jbGllbnQ6c3RvcmVkLXNlY3JldA==");
      const replay = await control(input);
      expect(replay.status).toBe(302);
      expect(replay.headers.get("location")).toContain("error=state_mismatch");
      expect(await (await control({ action: "idp-exchanges" })).json()).toHaveLength(1);
      if (mode === "runtime-discovery") {
        const row = (await (
          await control({ action: "row", providerId: "callback-provider" })
        ).json()) as any;
        const stored = JSON.parse(row.oidcConfig);
        for (const field of [
          "authorizationEndpoint",
          "tokenEndpoint",
          "jwksEndpoint",
          "userInfoEndpoint",
        ]) {
          expect(stored[field]).toBeUndefined();
        }
      }
      return { authenticated, account, completed: completed.status, replay: replay.status };
    },
  );
}
