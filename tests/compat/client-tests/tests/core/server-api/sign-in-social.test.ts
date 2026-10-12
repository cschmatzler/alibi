import { expect } from "bun:test";

import { authProfilePath } from "../../../support/profiles";
import { compatScenario } from "../../../support/scenario";
import { observeLogicalOAuthState } from "../../../support/server-oauth-state";

compatScenario(
  "server signInSocial issues signed state and usable PKCE through real logical dispatch",
  async (ctx) => {
    const profile = "generic-token-none";
    const actor = ctx.actor("logical-social", profile);
    async function invoke(logicalBody: unknown, physicalRequest = false) {
      const response = await ctx
        .actor("social-control")
        .fetch(ctx.baseURL + "/__test/generic-token/server-api", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            operation: "sign-in-social",
            logicalBody,
            logicalHeaders: { origin: "https://untrusted.example.test" },
            ...(physicalRequest ? { physicalRequest: true } : {}),
          }),
        });
      const text = await response.text();
      return {
        status: response.status,
        body: text ? (JSON.parse(text) as Record<string, unknown>) : null,
        location: response.headers.get("location"),
        cookies: response.headers.getSetCookie(),
      };
    }
    const rejected = [];
    for (const [body, status] of [
      [{}, 400],
      [{ provider: 7 }, 400],
      [{ provider: "generic", scopes: 7 }, 400],
      [{ provider: "generic", disableRedirect: null }, 400],
      [{ provider: "generic", additionalParams: { state: "injected" } }, 400],
      [{ provider: "missing-provider" }, 404],
      [{ provider: "generic", idToken: { token: "unsupported" } }, 404],
    ] as const) {
      const denial = await invoke(body);
      expect(denial.status).toBe(status);
      rejected.push(denial);
    }
    const starts = [];
    for (const [index, disableRedirect] of [true, false].entries()) {
      const callbackURL = index === 0 ? "/logical-done" : "https://external.example.test/done";
      const startedAt = Date.now();
      const start = await invoke({
        provider: "generic",
        callbackURL,
        newUserCallbackURL: callbackURL,
        errorCallbackURL: callbackURL,
        disableRedirect,
        scopes: ["profile", "calendar"],
        loginHint: "Owner+hint@example.test",
        requestSignUp: true,
        additionalParams: { prompt: "consent :+&" },
        additionalData: { application: "owned", nested: { round: index } },
        authorizationParams: { state: "ignored-unknown-field" },
      });
      const finishedAt = Date.now();
      expect(start.status).toBe(200);
      const url = new URL(start.body!.url as string);
      expect(start.body!.redirect).toBe(!disableRedirect);
      expect(start.location).toBe(disableRedirect ? null : url.toString());
      expect(url.searchParams.get("scope")).toBe("profile calendar profile");
      expect(url.searchParams.get("login_hint")).toBe("Owner+hint@example.test");
      expect(url.searchParams.get("prompt")).toBe("consent :+&");
      expect(url.searchParams.get("code_challenge_method")).toBe("S256");
      const { state, payload, observation } = await observeLogicalOAuthState(
        ctx,
        start,
        startedAt,
        finishedAt,
        {
          callbackURL,
          errorURL: callbackURL,
          newUserURL: callbackURL,
          requestSignUp: true,
          application: "owned",
          nested: { round: index },
        },
      );
      starts.push(observation);
      if (index === 0) {
        const cookie = start.cookies.map((c) => c.split(";")[0]).join("; ");
        expect(
          (
            await ctx.rawRequest({
              path: "/__test/generic-token/control",
              method: "POST",
              json: {
                profile: {
                  id: ctx.uniqueToken("logical-social-subject"),
                  email: ctx.uniqueEmail("logical-social"),
                  name: "Logical Social",
                  email_verified: true,
                },
              },
            })
          ).status,
        ).toBe(200);
        const callback = await actor.fetch(
          ctx.baseURL +
            authProfilePath(profile) +
            `/callback/generic?code=logical-code&state=${encodeURIComponent(state)}`,
          { headers: { cookie }, redirect: "manual" },
        );
        expect(callback.status).toBe(302);
        expect(callback.headers.get("location")).toBe("/logical-done");
        const session = await actor.client.getSession();
        expect(session.error).toBeNull();
        expect(session.data!.user.name).toBe("Logical Social");
        const sent = (await ctx.rawRequest({ path: "/__test/generic-token/receipts" })).body as {
          body: [string, string][];
        }[];
        const grant = Object.fromEntries(sent[0]!.body);
        expect(grant.code_verifier).toBe(payload.codeVerifier);
        expect(grant.code).toBe("logical-code");
      }
    }
    return ctx.snapshot({ rejected, starts });
  },
  [],
  30_000,
);
