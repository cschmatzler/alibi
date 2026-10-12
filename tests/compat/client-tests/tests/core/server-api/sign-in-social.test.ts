import { expect } from "bun:test";
import { createHash, createHmac } from "node:crypto";

import { authProfilePath } from "../../../support/profiles";
import { compatScenario } from "../../../support/scenario";

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
      const state = url.searchParams.get("state")!;
      expect(state).toMatch(/^[A-Za-z0-9_-]{32}$/);
      const rows = (await ctx.readVerificationState({ identifier: `auth-state:${state}` })) as {
        id: string;
        identifier: string;
        value: string;
        createdAt: string;
        updatedAt: string;
        expiresAt: string;
      }[];
      expect(rows).toHaveLength(1);
      expect(rows[0]!.identifier).toBe(`auth-state:${state}`);
      const payload = JSON.parse(rows[0]!.value) as {
        codeVerifier: string;
        callbackURL: string;
        errorURL: string;
        newUserURL: string;
        nested: { round: number };
        requestSignUp: boolean;
        application: string;
        expiresAt: number;
        oauthState: string;
      };
      expect(payload.codeVerifier).toMatch(/^[A-Za-z0-9_-]{128}$/);
      expect(createHash("sha256").update(payload.codeVerifier).digest("base64url")).toBe(
        url.searchParams.get("code_challenge")!,
      );
      expect(payload).toEqual({
        callbackURL,
        errorURL: callbackURL,
        newUserURL: callbackURL,
        requestSignUp: true,
        application: "owned",
        nested: { round: index },
        codeVerifier: payload.codeVerifier,
        oauthState: state,
        expiresAt: payload.expiresAt,
      });
      for (const expiresAt of [payload.expiresAt, Date.parse(rows[0]!.expiresAt)]) {
        expect(expiresAt).toBeGreaterThanOrEqual(startedAt + 600_000);
        expect(expiresAt).toBeLessThanOrEqual(finishedAt + 600_000);
      }
      for (const field of ["createdAt", "updatedAt"] as const) {
        expect(Date.parse(rows[0]![field])).toBeGreaterThanOrEqual(startedAt);
        expect(Date.parse(rows[0]![field])).toBeLessThanOrEqual(finishedAt);
      }
      const rawCookie = start.cookies.find((cookie) => cookie.startsWith("better-auth.state="))!;
      const encoded = rawCookie.split(";")[0]!.slice("better-auth.state=".length);
      expect(decodeURIComponent(encoded)).toBe(
        `${state}.${createHmac("sha256", "compat-test-only-key-not-real-minimum-32chars").update(state).digest("base64")}`,
      );
      // Decode authenticated protocol entropy into the comparator's semantic
      // identities, retaining cookie attributes and every stored field.
      starts.push({
        start: {
          ...start,
          cookies: start.cookies.map((cookie) =>
            cookie === rawCookie
              ? { state, attributes: cookie.slice(cookie.indexOf(";")) }
              : cookie,
          ),
        },
        state,
        rows: rows.map((row) => ({
          ...row,
          identifier: { prefix: "auth-state:", state },
          value: {
            ...payload,
            codeVerifier: { token: payload.codeVerifier },
            oauthState: { state: payload.oauthState },
            expiresAt: new Date(payload.expiresAt).toISOString(),
          },
        })),
      });
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
