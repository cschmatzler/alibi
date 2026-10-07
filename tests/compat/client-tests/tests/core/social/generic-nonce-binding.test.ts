import { expect } from "bun:test";
import { readFileSync } from "node:fs";

import { importPKCS8, SignJWT } from "jose";

import { authProfilePath } from "../../../support/profiles";
import { compatScenario } from "../../../support/scenario";

compatScenario(
  "generic OAuth disabled nonce binding permits a mismatched signed ID token while the default rejects it",
  async (ctx) => {
    const observations = [];
    for (const profile of ["generic-discovery-oidc", "generic-discovery-nonce-unbound"] as const) {
      const actor = ctx.actor(profile, profile);
      const start = await actor.client.signIn.social({
        provider: "discovery",
        callbackURL: "/nonce-return",
      });
      expect(start.error).toBeNull();
      const url = new URL(start.data!.url!);
      expect(url.searchParams.has("nonce")).toBe(profile === "generic-discovery-oidc");
      const subject = ctx.uniqueToken(profile);
      const email = ctx.uniqueEmail(profile);
      const key = await importPKCS8(
        readFileSync("../../../tests/fixtures/one-tap/private-key.pem", "utf8"),
        "RS256",
      );
      const token = await new SignJWT({
        sub: subject,
        email,
        name: "Nonce user",
        email_verified: true,
        nonce: "unrelated-nonce",
      })
        .setProtectedHeader({ alg: "RS256", kid: "one-tap-local-rs256" })
        .setIssuer("https://issuer.example.invalid")
        .setAudience("discovery-client")
        .setExpirationTime(4102444800)
        .sign(key);
      const configured = await ctx.rawRequest({
        path: "/__test/generic-discovery/control",
        method: "POST",
        json: {
          profile: { id: subject, sub: subject, email, name: "Nonce user", emailVerified: true },
          tokenResponse: {
            access_token: "oidc-access",
            refresh_token: "oidc-refresh",
            token_type: "Bearer",
            expires_in: 3600,
            id_token: token,
            scope: "openid profile",
          },
        },
      });
      expect(configured.status).toBe(200);
      const before = await ctx.rawRequest({ path: "/__test/social-provider/state" });
      const response = await actor.fetch(
        `${ctx.baseURL}${authProfilePath(profile)}/callback/discovery?code=discovery-code&state=${encodeURIComponent(url.searchParams.get("state")!)}`,
        { redirect: "manual" },
      );
      const callback = { status: response.status, location: response.headers.get("location") };
      const after = await ctx.rawRequest({ path: "/__test/social-provider/state" });
      if (profile === "generic-discovery-oidc") {
        expect(new URL(callback.location!, ctx.baseURL).searchParams.get("error")).toBe(
          "unable_to_get_user_info",
        );
        expect(after).toEqual(before);
      } else {
        expect(callback.location).toBe("/nonce-return");
        const session = await actor.client.getSession();
        expect(session.data?.user.email).toBe(email);
        observations.push({ session });
      }
      observations.push({ start, before, callback, after });
    }
    return ctx.snapshot(observations);
  },
  ["POST /sign-in/social", "GET /callback/{}"],
);
