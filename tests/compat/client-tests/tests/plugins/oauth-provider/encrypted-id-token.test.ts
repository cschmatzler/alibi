import { expect } from "bun:test";
import { createHash } from "node:crypto";

import { jwtVerify } from "jose";
import { Cookie } from "tough-cookie";

import { compatScenario } from "../../../support/scenario";

for (const [mode, publicClient] of [
  ["encrypted-generator", false],
  ["custom-encrypted-prefixed", false],
  ["encrypted-generator", true],
] as const) {
  compatScenario(
    `OpenID without JWT plugin uses ${mode} ${publicClient ? "public" : "confidential"} credentials`,
    async (ctx) => {
      const actor = ctx.actor();
      const control = (input: object) =>
        actor.fetch(`${ctx.baseURL}/__test/server-api/oauth-provider-clients`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ mode, ...input }),
        });
      const signup = await control({
        action: "signup",
        body: {
          email: ctx.uniqueEmail(`encrypted-id-${mode}-${publicClient}`),
          name: "Encrypted owner",
          password: "password123",
        },
      });
      expect(signup.status).toBe(200);
      const cookie = signup.headers
        .getSetCookie()
        .filter((raw) => Boolean(Cookie.parse(raw)?.value))
        .map((raw) => raw.split(";")[0])
        .join("; ");
      const created = await control({
        action: "admin-create",
        headers: { cookie },
        body: {
          client_name: "Encrypted ID client",
          redirect_uris: ["https://app.fixture.test/callback"],
          scope: "openid email profile",
          token_endpoint_auth_method: publicClient ? "none" : "client_secret_post",
          skip_consent: true,
        },
      });
      expect(created.status).toBe(201);
      const client = await created.json();
      const verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
      const challenge = createHash("sha256").update(verifier).digest("base64url");
      const grant = await control({
        action: "authorize",
        headers: { cookie, accept: "application/json" },
        query: {
          client_id: client.client_id,
          response_type: "code",
          redirect_uri: "https://app.fixture.test/callback",
          scope: "openid email profile",
          state: "encrypted-state",
          nonce: "encrypted-nonce",
          code_challenge: challenge,
          code_challenge_method: "S256",
        },
      });
      expect(grant.status).toBe(200);
      const callback = new URL((await grant.json()).url);
      const code = callback.searchParams.get("code");
      expect(code).toBeTruthy();
      const issuedAfter = Math.floor(Date.now() / 1000);
      const response = await control({
        action: "token",
        body: {
          grant_type: "authorization_code",
          client_id: client.client_id,
          ...(!publicClient ? { client_secret: client.client_secret } : {}),
          code,
          code_verifier: verifier,
          redirect_uri: "https://app.fixture.test/callback",
        },
      });
      expect(response.status).toBe(200);
      expect(response.headers.get("cache-control")).toBe("no-store");
      expect(response.headers.get("pragma")).toBe("no-cache");
      const issued = await response.json();
      expect(issued.expires_at).toBeGreaterThanOrEqual(issuedAfter + 3600);
      expect(issued.expires_at).toBeLessThanOrEqual(Math.floor(Date.now() / 1000) + 3600);
      expect(issued.access_token).toMatch(/^[A-Za-z]{32}$/);
      expect(issued.token_type).toBe("Bearer");
      expect(issued.scope).toBe("openid email profile");
      expect(issued.expires_in).toBe(3600);
      const sessionResponse = await control({ action: "session", headers: { cookie } });
      expect(sessionResponse.status).toBe(200);
      const authorizationSession = await sessionResponse.json();
      if (publicClient) {
        expect(issued).not.toHaveProperty("id_token");
      } else {
        const prefix = mode.includes("prefixed") ? "client_prefix_" : "";
        const secret = client.client_secret.slice(prefix.length);
        const verified = await jwtVerify(issued.id_token, new TextEncoder().encode(secret), {
          issuer: `${ctx.baseURL}/api/auth`,
          audience: client.client_id,
        });
        expect(verified.protectedHeader).toEqual({ alg: "HS256" });
        const payload = verified.payload;
        expect(payload.sub).toBe(authorizationSession.user.id);
        expect(payload.nonce).toBe("encrypted-nonce");
        expect(payload.acr).toBe("0");
        expect(payload.auth_time).toBe(
          Math.floor(Date.parse(authorizationSession.session.createdAt) / 1000),
        );
        expect(payload.exp! - payload.iat!).toBe(36000);
        expect(payload.at_hash).toBe(
          createHash("sha256")
            .update(issued.access_token)
            .digest()
            .subarray(0, 16)
            .toString("base64url"),
        );
        await expect(
          jwtVerify(issued.id_token, new TextEncoder().encode("unrelated-client-secret"), {
            issuer: `${ctx.baseURL}/api/auth`,
            audience: client.client_id,
          }),
        ).rejects.toThrow();
        if (prefix)
          await expect(
            jwtVerify(issued.id_token, new TextEncoder().encode(client.client_secret), {
              issuer: `${ctx.baseURL}/api/auth`,
              audience: client.client_id,
            }),
          ).rejects.toThrow();
      }
      return publicClient
        ? ctx.snapshot({ authorizationSession, clientId: client.client_id, tokens: issued })
        : ctx.snapshot({ authorizationSession, clientId: client.client_id, issued });
    },
  );
}
