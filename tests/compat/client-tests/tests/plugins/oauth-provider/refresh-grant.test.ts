import { expect } from "bun:test";
import { createHash } from "node:crypto";

import { Cookie } from "tough-cookie";

import { compatScenario } from "../../../support/scenario";
for (const [explicitRefresh, customHash] of [
  [true, false],
  [false, false],
  [false, true],
]) {
  compatScenario(
    `Refresh grants ${customHash ? "with custom token hashing " : ""}${explicitRefresh ? "explicitly" : "implicitly"} narrow scopes, rotate real authority and reject replay with family cleanup`,
    async (ctx) => {
      const actor = ctx.actor();
      let clientSecret: string | undefined;
      const control = (input: Record<string, unknown>) =>
        actor.fetch(`${ctx.baseURL}/__test/server-api/oauth-provider-clients`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            ...input,
            ...(customHash ? { mode: "custom-token-hash" } : {}),
            ...(["token", "introspect", "revoke"].includes(String(input.action)) && clientSecret
              ? { body: { ...(input.body as object), client_secret: clientSecret } }
              : {}),
          }),
        });
      const protectedToken = (token: string, kind: string) => {
        const digest = createHash("sha256").update(token).digest("base64url");
        return customHash ? `app:${kind}:${digest}` : digest;
      };
      for (const kind of [
        "authorization_code",
        "access_token",
        "refresh_token",
        "application-kind",
      ]) {
        const receipt = await control({ action: "hash-token", token: "known-token", kind });
        expect(receipt.status).toBe(200);
        expect(await receipt.json()).toEqual({ hash: protectedToken("known-token", kind) });
      }
      const signup = await control({
        action: "signup",
        body: { email: ctx.uniqueEmail("refresh-owner"), name: "Owner", password: "password123" },
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
          client_name: "Token client",
          redirect_uris: ["https://app.fixture.test/callback"],
          scope: "email offline_access",
          token_endpoint_auth_method: customHash ? "client_secret_post" : "none",
          skip_consent: true,
          grant_types: explicitRefresh
            ? ["authorization_code", "refresh_token"]
            : ["authorization_code"],
        },
      });
      expect(created.status).toBe(201);
      const client = (await created.json()) as any;
      const id = client.client_id;
      clientSecret = client.client_secret;
      const verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
      const challenge = createHash("sha256").update(verifier).digest("base64url");
      const grant = await control({
        action: "authorize",
        headers: { cookie, accept: "application/json" },
        query: {
          client_id: id,
          response_type: "code",
          redirect_uri: "https://app.fixture.test/callback",
          scope: "email offline_access",
          state: "token-state",
          code_challenge: challenge,
          code_challenge_method: "S256",
        },
      });
      expect(grant.status).toBe(200);
      const callback = new URL(((await grant.json()) as any).url);
      expect(callback.pathname).toBe("/callback");
      expect(callback.searchParams.get("state")).toBe("token-state");
      const code = callback.searchParams.get("code");
      expect(code).toBeTruthy();
      const grantReceipt = await control({
        action: "grant-row",
        token: code,
        protectedToken: protectedToken(code!, "authorization_code"),
      });
      expect(grantReceipt.status).toBe(200);
      expect(await grantReceipt.json()).not.toBeNull();
      const input = {
        grant_type: "authorization_code",
        client_id: id,
        code,
        code_verifier: verifier,
        redirect_uri: "https://app.fixture.test/callback",
      };
      const response = await control({ action: "token", body: input });
      expect(response.status).toBe(200);
      expect(response.headers.get("cache-control")).toBe("no-store");
      expect(response.headers.get("pragma")).toBe("no-cache");
      const token = (await response.json()) as any;
      expect(token.scope).toBe("email offline_access");
      expect(token.token_type).toBe("Bearer");
      expect(token.expires_in).toBe(3600);
      expect(token.access_token).toMatch(/^[A-Za-z]{32}$/);
      expect(token.refresh_token).toMatch(/^[A-Za-z]{32}$/);
      expect(token.id_token).toBeUndefined();

      const row = async (kind: string, value: string) => {
        const r = await control({
          action: "token-row",
          kind,
          token: value,
          protectedToken: protectedToken(
            value,
            kind === "refresh" ? "refresh_token" : "access_token",
          ),
        });
        expect(r.status).toBe(200);
        return (await r.json()) as any;
      };
      const original = await row("refresh", token.refresh_token);
      expect(original.token).toBe(protectedToken(token.refresh_token, "refresh_token"));
      expect(original.authorizationCodeId).toBe(protectedToken(code!, "authorization_code"));
      const failures = [];
      for (const [input, error, error_description] of [
        [{ grant_type: "refresh_token" }, "invalid_request", "Missing required client_id"],
        [
          { grant_type: "refresh_token", client_id: id },
          "invalid_request",
          "Missing a required refresh_token for refresh_token grant",
        ],
        [
          { grant_type: "refresh_token", client_id: id, refresh_token: "missing" },
          "invalid_grant",
          "session not found",
        ],
        [
          { grant_type: "refresh_token", client_id: "foreign", refresh_token: token.refresh_token },
          "invalid_grant",
          "invalid refresh token",
        ],
        [
          {
            grant_type: "refresh_token",
            client_id: id,
            refresh_token: token.refresh_token,
            scope: "profile",
          },
          "invalid_scope",
          "unable to issue scope profile",
        ],
      ] as const) {
        const r = await control({ action: "token", body: input });
        expect(r.status).toBe(400);
        const body = await r.json();
        expect(body).toEqual({ error, error_description });
        expect(await row("refresh", token.refresh_token)).toEqual(original);
        failures.push(body);
      }
      const rotatedResponse = await control({
        action: "token",
        body: {
          grant_type: "refresh_token",
          client_id: id,
          refresh_token: token.refresh_token,
          scope: "email",
        },
      });
      expect(rotatedResponse.status).toBe(200);
      const rotated = (await rotatedResponse.json()) as any;
      expect(rotated.scope).toBe("email");
      expect(rotated.expires_in).toBe(3600);
      expect(rotated.token_type).toBe("Bearer");
      expect(rotated.access_token).toMatch(/^[A-Za-z]{32}$/);
      expect(rotated.refresh_token).toMatch(/^[A-Za-z]{32}$/);
      expect(rotated.access_token).not.toBe(token.access_token);
      expect(rotated.refresh_token).not.toBe(token.refresh_token);
      const old = await row("refresh", token.refresh_token);
      expect(old.revoked).not.toBeNull();
      expect(old.rotatedAt).toBe(old.revoked);
      const next = await row("refresh", rotated.refresh_token);
      expect(next.scopes).toEqual(["email"]);
      expect(next.authTime).toBe(original.authTime);
      expect(next.userId).toBe(original.userId);
      expect(next.sessionId).toBe(original.sessionId);
      expect(next.authorizationCodeId).toBe(original.authorizationCodeId);
      const linked = await row("access", rotated.access_token);
      expect(linked.refreshId).toBe(next.id);
      expect(await row("access", token.access_token)).not.toBeNull();
      if (customHash) {
        for (const value of [rotated.access_token, rotated.refresh_token]) {
          const response = await control({
            action: "introspect",
            body: { client_id: id, token: value },
          });
          expect(response.status).toBe(200);
          const active = (await response.json()) as any;
          expect(active.active).toBe(true);
          expect(active.client_id).toBe(id);
          expect(active.scope).toBe("email");
        }
        const userInfo = await control({
          action: "userinfo",
          headers: { authorization: `Bearer ${rotated.access_token}` },
        });
        expect(userInfo.status).toBe(400);
        expect(await userInfo.json()).toEqual({
          error: "invalid_scope",
          error_description: "Missing required scope",
        });
        const revoked = await control({
          action: "revoke",
          body: { client_id: id, token: token.access_token },
        });
        expect(revoked.status).toBe(200);
        expect(await row("access", token.access_token)).toBeNull();
        const inactive = await control({
          action: "introspect",
          body: { client_id: id, token: token.access_token },
        });
        expect(await inactive.json()).toEqual({ active: false });
      }
      const replay = await control({
        action: "token",
        body: { grant_type: "refresh_token", client_id: id, refresh_token: token.refresh_token },
      });
      expect(replay.status).toBe(400);
      expect(await replay.json()).toEqual({
        error: "invalid_grant",
        error_description: "invalid refresh token",
      });
      for (const [kind, value] of [
        ["access", token.access_token],
        ["access", rotated.access_token],
        ["refresh", token.refresh_token],
        ["refresh", rotated.refresh_token],
      ]) {
        expect(await row(kind!, value!)).toBeNull();
      }
      return ctx.snapshot({ failures, scope: rotated.scope, replay: replay.status });
    },
  );
}
