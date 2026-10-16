import { createHash } from "node:crypto";
import { createServer } from "node:http";
import { once } from "node:events";
import { createLocalJWKSet, jwtVerify } from "jose";

import { Cookie } from "tough-cookie";
import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "Sign-out retires session-bound access tokens while offline refresh authority survives",
  async (ctx) => {
    const receipts: {
      target: string;
      contentType?: string;
      accept?: string;
      form: string;
    }[] = [];
    const rp = createServer(async (request, response) => {
      let form = "";
      for await (const chunk of request) form += chunk;
      receipts.push({
        target: request.url!,
        contentType: request.headers["content-type"],
        accept: request.headers.accept,
        form,
      });
      response.writeHead(request.url === "/failure" ? 503 : 204).end();
    });
    rp.listen(0, "127.0.0.1");
    await once(rp, "listening");
    const rpURL = `http://127.0.0.1:${(rp.address() as { port: number }).port}`;
    try {
      const actor = ctx.actor();
      const control = (input: unknown) =>
        actor.fetch(`${ctx.baseURL}/__test/server-api/oauth-provider-clients`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(input),
        });
      const signup = await control({
        action: "signup",
        body: {
          email: ctx.uniqueEmail("retirement-owner"),
          name: "Native owner",
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
          client_name: "Token client",
          redirect_uris: ["https://app.fixture.test/callback"],
          scope: "openid email offline_access",
          token_endpoint_auth_method: "client_secret_post",
          skip_consent: true,
          grant_types: ["authorization_code", "refresh_token"],
          enable_end_session: true,
        },
      });
      expect(created.status).toBe(201);
      const client = (await created.json()) as any;
      const id = client.client_id;
      expect(
        (
          await control({
            action: "backchannel-uri",
            clientId: id,
            uri: `${rpURL}/success`,
          })
        ).status,
      ).toBe(200);
      expect(typeof client.client_secret).toBe("string");
      const verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
      const challenge = createHash("sha256").update(verifier).digest("base64url");
      const grant = await control({
        action: "authorize",
        headers: { cookie, accept: "application/json" },
        query: {
          client_id: id,
          response_type: "code",
          redirect_uri: "https://app.fixture.test/callback",
          scope: "openid email offline_access",
          state: "token-state",
          nonce: "oidc-nonce",
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
      const input = {
        grant_type: "authorization_code",
        client_id: id,
        client_secret: client.client_secret,
        code,
        code_verifier: verifier,
        redirect_uri: "https://app.fixture.test/callback",
      };
      const response = await control({ action: "token", body: input });
      expect(response.status).toBe(200);
      expect(response.headers.get("cache-control")).toBe("no-store");
      expect(response.headers.get("pragma")).toBe("no-cache");
      const token = (await response.json()) as any;
      expect(token.scope).toBe("openid email offline_access");
      expect(token.token_type).toBe("Bearer");
      expect(token.expires_in).toBe(3600);
      expect(token.access_token).toMatch(/^[A-Za-z]{32}$/);
      expect(token.refresh_token).toMatch(/^[A-Za-z]{32}$/);
      const recipientIDs = new Map([["/success", id]]);
      for (const target of ["failure", "disabled", "no-uri"]) {
        const created = await control({
          action: "admin-create",
          headers: { cookie },
          body: {
            client_name: target,
            redirect_uris: ["https://app.fixture.test/callback"],
            scope: "openid email offline_access",
            token_endpoint_auth_method: "client_secret_post",
            skip_consent: true,
            grant_types: ["authorization_code", "refresh_token"],
          },
        });
        expect(created.status).toBe(201);
        const recipient = (await created.json()) as any;
        recipientIDs.set(`/${target}`, recipient.client_id);
        const grant = await control({
          action: "authorize",
          headers: { cookie, accept: "application/json" },
          query: {
            client_id: recipient.client_id,
            response_type: "code",
            redirect_uri: input.redirect_uri,
            scope: "openid email offline_access",
            code_challenge: challenge,
            code_challenge_method: "S256",
          },
        });
        expect(grant.status).toBe(200);
        const code = new URL(((await grant.json()) as any).url).searchParams.get("code");
        const issued = await control({
          action: "token",
          body: {
            ...input,
            client_id: recipient.client_id,
            client_secret: recipient.client_secret,
            code,
          },
        });
        expect(issued.status).toBe(200);
        if (target !== "no-uri")
          expect(
            (
              await control({
                action: "backchannel-uri",
                clientId: recipient.client_id,
                uri: `${rpURL}/${target}`,
                disabled: target === "disabled",
              })
            ).status,
          ).toBe(200);
      }

      const sessionResponse = await control({
        action: "session",
        headers: { cookie },
      });
      expect(sessionResponse.status).toBe(200);
      const session = (await sessionResponse.json()) as any;
      const otherSignup = await control({
        action: "signup",
        body: {
          email: ctx.uniqueEmail("retirement-other"),
          name: "Native owner",
          password: "password123",
        },
      });
      expect(otherSignup.status).toBe(200);
      const otherCookie = otherSignup.headers
        .getSetCookie()
        .filter((raw) => Boolean(Cookie.parse(raw)?.value))
        .map((raw) => raw.split(";")[0])
        .join("; ");
      const otherSessionResponse = await control({
        action: "session",
        headers: { cookie: otherCookie },
      });
      expect(otherSessionResponse.status).toBe(200);
      const otherSession = (await otherSessionResponse.json()) as any;
      const otherGrant = await control({
        action: "authorize",
        headers: { cookie: otherCookie, accept: "application/json" },
        query: {
          client_id: id,
          response_type: "code",
          redirect_uri: "https://app.fixture.test/callback",
          scope: "openid email offline_access",
          state: "token-state",
          nonce: "oidc-nonce",
          code_challenge: challenge,
          code_challenge_method: "S256",
        },
      });
      expect(otherGrant.status).toBe(200);
      const otherCode = new URL(((await otherGrant.json()) as any).url).searchParams.get("code");
      const issuedOther = await control({
        action: "token",
        body: { ...input, code: otherCode },
      });
      expect(issuedOther.status).toBe(200);
      const otherToken = (await issuedOther.json()) as any;
      expect(otherToken.access_token).not.toBe(token.access_token);
      const before = await control({
        action: "token-row",
        kind: "access",
        token: token.access_token,
      });
      expect(before.status).toBe(200);
      const original = (await before.json()) as any;
      expect(original.revoked).toBeNull();
      const started = Date.now();
      const ended = await control({
        action: "signout",
        headers: { cookie, origin: ctx.baseURL },
        foreignKeys: true,
      });
      const finished = Date.now();
      expect(ended.status).toBe(200);
      expect(receipts.map((receipt) => receipt.target).sort()).toEqual(["/failure", "/success"]);
      const jwks = await control({ action: "jwks" });
      expect(jwks.status).toBe(200);
      const keys = createLocalJWKSet((await jwks.json()) as any);
      const identifiers = new Set<string>();
      for (const receipt of receipts) {
        expect(receipt.contentType).toBe("application/x-www-form-urlencoded");
        expect(receipt.accept).toBe("application/json");
        const form = new URLSearchParams(receipt.form);
        expect([...form.keys()]).toEqual(["logout_token"]);
        const { payload, protectedHeader } = await jwtVerify(form.get("logout_token")!, keys, {
          issuer: `${ctx.baseURL}/api/auth`,
          audience: recipientIDs.get(receipt.target),
        });
        expect(protectedHeader.typ).toBe("logout+jwt");
        expect(payload.sub).toBe(session.user.id);
        expect(payload.sid).toBe(session.session.id);
        expect(payload.iat).toBeGreaterThanOrEqual(Math.floor(started / 1000));
        expect(payload.iat).toBeLessThanOrEqual(Math.floor(finished / 1000));
        expect(payload.exp! - payload.iat!).toBe(120);
        expect(payload.jti).toMatch(/^[A-Za-z0-9]{32}$/);
        expect(payload.events).toEqual({
          "http://schemas.openid.net/event/backchannel-logout": {},
        });
        expect(payload).not.toHaveProperty("nonce");
        identifiers.add(payload.jti!);
      }
      expect(identifiers.size).toBe(2);
      const afterResponse = await control({
        action: "token-row",
        kind: "access",
        token: token.access_token,
      });
      expect(afterResponse.status).toBe(200);
      const after = (await afterResponse.json()) as any;
      expect(after.id).toBe(original.id);
      expect(after.sessionId).toBeNull();
      expect(Date.parse(after.revoked)).toBeGreaterThanOrEqual(started);
      expect(Date.parse(after.revoked)).toBeLessThanOrEqual(finished);
      const denied = await control({
        action: "userinfo",
        headers: { authorization: `Bearer ${token.access_token}` },
      });
      expect(denied.status).toBe(401);
      expect(await denied.json()).toEqual({
        error: "invalid_token",
        error_description: "Invalid access token",
      });
      const results = [];
      for (const [value, hint, active] of [
        [token.access_token, "access_token", false],
        [token.refresh_token, "refresh_token", true],
      ] as const) {
        const observed = await control({
          action: "introspect",
          body: {
            client_id: id,
            client_secret: client.client_secret,
            token: value,
            token_type_hint: hint,
          },
        });
        expect(observed.status).toBe(200);
        const body = (await observed.json()) as any;
        expect(body.active).toBe(active);
        results.push({ hint, active: body.active });
      }
      const refreshed = await control({
        action: "token-row",
        kind: "refresh",
        token: token.refresh_token,
      });
      expect(refreshed.status).toBe(200);
      expect(((await refreshed.json()) as any).revoked).toBeNull();
      const unaffected = await control({
        action: "userinfo",
        headers: { authorization: `Bearer ${otherToken.access_token}` },
      });
      expect(unaffected.status).toBe(200);
      const info = (await unaffected.json()) as any;
      expect(info.sub).toBe(otherSession.user.id);
      return ctx.snapshot({
        authorizationSession: session,
        otherAuthorizationSession: otherSession,
        unaffected: unaffected.status,
        ended: ended.status,
        denied: denied.status,
        results,
        notified: receipts.map((receipt) => receipt.target).sort(),
      });
    } finally {
      rp.closeAllConnections();
      await new Promise<void>((resolve, reject) =>
        rp.close((error) => (error ? reject(error) : resolve())),
      );
    }
  },
);
