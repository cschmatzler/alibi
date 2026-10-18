import { createHash } from "node:crypto";
import { once } from "node:events";
import { createServer } from "node:http";

import { createLocalJWKSet, jwtVerify } from "jose";
import { Cookie } from "tough-cookie";
import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";
for (const { preserve, retirement } of [false, true].flatMap((preserve) =>
  (["signout", "revoke-sessions"] as const).map((retirement) => ({ preserve, retirement })),
)) {
  compatScenario(
    `${preserve ? "preserved" : "deleted"} ${retirement} retires session-bound authority exactly once while offline refresh survives`,
    async (ctx) => {
      const receipts: { target: string; contentType?: string; accept?: string; form: string }[] =
        [];
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
        const control = (input: Record<string, unknown>) =>
          actor.fetch(`${ctx.baseURL}/__test/server-api/oauth-provider-clients`, {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({ ...input, mode: preserve ? "preserved" : "retirement" }),
          });
        if (preserve) await control({ action: "preserved-gate", gate: "", reset: true });
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
          (await control({ action: "backchannel-uri", clientId: id, uri: `${rpURL}/success` }))
            .status,
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
        expect(response.status, await response.clone().text()).toBe(200);
        expect(response.headers.get("cache-control")).toBe("no-store");
        expect(response.headers.get("pragma")).toBe("no-cache");
        const token = (await response.json()) as any;
        expect(token.scope).toBe("openid email offline_access");
        expect(token.token_type).toBe("Bearer");
        expect(token.expires_in).toBe(3600);
        expect(token.access_token).toMatch(/^[A-Za-z]{32}$/);
        expect(token.refresh_token).toMatch(/^[A-Za-z]{32}$/);
        const issueForSession = async (cookie: string, recipient = client) => {
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
          return (await issued.json()) as any;
        };
        const recipientIDs = new Map([["/success", id]]);
        // A genuine rotated/downscoped refresh token no longer carries
        // offline_access; unlike the original offline grant it must retire.
        const onlineGrant = await issueForSession(cookie);
        const downscoped = await control({
          action: "token",
          body: {
            grant_type: "refresh_token",
            client_id: id,
            client_secret: client.client_secret,
            refresh_token: onlineGrant.refresh_token,
            scope: "openid email",
          },
        });
        expect(downscoped.status).toBe(200);
        const online = (await downscoped.json()) as any;
        expect(online.scope).toBe("openid email");
        expect(online.refresh_token).toMatch(/^[A-Za-z]{32}$/);
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
          await issueForSession(cookie, recipient);
          if (target !== "no-uri") {
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
        }

        const sessionResponse = await control({ action: "session", headers: { cookie } });
        expect(sessionResponse.status).toBe(200);
        const session = (await sessionResponse.json()) as any;
        let sibling: { session: any; token: any } | undefined;
        if (retirement === "revoke-sessions") {
          const signedIn = await control({
            action: "signin",
            body: { email: session.user.email, password: "password123" },
          });
          expect(signedIn.status).toBe(200);
          const siblingCookie = signedIn.headers
            .getSetCookie()
            .filter((raw) => Boolean(Cookie.parse(raw)?.value))
            .map((raw) => raw.split(";")[0])
            .join("; ");
          const lookup = await control({ action: "session", headers: { cookie: siblingCookie } });
          expect(lookup.status).toBe(200);
          sibling = { session: await lookup.json(), token: await issueForSession(siblingCookie) };
          expect(sibling.session.session.id).not.toBe(session.session.id);
          expect(sibling.session.user.id).toBe(session.user.id);
        }
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
        const otherToken = await issueForSession(otherCookie);
        expect(otherToken.access_token).not.toBe(token.access_token);
        const before = await control({
          action: "token-row",
          kind: "access",
          token: token.access_token,
        });
        expect(before.status).toBe(200);
        const original = (await before.json()) as any;
        expect(original.revoked).toBeNull();
        const state = async (selected = session) => {
          const response = await control({
            action: "preserved-state",
            token: selected.session.token,
            sessionId: selected.session.id,
          });
          expect(response.status).toBe(200);
          return (await response.json()) as any;
        };
        if (preserve) {
          const live = await state();
          expect(live.row.id).toBe(session.session.id);
          expect(Date.parse(live.row.expiresAt)).toBeGreaterThan(Date.now());
          expect(live.cached).toBe(true);
          expect(live.completed).toEqual([]);
          if (sibling) {
            for (const gate of ["veto", "error"]) {
              await control({ action: "preserved-gate", gate });
              const attempted = await control({
                action: "end-session-rows",
                body: { userId: session.user.id },
              });
              expect(attempted.status).toBe(gate === "veto" ? 200 : 503);
              if (gate === "error") {
                expect(await attempted.json()).toEqual({
                  code: "SESSION_END_FAILED",
                  message: "application rejected deletion",
                });
              }
              for (const selected of [session, sibling.session]) {
                const unchanged = await state(selected);
                expect(unchanged.cached).toBe(true);
                expect(Date.parse(unchanged.row.expiresAt)).toBeGreaterThan(Date.now());
                expect(unchanged.completed).toEqual([]);
              }
              expect(receipts).toEqual([]);
              const row = await control({
                action: "token-row",
                kind: "access",
                token: token.access_token,
              });
              expect(((await row.json()) as any).revoked).toBeNull();
            }
          }
          await control({ action: "preserved-gate", gate: "" });
        }
        const started = Date.now();
        const ended = await control({
          action: retirement,
          headers: { cookie, origin: ctx.baseURL },
          foreignKeys: true,
        });
        const finished = Date.now();
        expect(ended.status).toBe(200);
        expect(receipts.map((receipt) => receipt.target).sort()).toEqual(
          sibling ? ["/failure", "/success", "/success"] : ["/failure", "/success"],
        );
        const jwks = await control({ action: "jwks" });
        expect(jwks.status).toBe(200);
        const keys = createLocalJWKSet((await jwks.json()) as any);
        const identifiers = new Set<string>();
        const notifiedSessions: string[] = [];
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
          notifiedSessions.push(`${receipt.target}:${payload.sid}`);
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
        expect(identifiers.size).toBe(sibling ? 3 : 2);
        const expectedSessions = [
          `/failure:${session.session.id}`,
          `/success:${session.session.id}`,
        ];
        if (sibling) expectedSessions.push(`/success:${sibling.session.session.id}`);
        expect(notifiedSessions.sort()).toEqual(expectedSessions.sort());
        for (const removed of [session, ...(sibling ? [sibling.session] : [])]) {
          if (preserve) {
            const audit = await state(removed);
            expect(audit.cached).toBe(false);
            expect(audit.row.id).toBe(removed.session.id);
            expect(Date.parse(audit.row.expiresAt)).toBeGreaterThanOrEqual(started);
            expect(Date.parse(audit.row.expiresAt)).toBeLessThanOrEqual(finished);
            expect(audit.completed.sort()).toEqual(
              [session.session.id, ...(sibling ? [sibling.session.session.id] : [])].sort(),
            );
            const liveness = await control({ action: "session", headers: { cookie } });
            expect(await liveness.json()).toBeNull();
          } else {
            const row = await control({ action: "session-row", token: removed.session.token });
            expect(row.status).toBe(200);
            expect(await row.json()).toBeNull();
          }
        }
        const afterResponse = await control({
          action: "token-row",
          kind: "access",
          token: token.access_token,
        });
        expect(afterResponse.status).toBe(200);
        const after = (await afterResponse.json()) as any;
        expect(after.id).toBe(original.id);
        expect(after.sessionId).toBe(preserve ? session.session.id : null);
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
          [online.access_token, "access_token", false],
          [online.refresh_token, "refresh_token", false],
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
        if (sibling) {
          for (const [kind, value, revoked] of [
            ["access", sibling.token.access_token, true],
            ["refresh", sibling.token.refresh_token, false],
          ] as const) {
            const row = await control({ action: "token-row", kind, token: value });
            expect(row.status).toBe(200);
            const observed = (await row.json()) as any;
            expect(observed.revoked !== null).toBe(revoked);
            expect(observed.sessionId).toBe(preserve ? sibling.session.session.id : null);
          }
        }
        const unaffected = await control({
          action: "userinfo",
          headers: { authorization: `Bearer ${otherToken.access_token}` },
        });
        expect(unaffected.status).toBe(200);
        const info = (await unaffected.json()) as any;
        expect(info.sub).toBe(otherSession.user.id);
        const survivingSession = await control({
          action: "session-row",
          token: otherSession.session.token,
        });
        expect(survivingSession.status).toBe(200);
        expect(await survivingSession.json()).toEqual({ id: otherSession.session.id });
        if (preserve) {
          const audit = await state();
          const authority = await control({
            action: "token-row",
            kind: "refresh",
            token: online.refresh_token,
          });
          const revoked = (await authority.json()) as any;
          expect(Date.parse(revoked.revoked)).toBeGreaterThanOrEqual(started);
          expect(Date.parse(revoked.revoked)).toBeLessThanOrEqual(finished);
          for (const body of [
            { token: session.session.token },
            { userId: session.user.id },
            { userId: session.user.id },
          ]) {
            const repeated = await control({ action: "end-session-rows", body });
            expect(repeated.status).toBe(200);
            expect(await state()).toEqual(audit);
            expect(receipts).toHaveLength(sibling ? 3 : 2);
            const unchanged = await control({
              action: "token-row",
              kind: "refresh",
              token: online.refresh_token,
            });
            expect(await unchanged.json()).toEqual(revoked);
          }
          // Single-session failure ordering differs from bulk: cache eviction
          // precedes the veto, but the durable row and token authority stay live.
          for (const gate of ["veto", "error"]) {
            await control({ action: "preserved-gate", gate });
            const attempted = await control({
              action: "end-session-rows",
              body: { token: otherSession.session.token },
            });
            expect(attempted.status).toBe(gate === "veto" ? 200 : 503);
            if (gate === "error") {
              expect(await attempted.json()).toEqual({
                code: "SESSION_END_FAILED",
                message: "application rejected deletion",
              });
            }
            const retained = await state(otherSession);
            expect(retained.cached).toBe(false);
            expect(Date.parse(retained.row.expiresAt)).toBeGreaterThan(Date.now());
            expect(retained.completed).toEqual(audit.completed);
            const authority = await control({
              action: "userinfo",
              headers: { authorization: `Bearer ${otherToken.access_token}` },
            });
            expect(authority.status).toBe(200);
            expect(receipts).toHaveLength(sibling ? 3 : 2);
          }
          await control({ action: "preserved-gate", gate: "" });
        }
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
}
