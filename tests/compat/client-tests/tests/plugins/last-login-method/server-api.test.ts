import { expect } from "bun:test";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "last-login server issuance tracks cookies and stored login methods",
  async (ctx) => {
    const actor = ctx.actor();
    for (const profile of ["last-login-default", "last-login-database"]) {
      const email = ctx.uniqueEmail(`sdk-${profile}`);
      for (const action of ["sign-up", "sign-in"]) {
        const response = await actor.fetch(`${ctx.baseURL}/__test/server-api/last-login-method`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            profile,
            action,
            body: { email, name: "Owner", password: "a-native-password-123" },
          }),
        });
        expect(response.status).toBe(200);
        expect(
          response.headers
            .getSetCookie()
            .some(
              (cookie) =>
                cookie.startsWith("better-auth.last_used_login_method=email;") &&
                !cookie.includes("HttpOnly"),
            ),
        ).toBe(true);
        const state = await actor.fetch(`${ctx.baseURL}/__test/last-login-method`);
        const value = (await state.json()) as any;
        const user = value.users.find((user: any) => user.email === email);
        expect(user).toBeDefined();
        expect(user.lastLoginMethod).toBe(profile === "last-login-database" ? "email" : null);
      }
    }
    for (const mode of ["custom", "denied", "cookie-error"]) {
      await actor.fetch(`${ctx.baseURL}/__test/last-login-method`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ action: "clear" }),
      });
      const email = ctx.uniqueEmail(`sdk-last-login-${mode}`);
      const response = await actor.fetch(`${ctx.baseURL}/__test/server-api/last-login-method`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          profile: `last-login-${mode}`,
          body: { email, name: "Owner", password: "a-native-password-123" },
          headers: { "x-last-login-probe": "sdk", "x-last-login-method": "enterprise" },
          ...(mode === "custom" ? { requestHeaders: { "x-last-login-probe": "original" } } : {}),
        }),
      });
      expect(response.status).toBe(200);
      const cookies = response.headers
        .getSetCookie()
        .filter(
          (cookie) =>
            cookie.startsWith("fixture.last_login_method=") ||
            cookie.startsWith("better-auth.last_used_login_method="),
        );
      if (mode === "custom") {
        expect(cookies).toHaveLength(1);
        expect(cookies[0]!.startsWith("fixture.last_login_method=enterprise;")).toBe(true);
        expect(cookies[0]).toContain("Max-Age=123");
      } else {
        expect(cookies).toHaveLength(0);
      }
      const state = await actor.fetch(`${ctx.baseURL}/__test/last-login-method`);
      const value = (await state.json()) as any;
      expect(value.users.find((user: any) => user.email === email).lastLoginMethod).toBe(
        mode === "custom" ? "enterprise" : "email",
      );
      const resolves = value.events.filter((event: any) => event.kind === "resolve");
      expect(resolves).toHaveLength(3);
      expect(resolves[0].newSession).toBeNull();
      expect(resolves[1].newSession.session.userId).toBe(resolves[1].newSession.user.id);
      expect(resolves[2].newSession.session.userId).toBe(resolves[2].newSession.user.id);
      for (const event of value.events) {
        expect(event.path).toBe("/sign-up/email");
        expect(event.probe).toBe("sdk");
        expect(event.method).toBe(
          event.kind === "resolve" && resolves.indexOf(event) < 2 ? "POST" : null,
        );
        expect(event.body.email).toBe(email);
        if (mode === "custom") {
          expect(typeof event.requestPath).toBe("string");
        } else {
          expect(event.requestPath).toBeNull();
        }
      }
      const consent = value.events.find((event: any) => event.kind === "cookie");
      expect(consent).toBeDefined();
      expect(consent.newSession.session.userId).toBe(consent.newSession.user.id);
      await actor.fetch(`${ctx.baseURL}/__test/last-login-method`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ action: "clear" }),
      });
      const signin = await actor.fetch(`${ctx.baseURL}/__test/server-api/last-login-method`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          profile: `last-login-${mode}`,
          action: "sign-in",
          body: { email, password: "a-native-password-123" },
          headers: { "x-last-login-probe": "sdk", "x-last-login-method": "enterprise" },
        }),
      });
      expect(signin.status).toBe(200);
      const after = (await (
        await actor.fetch(`${ctx.baseURL}/__test/last-login-method`)
      ).json()) as any;
      const phases = after.events.filter((event: any) => event.kind === "resolve");
      expect(phases).toHaveLength(2);
      expect(phases[0].method).toBe("POST");
      expect(phases[0].newSession).toBeNull();
      expect(phases[1].method).toBeNull();
      expect(phases[1].newSession.session.userId).toBe(phases[1].newSession.user.id);
      for (const phase of phases) {
        expect(phase.requestPath).toBeNull();
      }
    }
    return { cookie: true, persisted: true };
  },
);
