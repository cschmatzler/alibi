import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";

compatScenario(
  "custom session server device lists honor mutation options and callback context",
  async (ctx) => {
    for (const profile of [
      "custom-session-server",
      "custom-session-list-default",
      "custom-session-list-false",
    ]) {
      const actor = ctx.actor(profile);
      const enabled = profile === "custom-session-server";
      const proofs: string[] = [];
      const owners: string[] = [];
      for (const name of ["first", "second"]) {
        const response = await actor.fetch(
          `${ctx.baseURL}/__test/profiles/${profile}/api/auth/sign-up/email`,
          {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({
              email: ctx.uniqueEmail(`${profile}-${name}`),
              name,
              password: "a-native-password-123",
            }),
          },
        );
        expect(response.status).toBe(200);
        owners.push(((await response.json()) as any).user.id);
        proofs.push(
          ...response.headers
            .getSetCookie()
            .filter((cookie) => cookie.startsWith("better-auth.session_token_multi-"))
            .map((cookie) => cookie.split(";")[0]!),
        );
      }
      const control = (mode = "", original = false, cookie = proofs.join("; ")) =>
        actor.fetch(`${ctx.baseURL}/__test/server-api/custom-session`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            profile,
            action: "list",
            headers: { cookie, "x-custom-session": mode, "x-custom-marker": "sdk" },
            ...(original ? { requestHeaders: { "x-custom-marker": "original" } } : {}),
          }),
        });
      const listed = await control();
      expect(listed.status).toBe(200);
      const rows = (await listed.json()) as any[];
      expect(rows).toHaveLength(2);
      for (const row of rows) {
        expect(owners).toContain(row.user.id);
        if (enabled) {
          expect(row.application).toMatchObject({
            userId: row.user.id,
            path: "/multi-session/list-device-sessions",
            hasRequest: false,
            marker: "sdk",
          });
        } else {
          expect(row.application).toBeUndefined();
        }
      }
      if (enabled) {
        const original = await control("", true);
        expect(original.status).toBe(200);
        for (const row of (await original.json()) as any[]) {
          expect(row.application.hasRequest).toBe(true);
          expect(row.application.marker).toBe("sdk");
        }
        const filtered = await control("filtered");
        expect(filtered.status).toBe(200);
        for (const row of (await filtered.json()) as any[]) {
          expect(owners).toContain(row.userId);
          expect(row.session).toBeUndefined();
        }
        const nil = await control("null");
        expect(nil.status).toBe(200);
        expect(await nil.json()).toEqual([null, null]);
        const denied = await control("error");
        expect(denied.status).toBe(403);
        expect(await denied.json()).toEqual({
          code: "CUSTOM_SESSION_DENIED",
          message: "Application session denied",
        });
      } else {
        expect((await control("error")).status).toBe(200);
      }
      const empty = await control("error", false, "");
      expect(empty.status).toBe(200);
      expect(await empty.json()).toEqual([]);
    }
    return { options: true, context: true, projection: true };
  },
);
