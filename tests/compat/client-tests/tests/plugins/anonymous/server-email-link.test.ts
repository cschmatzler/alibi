import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";

compatScenario(
  "anonymous SDK email completion transfers the actual owner and retires old authority",
  async (ctx) => {
    const results = [];
    const email = ctx.uniqueEmail("anonymous-sdk-owner");
    for (const action of ["sign-up", "sign-in"]) {
      const issued = await ctx
        .actor(`anonymous-${action}`)
        .fetch(`${ctx.baseURL}/__test/server-api/anonymous-sign-in`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ headers: {} }),
        });
      expect(issued.status).toBe(200);
      const anonymous = { status: issued.status, body: await issued.json() };
      const cookie = issued.headers
        .getSetCookie()
        .map((value) => value.split(";")[0])
        .join("; ");
      const before = await ctx.rawRequest({ path: "/__test/anonymous/state" });
      const oldUser = (anonymous.body as any).user.id;
      const session = (before.body as any).sessions.find((row: any) => row.userId === oldUser);
      expect(session).toBeDefined();
      // Reuse the cookie issued by the genuine anonymous operation as explicit SDK headers.
      expect(cookie).toContain("session_token=");
      const result = await ctx.rawRequest({
        path: "/__test/server-api/anonymous-email",
        method: "POST",
        json: {
          action,
          headers: { cookie },
          body: { email, name: "SDK Owner", password: "password123" },
        },
      });
      expect(result.status).toBe(200);
      const newUser = (result.body as any).user.id;
      expect(newUser).not.toBe(oldUser);
      const state = await ctx.rawRequest({ path: "/__test/anonymous/state" });
      const stored = state.body as any;
      expect(stored.users.some((row: any) => row.id === oldUser)).toBe(false);
      expect(stored.sessions.some((row: any) => row.userId === oldUser)).toBe(false);
      expect(stored.events.at(-1)).toMatchObject({
        path: action === "sign-up" ? "/sign-up/email" : "/sign-in/email",
        request: null,
        anonymousUser: { user: { id: oldUser }, session: { id: session.id } },
        newUser: { user: { id: newUser }, session: { userId: newUser } },
      });
      results.push({ anonymous, result, state });
    }
    return ctx.snapshot({ results });
  },
  ["POST /sign-up/email", "POST /sign-in/email"],
);
