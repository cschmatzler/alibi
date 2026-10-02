import { expect } from "bun:test";

import { compatScenario } from "../support/scenario";

// Run with actual fixture processes initialized in development/test mode, or
// with the published TEST environment flag. The regular production suite
// independently proves unresolved addresses remain empty.
compatScenario(
  "client IP actual process environment fallback preserves tracking opt-out",
  async (ctx) => {
    const observations = [];
    for (const profile of ["client-ip-default", "client-ip-empty", "client-ip-disabled"] as const) {
      const actor = ctx.actor(profile, profile);
      const signup = await actor.client.signUp.email(
        { email: ctx.uniqueEmail(profile), password: "Password123!", name: "Environment Owner" },
        { headers: { "user-agent": "environment-browser" } },
      );
      expect(signup.error).toBeNull();

      const physical = await ctx.rawRequest({ path: "/__test/client-ip/sessions" });
      expect(physical.status).toBe(200);

      const rows = physical.body as Array<Record<string, unknown>>;
      const row = rows.find((row) => row.userId === signup.data!.user.id)!;
      expect(row.ipAddress).toBe(profile === "client-ip-disabled" ? "" : "127.0.0.1");
      expect(row.userAgent).toBe("environment-browser");

      const current = await actor.client.getSession();
      expect(current.data?.session).toMatchObject({
        id: row.id,
        token: row.token,
        ipAddress: row.ipAddress,
        userAgent: "environment-browser",
      });

      const denied = await actor.client.signIn.email({
        email: signup.data!.user.email,
        password: "wrong-password",
      });
      expect(denied.error?.status).toBe(401);
      expect((await ctx.rawRequest({ path: "/__test/client-ip/sessions" })).body).toEqual(rows);

      const signOut = await actor.client.signOut();
      expect(signOut.error).toBeNull();
      expect((await actor.client.getSession()).data).toBeNull();

      const after = await ctx.rawRequest({ path: "/__test/client-ip/sessions" });
      expect(after.body).toEqual(rows.filter((value) => value.id !== row.id));

      observations.push({
        profile,
        signup: ctx.snapshot(signup),
        physical,
        current: ctx.snapshot(current),
        denied: ctx.snapshot(denied),
        signOut: ctx.snapshot(signOut),
        after,
      });
    }
    return { observations };
  },
);
