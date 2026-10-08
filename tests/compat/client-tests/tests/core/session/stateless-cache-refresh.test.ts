import { expect } from "bun:test";

import { authProfilePath } from "../../../support/profiles";
import { compatScenario } from "../../../support/scenario";
for (const mode of ["compact", "jwt", "deferred"] as const) {
  compatScenario(
    `stateless ${mode} cache renews only below configured remaining lifetime without extending the session`,
    async (ctx) => {
      const actor = ctx.actor("owner", `stateless-refresh-${mode}`);
      let issued: string[] = [];
      const signup = await actor.client.signUp.email(
        {
          email: ctx.uniqueEmail("stateless-refresh"),
          password: "password123",
          name: "Stateless refresh",
        },
        {
          onSuccess({ response }) {
            issued = response.headers.getSetCookie();
          },
        },
      );
      expect(signup.error).toBeNull();
      const cache = (cookies: string[]) =>
        cookies.find((c) => c.startsWith("better-auth.session_data="));
      expect(cache(issued)).toBeDefined();
      expect(cache(issued)).toContain("Max-Age=5");
      let immediateCookies: string[] = [];
      const immediate = await actor.client.getSession(
        {},
        {
          onSuccess({ response }) {
            immediateCookies = response.headers.getSetCookie();
          },
        },
      );
      expect(immediate.error).toBeNull();
      expect(cache(immediateCookies)).toBeUndefined();
      await Bun.sleep(1800);
      let renewedCookies: string[] = [];
      const renewed = await actor.client.getSession(
        { query: { disableRefresh: true } },
        {
          onSuccess({ response }) {
            renewedCookies = response.headers.getSetCookie();
          },
        },
      );
      expect(renewed.error).toBeNull();
      expect(renewed.data).toEqual(immediate.data);
      expect(cache(renewedCookies)).toBeDefined();
      expect(cache(renewedCookies)).toContain("Max-Age=5");
      expect(cache(renewedCookies)!.split(";")[0]).not.toBe(cache(issued)!.split(";")[0]);
      let stableCookies: string[] = [];
      const stable = await actor.client.getSession(
        {},
        {
          onSuccess({ response }) {
            stableCookies = response.headers.getSetCookie();
          },
        },
      );
      expect(stable.data).toEqual(immediate.data);
      expect(cache(stableCookies)).toBeUndefined();
      const oldVersion = await actor.fetch(
        ctx.baseURL +
          authProfilePath(mode === "jwt" ? "stateless-refresh-jwt-v2" : "stateless-refresh-v2") +
          "/get-session",
        { credentials: "omit", headers: { cookie: issued.map((c) => c.split(";")[0]).join("; ") } },
      );
      expect(oldVersion.status).toBe(200);
      expect(await oldVersion.json()).toBeNull();
      return ctx.snapshot({ signup, immediate, renewed, stable });
    },
    ["GET /get-session"],
  );
}
