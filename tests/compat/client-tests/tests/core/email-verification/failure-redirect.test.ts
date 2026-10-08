import { expect } from "bun:test";

import { SignJWT } from "jose";

import { authProfilePath } from "../../../support/profiles";
import { compatScenario } from "../../../support/scenario";
compatScenario(
  "verification failure redirects append errors after existing encoded query and before fragments",
  async (ctx) => {
    const profile = "user-lifecycle-auto";
    const control = async () => {
      const r = await ctx.rawRequest({
        path: "/__test/user-lifecycle/control",
        method: "POST",
        json: { profile: "auto", action: "state" },
      });
      expect(r.status).toBe(200);
      return r.body as any;
    };
    const email = ctx.uniqueEmail("redirect-owner");
    const signup = await ctx
      .actor("owner", profile)
      .client.signUp.email({ email, name: "Owner", password: "password123" });
    expect(signup.error).toBeNull();
    const before = await control();
    const now = Math.floor(Date.now() / 1000);
    const secret = new TextEncoder().encode("compat-test-only-key-not-real-minimum-32chars");
    const sign = (email: string, exp: number) =>
      new SignJWT({ email, iat: now - 60, exp }).setProtectedHeader({ alg: "HS256" }).sign(secret);
    const callback = "/done?email=a%2Bb%40fixture.test&error=old#fragment";
    const observations = [];
    for (const [token, code] of [
      ["not-a-jwt", "INVALID_TOKEN"],
      [await sign(email, now - 30), "TOKEN_EXPIRED"],
      [await sign(ctx.uniqueEmail("missing-owner"), now + 3600), "USER_NOT_FOUND"],
    ] as const) {
      const response = await ctx
        .actor("guest", profile)
        .fetch(
          ctx.baseURL +
            authProfilePath(profile) +
            "/verify-email?" +
            new URLSearchParams({ token, callbackURL: callback }),
          { redirect: "manual" },
        );
      const observed = {
        status: response.status,
        location: response.headers.get("location"),
        body: await response.text(),
        cookies: response.headers.getSetCookie(),
      };
      expect(observed).toEqual({
        status: 302,
        location: "/done?email=a%2Bb%40fixture.test&error=old&error=" + code + "#fragment",
        body: "",
        cookies: [],
      });
      expect(await control()).toEqual(before);
      observations.push(observed);
    }
    const accepted = await ctx
      .actor("guest", profile)
      .client.verifyEmail({ query: { token: await sign(email, now + 3600) } });
    expect(accepted.error).toBeNull();
    expect((await ctx.actor("guest", profile).client.getSession()).data!.user.id).toBe(
      signup.data!.user.id,
    );
    const project = (s: any) => ({
      ...s,
      accounts: s.accounts.map((a: any) => ({
        ...a,
        password: a.password ? { token: a.password } : a.password,
      })),
    });
    return ctx.snapshot({ signup, observations, before: project(before), accepted });
  },
  ["GET /verify-email"],
);
