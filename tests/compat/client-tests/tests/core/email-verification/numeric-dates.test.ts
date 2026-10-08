import { expect } from "bun:test";

import { SignJWT } from "jose";

import { compatScenario } from "../../../support/scenario";

compatScenario(
  "verification signed NumericDate claims reject strings nulls and booleans before any side effect",
  async (ctx) => {
    const profile = "user-lifecycle-auto";
    const control = async (action = "state") => {
      const response = await ctx.rawRequest({
        path: "/__test/user-lifecycle/control",
        method: "POST",
        json: { profile: "auto", action },
      });
      expect(response.status).toBe(200);
      return response.body as any;
    };
    await control("reset");
    const email = ctx.uniqueEmail("numeric-date-owner");
    const signup = await ctx
      .actor("owner", profile)
      .client.signUp.email({ email, name: "Proof Owner", password: "password123" });
    expect(signup.error).toBeNull();
    const before = await control();
    const secret = new TextEncoder().encode("compat-test-only-key-not-real-minimum-32chars");
    const token = (payload: Record<string, any>) =>
      new SignJWT(payload).setProtectedHeader({ alg: "HS256" }).sign(secret);
    // Fixed application claims isolate type validation from independent wall clocks.
    const valid = { email, iat: 946684800, nbf: 946684740, exp: 4102444800 };
    const guest = ctx.actor("guest", profile);
    let cookies: string[] = [];
    const denied = [];
    for (const field of ["iat", "nbf", "exp"] as const) {
      for (const value of [String(valid[field]), null, false]) {
        const response = await guest.client.verifyEmail({
          query: { token: await token({ ...valid, [field]: value }) },
          fetchOptions: {
            onResponse({ response }) {
              cookies = response.headers.getSetCookie();
            },
          },
        });
        expect(response.error).toMatchObject({ status: 401, code: "INVALID_TOKEN" });
        expect(cookies.filter((cookie) => cookie.startsWith("better-auth.session"))).toEqual([]);
        expect(await control()).toEqual(before);
        denied.push({ field, value, response });
      }
    }
    expect((await guest.client.getSession()).data).toBeNull();
    const accepted = await guest.client.verifyEmail({ query: { token: await token(valid) } });
    expect(accepted.error).toBeNull();
    const after = await control();
    expect(after.users.find((user: any) => user.id === signup.data!.user.id).emailVerified).toBe(
      true,
    );
    expect(after.accounts).toEqual(before.accounts);
    expect(after.sessions.length).toBe(before.sessions.length + 1);
    expect(
      after.events.filter(
        (event: any) => event.stage.includes("verification") && !event.stage.includes("mail"),
      ).length,
    ).toBeGreaterThan(0);
    const session = await guest.client.getSession();
    expect(session.data!.user.id).toBe(signup.data!.user.id);
    const project = (state: any) => ({
      ...state,
      accounts: state.accounts.map((account: any) => ({
        ...account,
        password: account.password ? { token: account.password } : account.password,
      })),
    });
    return ctx.snapshot({
      signup,
      denied,
      cookies,
      accepted,
      session,
      before: project(before),
      after: project(after),
    });
  },
  ["GET /verify-email", "GET /get-session"],
);
