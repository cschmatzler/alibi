import { expect } from "bun:test";

import { SignJWT } from "jose";

import { compatScenario } from "../../../support/scenario";

compatScenario(
  "verification authentic signed application claims validate before identity lookup and hooks",
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
    const email = ctx.uniqueEmail("application-claims-owner");
    const signup = await ctx
      .actor("owner", profile)
      .client.signUp.email({ email, name: "Proof Owner", password: "password123" });
    expect(signup.error).toBeNull();
    const before = await control();
    // Application-authored claims stay literal across independent server runs.
    const now = 946684800;
    const secret = new TextEncoder().encode("compat-test-only-key-not-real-minimum-32chars");
    const token = (payload: Record<string, any>) =>
      new SignJWT(payload).setProtectedHeader({ alg: "HS256" }).sign(secret);
    const valid = { email, iat: now, nbf: now - 60, exp: 4102444800 };
    const guest = ctx.actor("guest", profile);
    let cookies: string[] = [];
    const denied = [];
    for (const [label, claims] of [
      ["invalid-email", { ...valid, email: "invalid-mailbox" }],
      ["missing-email", { iat: now, exp: 4102444800 }],
      ["update-number", { ...valid, updateTo: 7 }],
      ["update-null", { ...valid, updateTo: null }],
      ["request-number", { ...valid, requestType: 7 }],
      ["request-null", { ...valid, requestType: null }],
    ] as const) {
      const response = await guest.client.verifyEmail({
        query: { token: await token(claims) },
        fetchOptions: {
          onResponse({ response }) {
            cookies = response.headers.getSetCookie();
          },
        },
      });
      expect(response.error?.status).toBe(500);
      expect(cookies.filter((cookie) => cookie.startsWith("better-auth.session"))).toEqual([]);
      expect(await control()).toEqual(before);
      denied.push({ label, response });
    }
    expect((await guest.client.getSession()).data).toBeNull();
    const accepted = await guest.client.verifyEmail({
      query: { token: await token({ ...valid, requestType: "application-control" }) },
    });
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
