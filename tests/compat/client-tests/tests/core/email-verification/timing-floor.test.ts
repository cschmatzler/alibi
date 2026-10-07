import { expect } from "bun:test";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "guest verification send enforces its timing floor for absent verified and unverified owners",
  async (ctx) => {
    const profile = "user-lifecycle-auto";
    const control = async (action = "state") => {
      const r = await ctx.rawRequest({
        path: "/__test/user-lifecycle/control",
        method: "POST",
        json: { profile: "auto", action },
      });
      expect(r.status).toBe(200);
      return r.body as any;
    };
    await control("reset");
    const email = ctx.uniqueEmail("timing-owner");
    const owner = ctx.actor("owner", profile);
    const signup = await owner.client.signUp.email({
      email,
      name: "Owner",
      password: "password123",
    });
    expect(signup.error).toBeNull();
    expect((await owner.client.sendVerificationEmail({ email })).error).toBeNull();
    const token = (await control()).events
      .filter((e: any) => e.stage === "verification-mail")
      .at(-1).token;
    expect((await owner.client.verifyEmail({ query: { token } })).error).toBeNull();
    const before = await control();
    expect(before.users.find((u: any) => u.id === signup.data!.user.id).emailVerified).toBe(true);
    const unknown = ctx.uniqueEmail("timing-missing");
    const results = [];
    for (const address of [unknown, email]) {
      const started = performance.now();
      const result = await ctx
        .actor("guest", profile)
        .client.sendVerificationEmail({ email: address });
      const elapsed = performance.now() - started;
      expect(result.error).toBeNull();
      expect(result.data).toEqual({ status: true });
      expect(elapsed).toBeGreaterThanOrEqual(490);
      expect(await control()).toEqual(before);
      results.push({ kind: address === email ? "verified" : "missing", result, floorMet: true });
    }
    const pendingEmail = ctx.uniqueEmail("timing-pending");
    const pending = await ctx
      .actor("pending", profile)
      .client.signUp.email({ email: pendingEmail, name: "Pending", password: "password123" });
    expect(pending.error).toBeNull();
    await control("reset");
    const pendingBefore = await control();
    const start = performance.now();
    const sent = await ctx
      .actor("guest", profile)
      .client.sendVerificationEmail({ email: pendingEmail });
    expect(performance.now() - start).toBeGreaterThanOrEqual(490);
    expect(sent.error).toBeNull();
    const after = await control();
    const delivered = after.events.filter((e: any) => e.stage === "verification-mail");
    expect(delivered).toHaveLength(1);
    expect(delivered[0].user.id).toBe(pending.data!.user.id);
    expect(after.users).toEqual(pendingBefore.users);
    expect(after.accounts).toEqual(pendingBefore.accounts);
    expect(after.sessions).toEqual(pendingBefore.sessions);
    const project = (s: any) => ({
      ...s,
      accounts: s.accounts.map((a: any) => ({
        ...a,
        password: a.password ? { token: a.password } : a.password,
      })),
    });
    return ctx.snapshot({
      signup,
      results,
      pending,
      sent,
      before: project(before),
      pendingBefore: project(pendingBefore),
      after: project(after),
    });
  },
  ["POST /send-verification-email"],
);
