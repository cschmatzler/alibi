import { expect } from "bun:test";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "verification sender reads original parsed HTTP JSON bodies for signup gated signin and direct send",
  async (ctx) => {
    const profile = "user-lifecycle-request-body";
    const control = async () => {
      const r = await ctx.rawRequest({
        path: "/__test/user-lifecycle/control",
        method: "POST",
        json: { profile: "request-body", action: "state" },
      });
      expect(r.status).toBe(200);
      return r.body as any;
    };
    const actor = ctx.actor("owner", profile);
    const email = ctx.uniqueEmail("request-body-owner");
    const signupBody = {
      email,
      name: "Body owner",
      password: "password123",
      applicationMarker: "signup-original",
    };
    const signup = await actor.client.signUp.email(signupBody, {
      headers: { "x-lifecycle-marker": "signup-header" },
    });
    expect(signup.error).toBeNull();
    expect(signup.data!.token).toBeNull();
    let state = await control();
    let delivered = state.events.filter((e: any) => e.stage === "verification-mail");
    expect(delivered).toHaveLength(1);
    expect(delivered[0].requestBody).toEqual(signupBody);
    expect(delivered[0].request.marker).toBe("signup-header");
    const before = state;
    // JWT issuance uses whole seconds; separate sends so token identity is deterministic.
    await Bun.sleep(1100);
    const signinBody = { email, password: "password123", applicationMarker: "signin-original" };
    const gated = await actor.client.signIn.email(signinBody, {
      headers: { "x-lifecycle-marker": "signin-header" },
    });
    expect(gated.error).toMatchObject({ status: 403, code: "EMAIL_NOT_VERIFIED" });
    state = await control();
    delivered = state.events.filter((e: any) => e.stage === "verification-mail");
    expect(delivered).toHaveLength(2);
    expect(delivered[1].requestBody).toEqual(signinBody);
    expect(delivered[1].request.marker).toBe("signin-header");
    await Bun.sleep(1100);
    const sendBody = { email, applicationMarker: "direct-original" };
    const sent = await actor.client.sendVerificationEmail(sendBody, {
      headers: { "x-lifecycle-marker": "direct-header" },
    });
    expect(sent.error).toBeNull();
    state = await control();
    delivered = state.events.filter((e: any) => e.stage === "verification-mail");
    expect(delivered).toHaveLength(3);
    expect(delivered[2].requestBody).toEqual(sendBody);
    expect(delivered[2].request.marker).toBe("direct-header");
    expect(state.users).toEqual(before.users);
    expect(state.accounts).toEqual(before.accounts);
    expect(state.sessions).toEqual([]);
    const accepted = await actor.client.verifyEmail({ query: { token: delivered[2].token } });
    expect(accepted.error).toBeNull();
    const retry = await actor.client.signIn.email({ email, password: "password123" });
    expect(retry.error).toBeNull();
    expect(retry.data!.user.id).toBe(signup.data!.user.id);
    expect(retry.data!.user.emailVerified).toBe(true);
    const after = await control();
    expect(after.sessions).toHaveLength(1);
    const project = (s: any) => ({
      ...s,
      accounts: s.accounts.map((a: any) => ({
        ...a,
        password: a.password ? { token: a.password } : a.password,
      })),
    });
    return ctx.snapshot({
      signup,
      gated,
      sent,
      accepted,
      retry,
      before: project(before),
      state: project(state),
      after: project(after),
    });
  },
  ["POST /sign-up/email", "POST /sign-in/email", "POST /send-verification-email"],
);
