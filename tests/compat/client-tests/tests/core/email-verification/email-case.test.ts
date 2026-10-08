import { expect } from "bun:test";

import { jwtVerify } from "jose";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "authenticated case-varied verification email delivers and signs the canonical stored identity",
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
    const email = ctx.uniqueEmail("canonical-proof");
    const owner = ctx.actor("owner", profile);
    const signup = await owner.client.signUp.email({
      email: email.toUpperCase(),
      name: "Canonical owner",
      password: "password123",
    });
    expect(signup.error).toBeNull();
    expect(signup.data!.user.email).toBe(email);
    const sent = await owner.client.sendVerificationEmail({ email: email.toUpperCase() });
    expect(sent.error).toBeNull();
    const before = await control();
    const deliveries = before.events.filter((e: any) => e.stage === "verification-mail");
    expect(deliveries).toHaveLength(1);
    const delivered = deliveries[0];
    expect(delivered.user.email).toBe(email);
    const verified = await jwtVerify(
      delivered.token,
      new TextEncoder().encode("compat-test-only-key-not-real-minimum-32chars"),
      { algorithms: ["HS256"] },
    );
    expect(verified.payload.email).toBe(email);
    expect(verified.payload.exp! - verified.payload.iat!).toBe(90);
    expect(new URL(delivered.url).searchParams.get("token")).toBe(delivered.token);
    const accepted = await owner.client.verifyEmail({ query: { token: delivered.token } });
    expect(accepted.error).toBeNull();
    const after = await control();
    expect(after.users.find((u: any) => u.id === signup.data!.user.id)).toMatchObject({
      email,
      emailVerified: true,
    });
    expect(after.accounts).toEqual(before.accounts);
    expect(after.sessions).toEqual(before.sessions);
    const session = await owner.client.getSession();
    expect(session.data!.user).toMatchObject({
      id: signup.data!.user.id,
      email,
      emailVerified: true,
    });
    const project = (s: any) => ({
      ...s,
      accounts: s.accounts.map((a: any) => ({
        ...a,
        password: a.password ? { token: a.password } : a.password,
      })),
    });
    return ctx.snapshot({
      signup,
      sent,
      accepted,
      session,
      claims: { token: delivered.token },
      before: project(before),
      after: project(after),
    });
  },
  ["POST /send-verification-email", "GET /verify-email"],
);
