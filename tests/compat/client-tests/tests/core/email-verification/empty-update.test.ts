import { SignJWT } from "jose";
import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";

compatScenario(
  "signed empty updateTo verifies the current mailbox without a legacy change or delivery",
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
    const email = ctx.uniqueEmail("empty-update-owner");
    const owner = ctx.actor("owner", profile);
    const signup = await owner.client.signUp.email({
      email,
      password: "password123",
      name: "Owner",
    });
    expect(signup.error).toBeNull();
    const foreign = ctx.actor("foreign", profile);
    const foreignSignup = await foreign.client.signUp.email({
      email: ctx.uniqueEmail("empty-update-foreign"),
      password: "password123",
      name: "Foreign",
    });
    expect(foreignSignup.error).toBeNull();
    await control("reset");
    const before = await control();
    const proof = await new SignJWT({ email, updateTo: "", iat: 946684800, exp: 4102444800 })
      .setProtectedHeader({ alg: "HS256" })
      .sign(new TextEncoder().encode("compat-test-only-key-not-real-minimum-32chars"));
    const guest = ctx.actor("guest", profile);
    const verified = await guest.client.verifyEmail({ query: { token: proof } });
    expect(verified.error).toBeNull();
    expect(verified.data as unknown).toEqual({ status: true, user: null });
    const after = await control();
    const updated = after.users.find((user: any) => user.id === signup.data!.user.id);
    expect(updated).toMatchObject({ email, emailVerified: true });
    expect(after.users.filter((user: any) => user.id !== signup.data!.user.id)).toEqual(
      before.users.filter((user: any) => user.id !== signup.data!.user.id),
    );
    expect(after.accounts).toEqual(before.accounts);
    expect(after.verifications).toEqual(before.verifications);
    expect(after.sessions).toHaveLength(before.sessions.length + 1);
    for (const session of before.sessions) expect(after.sessions).toContainEqual(session);
    expect(after.events.filter((event: any) => event.stage === "verification-mail")).toEqual([]);
    expect(
      after.events
        .filter((event: any) => event.stage.includes("verification"))
        .map((event: any) => event.stage),
    ).toEqual(["before-verification", "after-verification"]);
    const current = await guest.client.getSession();
    expect(current.data!.user).toMatchObject({
      id: signup.data!.user.id,
      email,
      emailVerified: true,
    });
    const foreignCurrent = await foreign.client.getSession();
    expect(foreignCurrent.data!.user.id).toBe(foreignSignup.data!.user.id);
    expect(foreignSignup.data!.token).toBeTypeOf("string");
    expect(foreignCurrent.data!.session.token).toBe(foreignSignup.data!.token!);
    const project = (state: any) => ({
      ...state,
      accounts: state.accounts.map((account: any) => ({
        ...account,
        password: account.password ? { token: account.password } : account.password,
      })),
    });
    return ctx.snapshot({
      signup,
      foreignSignup,
      verified,
      current,
      foreignCurrent,
      before: project(before),
      after: project(after),
    });
  },
  ["GET /verify-email", "GET /get-session"],
);
