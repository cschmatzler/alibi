import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";

compatScenario("sign out after sign-in invalidates session", async (ctx) => {
  const primary = ctx.actor();
  const email = ctx.uniqueEmail("core-signout");
  await primary.client.signUp.email({
    email,
    password: "password123",
    name: "Signout User",
  });

  const before = await primary.client.getSession();
  const signout = await primary.client.signOut();
  const after = await primary.client.getSession();

  return {
    before: ctx.snapshot(before),
    signout: ctx.snapshot(signout),
    after: ctx.snapshot(after),
  };
});

compatScenario("sign out without auth still succeeds", async (ctx) => {
  const primary = ctx.actor();
  const signout = await primary.client.signOut();

  return {
    signout: ctx.snapshot(signout),
  };
});

compatScenario(
  "sign out rejects repeated callback query values before retiring the session",
  async (ctx) => {
    const primary = ctx.actor();
    const signup = await primary.client.signUp.email({
      email: ctx.uniqueEmail("signout-query"),
      password: "password123",
      name: "Signout Query Owner",
    });
    expect(signup.error).toBeNull();
    const before = await ctx.readUserState({ userId: signup.data!.user.id });
    const rejected = [];
    for (const values of [
      ["/first", "/second"],
      ["/first", ""],
      ["", ""],
    ]) {
      const query = new URLSearchParams(values.map((value) => ["callbackURL", value]));
      const response = await primary.fetch(`/api/auth/sign-out?${query}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: "{}",
      });
      expect(response.status).toBe(400);
      const body = await response.json();
      expect(body).toEqual({ message: "Invalid callbackURL: expected a string" });
      expect(response.headers.getSetCookie()).toEqual([]);
      expect(await ctx.readUserState({ userId: signup.data!.user.id })).toEqual(before);
      expect((await primary.client.getSession()).data?.session.token).toBe(signup.data!.token);
      rejected.push({ values, status: response.status, body });
    }
    const signout = await primary.fetch("/api/auth/sign-out?callbackURL=%2Fsingle", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}",
    });
    expect(signout.status).toBe(200);
    expect(await signout.json()).toEqual({ success: true });
    const after = await primary.client.getSession();
    expect(after.data).toBeNull();
    return ctx.snapshot({ signup, before, rejected, after });
  },
);
