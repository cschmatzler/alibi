import { expect } from "bun:test";

import { compatScenario } from "../../../support/scenario";
import { signUpAndPromoteAdmin } from "./helpers";
compatScenario(
  "admin password replacement enforces length bounds before changing credentials",
  async (ctx) => {
    const admin = await signUpAndPromoteAdmin(ctx);
    expect(admin.signup.error).toBeNull();
    const email = ctx.uniqueEmail("password-bounds-target");
    const signup = await ctx
      .actor("target")
      .client.signUp.email({ email, name: "Target", password: "password123" });
    expect(signup.error).toBeNull();
    const userId = signup.data!.user.id;
    const before = await ctx.readUserState({ userId });
    const denied = [];
    for (const [newPassword, code] of [
      ["x".repeat(7), "PASSWORD_TOO_SHORT"],
      ["x".repeat(129), "PASSWORD_TOO_LONG"],
    ]) {
      const result = await admin.adminClient.admin.setUserPassword({
        userId,
        newPassword: newPassword!,
      });
      expect(result.error).toMatchObject({ status: 400, code });
      expect(await ctx.readUserState({ userId })).toEqual(before);
      denied.push(result);
    }
    const original = await ctx
      .actor("original")
      .client.signIn.email({ email, password: "password123" });
    expect(original.error).toBeNull();
    expect(original.data!.user.id).toBe(userId);
    const accepted = [];
    for (const length of [8, 128]) {
      const password = "x".repeat(length);
      const result = await admin.adminClient.admin.setUserPassword({
        userId,
        newPassword: password,
      });
      expect(result.error).toBeNull();
      const signin = await ctx.actor("boundary-" + length).client.signIn.email({ email, password });
      expect(signin.error).toBeNull();
      expect(signin.data!.user.id).toBe(userId);
      accepted.push({ length, result, signin });
    }
    return ctx.snapshot({ signup, before, denied, original, accepted });
  },
  ["POST /admin/set-user-password", "POST /sign-in/email"],
);
