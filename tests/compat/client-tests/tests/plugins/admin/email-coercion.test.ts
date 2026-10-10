import { expect } from "bun:test";

import { compatScenario } from "../../../support/scenario";
import { signUpAndPromoteAdmin } from "./helpers";

compatScenario(
  "admin coerces email data before validation and accompanying updates",
  async (ctx) => {
    const admin = await signUpAndPromoteAdmin(ctx);
    expect(admin.signup.error).toBeNull();
    const owner = ctx.actor("owner");
    const signup = await owner.client.signUp.email({
      email: ctx.uniqueEmail("email-coercion"),
      name: "Original",
      password: "password123",
    });
    expect(signup.error).toBeNull();
    const userId = signup.data!.user.id;
    const before = await ctx.readUserState({ userId });
    const denied = [];
    for (const email of [null, 123, false, [], {}]) {
      const result = await admin.adminClient.admin.updateUser({
        userId,
        data: { email, name: "must-not-commit" },
      });
      expect(result.error).toMatchObject({ status: 400, code: "INVALID_EMAIL" });
      expect(await ctx.readUserState({ userId })).toEqual(before);
      denied.push(result);
    }
    const replacement = ctx.uniqueEmail("email-coercion-retry");
    const accepted = await admin.adminClient.admin.updateUser({
      userId,
      data: { email: [replacement.toUpperCase()] },
    });
    expect(accepted.error).toBeNull();
    expect(accepted.data).toMatchObject({ id: userId, email: replacement, name: "Original" });
    const login = await ctx
      .actor("login")
      .client.signIn.email({ email: replacement, password: "password123" });
    expect(login.error).toBeNull();
    expect(login.data!.user.id).toBe(userId);
    return ctx.snapshot({ signup, before, denied, accepted, login });
  },
  ["POST /admin/update-user", "POST /sign-in/email"],
);
