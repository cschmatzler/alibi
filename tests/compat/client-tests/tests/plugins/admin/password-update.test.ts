import { expect } from "bun:test";

import { compatScenario } from "../../../support/scenario";
import { signUpAndPromoteAdmin } from "./helpers";
compatScenario(
  "admin update-user rejects password and accompanying mutations as one request",
  async (ctx) => {
    const admin = await signUpAndPromoteAdmin(ctx);
    expect(admin.signup.error).toBeNull();
    const target = ctx.actor("target");
    const email = ctx.uniqueEmail("password-update-target");
    const signup = await target.client.signUp.email({
      email,
      name: "Original target",
      password: "password123",
    });
    expect(signup.error).toBeNull();
    const before = await ctx.readUserState({ userId: signup.data!.user.id });
    const denied = await admin.adminClient.admin.updateUser({
      userId: signup.data!.user.id,
      data: { password: "replacement-password", name: "must-not-commit" },
    });
    expect(denied.error).toMatchObject({
      status: 400,
      code: "PASSWORD_CANNOT_BE_UPDATED_VIA_UPDATE_USER",
    });
    const after = await ctx.readUserState({ userId: signup.data!.user.id });
    expect(after).toEqual(before);
    const wrong = await ctx
      .actor("wrong")
      .client.signIn.email({ email, password: "replacement-password" });
    expect(wrong.error).toMatchObject({ status: 401, code: "INVALID_EMAIL_OR_PASSWORD" });
    expect(await ctx.readUserState({ userId: signup.data!.user.id })).toEqual(before);
    const original = await ctx
      .actor("original")
      .client.signIn.email({ email, password: "password123" });
    expect(original.error).toBeNull();
    expect(original.data!.user.name).toBe("Original target");
    expect(original.data!.user.id).toBe(signup.data!.user.id);
    return ctx.snapshot({ signup, denied, before, after, wrong, original });
  },
  ["POST /admin/update-user", "POST /sign-in/email"],
);
