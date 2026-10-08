import { expect } from "bun:test";

import { compatScenario } from "../../../support/scenario";
import { signUpAndPromoteAdmin } from "./helpers";
compatScenario(
  "admin invalid email rejects the accompanying update before identity and credential mutation",
  async (ctx) => {
    const admin = await signUpAndPromoteAdmin(ctx);
    expect(admin.signup.error).toBeNull();
    const email = ctx.uniqueEmail("invalid-email-target");
    const signup = await ctx
      .actor("target")
      .client.signUp.email({ email, name: "Original", password: "password123" });
    expect(signup.error).toBeNull();
    const userId = signup.data!.user.id;
    const before = await ctx.readUserState({ userId });
    const visibleBefore = await admin.adminClient.admin.getUser({ query: { id: userId } });
    expect(visibleBefore.error).toBeNull();
    const denied = await admin.adminClient.admin.updateUser({
      userId,
      data: { email: "not-an-address", name: "must-not-commit" },
    });
    expect(denied.error).toMatchObject({ status: 400, code: "INVALID_EMAIL" });
    expect(await ctx.readUserState({ userId })).toEqual(before);
    expect(await admin.adminClient.admin.getUser({ query: { id: userId } })).toEqual(visibleBefore);
    const replacement = ctx.uniqueEmail("valid-email-retry");
    const accepted = await admin.adminClient.admin.updateUser({
      userId,
      data: { email: replacement },
    });
    expect(accepted.error).toBeNull();
    expect(accepted.data).toMatchObject({ id: userId, email: replacement, name: "Original" });
    const signin = await ctx
      .actor("retry")
      .client.signIn.email({ email: replacement, password: "password123" });
    expect(signin.error).toBeNull();
    expect(signin.data!.user.id).toBe(userId);
    return ctx.snapshot({ signup, before, visibleBefore, denied, accepted, signin });
  },
  ["POST /admin/update-user", "POST /sign-in/email"],
);
