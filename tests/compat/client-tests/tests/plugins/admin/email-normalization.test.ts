import { expect } from "bun:test";

import { compatScenario } from "../../../support/scenario";
import { signUpAndPromoteAdmin } from "./helpers";
compatScenario(
  "admin email replacement lowercases the identity and moves credential sign-in to that address",
  async (ctx) => {
    const admin = await signUpAndPromoteAdmin(ctx);
    expect(admin.signup.error).toBeNull();
    const email = ctx.uniqueEmail("email-before");
    const replacement = ctx.uniqueEmail("email-after");
    const signup = await ctx
      .actor("target")
      .client.signUp.email({ email, name: "Target", password: "password123" });
    expect(signup.error).toBeNull();
    const userId = signup.data!.user.id;
    const before = (await ctx.readUserState({ userId })) as any;
    const updated = await admin.adminClient.admin.updateUser({
      userId,
      data: { email: replacement.toUpperCase(), emailVerified: false },
    });
    expect(updated.error).toBeNull();
    expect(updated.data).toMatchObject({ id: userId, email: replacement, emailVerified: false });
    const after = (await ctx.readUserState({ userId })) as any;
    expect(after.user).toMatchObject({ id: userId, email: replacement, emailVerified: false });
    expect(after.accounts).toEqual(before.accounts);
    expect(after.sessions).toEqual(before.sessions);
    const obsolete = await ctx
      .actor("old-address")
      .client.signIn.email({ email, password: "password123" });
    expect(obsolete.error).toMatchObject({ status: 401, code: "INVALID_EMAIL_OR_PASSWORD" });
    const current = await ctx
      .actor("new-address")
      .client.signIn.email({ email: replacement, password: "password123" });
    expect(current.error).toBeNull();
    expect(current.data!.user.id).toBe(userId);
    expect(current.data!.user.email).toBe(replacement);
    return ctx.snapshot({ signup, before, updated, after, obsolete, current });
  },
  ["POST /admin/update-user", "POST /sign-in/email"],
);
