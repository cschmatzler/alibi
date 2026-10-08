import { expect } from "bun:test";

import { compatScenario } from "../../../support/scenario";
import { signUpAndPromoteAdmin } from "./helpers";
compatScenario(
  "admin update-user ban revokes all target sessions and preserves other principals",
  async (ctx) => {
    const admin = await signUpAndPromoteAdmin(ctx);
    expect(admin.signup.error).toBeNull();
    const target = ctx.actor("target");
    const email = ctx.uniqueEmail("ban-update-target");
    const signup = await target.client.signUp.email({
      email,
      name: "Target",
      password: "password123",
    });
    expect(signup.error).toBeNull();
    const sibling = await ctx
      .actor("sibling")
      .client.signIn.email({ email, password: "password123" });
    expect(sibling.error).toBeNull();
    const unrelated = ctx.actor("unrelated");
    const other = await unrelated.client.signUp.email({
      email: ctx.uniqueEmail("ban-update-other"),
      name: "Other",
      password: "password123",
    });
    expect(other.error).toBeNull();
    const userId = signup.data!.user.id;
    const before = (await ctx.readUserState({ userId })) as any;
    const otherBefore = await ctx.readUserState({ userId: other.data!.user.id });
    expect(before.sessions).toHaveLength(2);
    const updated = await admin.adminClient.admin.updateUser({
      userId,
      data: { banned: true, banReason: "Update route ban" },
    });
    expect(updated.error).toBeNull();
    expect(updated.data!).toMatchObject({
      id: userId,
      banned: true,
      banReason: "Update route ban",
    });
    const after = (await ctx.readUserState({ userId })) as any;
    expect(after.sessions).toEqual([]);
    expect(after.accounts).toEqual(before.accounts);
    expect(await ctx.readUserState({ userId: other.data!.user.id })).toEqual(otherBefore);
    const first = await target.client.getSession();
    const second = await ctx.actor("sibling").client.getSession();
    expect(first.data).toBeNull();
    expect(second.data).toBeNull();
    const retained = await unrelated.client.getSession();
    expect(retained.data!.user.id).toBe(other.data!.user.id);
    const stored = await admin.adminClient.admin.getUser({ query: { id: userId } });
    expect(stored.data).toMatchObject({ banned: true, banReason: "Update route ban" });
    return ctx.snapshot({
      signup,
      sibling,
      other,
      before,
      updated,
      after,
      first,
      second,
      retained,
      stored,
      otherBefore,
    });
  },
  ["POST /admin/update-user", "GET /get-session"],
);
