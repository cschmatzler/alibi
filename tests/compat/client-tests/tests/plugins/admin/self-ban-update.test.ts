import { expect } from "bun:test";

import { compatScenario } from "../../../support/scenario";
import { signUpAndPromoteAdmin } from "./helpers";
compatScenario(
  "admin cannot ban itself through update-user and retains live authority after rejection",
  async (ctx) => {
    const admin = await signUpAndPromoteAdmin(ctx);
    expect(admin.signup.error).toBeNull();
    const userId = admin.signup.data!.user.id;
    const before = await ctx.readUserState({ userId });
    const visibleBefore = await admin.adminClient.admin.getUser({ query: { id: userId } });
    expect(visibleBefore.error).toBeNull();
    const denied = await admin.adminClient.admin.updateUser({
      userId,
      data: { banned: true, banReason: "self", name: "must-not-commit" },
    });
    expect(denied.error).toMatchObject({ status: 400, code: "YOU_CANNOT_BAN_YOURSELF" });
    expect(await ctx.readUserState({ userId })).toEqual(before);
    const visibleAfter = await admin.adminClient.admin.getUser({ query: { id: userId } });
    expect(visibleAfter).toEqual(visibleBefore);
    const session = await admin.client.getSession();
    expect(session.data!.user.id).toBe(userId);
    const accepted = await admin.adminClient.admin.updateUser({
      userId,
      data: { name: "Still authorized" },
    });
    expect(accepted.error).toBeNull();
    expect(accepted.data!.name).toBe("Still authorized");
    return ctx.snapshot({ denied, before, visibleBefore, visibleAfter, session, accepted });
  },
  ["POST /admin/update-user", "GET /get-session"],
);
