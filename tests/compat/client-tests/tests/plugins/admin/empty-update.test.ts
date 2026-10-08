import { expect } from "bun:test";

import { compatScenario } from "../../../support/scenario";
import { signUpAndPromoteAdmin, adminActor } from "./helpers";
compatScenario(
  "admin empty update rejects after permission admission and leaves the target unchanged",
  async (ctx) => {
    const admin = await signUpAndPromoteAdmin(ctx);
    expect(admin.signup.error).toBeNull();
    const target = adminActor(ctx, "target");
    const signup = await target.client.signUp.email({
      email: ctx.uniqueEmail("empty-update-target"),
      name: "Original",
      password: "password123",
    });
    expect(signup.error).toBeNull();
    const userId = signup.data!.user.id;
    const before = await ctx.readUserState({ userId });
    const visibleBefore = await admin.adminClient.admin.getUser({ query: { id: userId } });
    const denied = await admin.adminClient.admin.updateUser({ userId, data: {} });
    expect(denied.error).toMatchObject({ status: 400, code: "NO_DATA_TO_UPDATE" });
    const unprivileged = await target.adminClient.admin.updateUser({ userId, data: {} });
    expect(unprivileged.error).toMatchObject({
      status: 403,
      code: "YOU_ARE_NOT_ALLOWED_TO_UPDATE_USERS",
    });
    expect(await ctx.readUserState({ userId })).toEqual(before);
    expect(await admin.adminClient.admin.getUser({ query: { id: userId } })).toEqual(visibleBefore);
    const accepted = await admin.adminClient.admin.updateUser({
      userId,
      data: { name: "Valid retry" },
    });
    expect(accepted.error).toBeNull();
    expect(accepted.data).toMatchObject({ id: userId, name: "Valid retry" });
    return ctx.snapshot({ signup, before, visibleBefore, denied, unprivileged, accepted });
  },
  ["POST /admin/update-user"],
);
