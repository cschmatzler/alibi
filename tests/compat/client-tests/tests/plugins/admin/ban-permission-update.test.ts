import { expect } from "bun:test";

import { createAuthClient } from "better-auth/client";
import { adminClient } from "better-auth/client/plugins";

import { authProfilePath } from "../../../support/profiles";
import { compatScenario } from "../../../support/scenario";
compatScenario(
  "admin update grant cannot mutate any ban property without the ban grant",
  async (ctx) => {
    const profile = "admin-role-manager";
    const actor = ctx.actor("manager", profile);
    const client = createAuthClient({
      baseURL: ctx.baseURL + authProfilePath(profile),
      plugins: [adminClient()],
      fetchOptions: { customFetchImpl: actor.fetch },
    });
    const manager = await client.signUp.email({
      email: ctx.uniqueEmail("ban-manager"),
      name: "Manager",
      password: "password123",
    });
    expect(manager.error).toBeNull();
    const email = ctx.uniqueEmail("ban-permission-target");
    const signup = await ctx
      .actor("target")
      .client.signUp.email({ email, name: "Original target", password: "password123" });
    expect(signup.error).toBeNull();
    const userId = signup.data!.user.id;
    const read = async () =>
      (
        await ctx.rawRequest({
          path: "/__test/admin-role-state?email=" + encodeURIComponent(email),
        })
      ).body;
    const before = await read();
    const denied = [];
    for (const data of [
      { banned: false },
      { banReason: "reason" },
      { banExpires: new Date(Date.now() + 3600000).toISOString() },
    ]) {
      const result = await client.admin.updateUser({
        userId,
        data: { ...data, name: "must-not-commit" },
      });
      expect(result.error).toMatchObject({ status: 403, code: "YOU_ARE_NOT_ALLOWED_TO_BAN_USERS" });
      expect(await read()).toEqual(before);
      denied.push(result);
    }
    const accepted = await client.admin.updateUser({ userId, data: { name: "Allowed name" } });
    expect(accepted.error).toBeNull();
    expect(accepted.data!.name).toBe("Allowed name");
    const after = (await read()) as any;
    expect(after.user.name).toBe("Allowed name");
    expect(after.accounts).toEqual((before as any).accounts);
    expect(after.sessions).toEqual((before as any).sessions);
    return ctx.snapshot({ manager, signup, before, denied, accepted, after });
  },
  ["POST /admin/update-user"],
);
