import { expect } from "bun:test";

import { createAuthClient } from "better-auth/client";
import { adminClient } from "better-auth/client/plugins";

import { authProfilePath } from "../../../support/profiles";
import { compatScenario } from "../../../support/scenario";
compatScenario(
  "admin create grant cannot initialize any ban property without the ban grant",
  async (ctx) => {
    const profile = "admin-role-creator";
    const actor = ctx.actor("creator", profile);
    const client = createAuthClient({
      baseURL: ctx.baseURL + authProfilePath(profile),
      plugins: [adminClient()],
      fetchOptions: { customFetchImpl: actor.fetch },
    });
    const creator = await client.signUp.email({
      email: ctx.uniqueEmail("ban-creator"),
      name: "Creator",
      password: "password123",
    });
    expect(creator.error).toBeNull();
    const email = ctx.uniqueEmail("ban-create-target");
    const read = async () =>
      (
        await ctx.rawRequest({
          path: "/__test/admin-role-state?email=" + encodeURIComponent(email),
        })
      ).body;
    const before = await read();
    expect(before).toEqual({ user: null, accounts: [], sessions: [] });
    const denied = [];
    for (const data of [
      { banned: false },
      { banReason: "reason" },
      { banExpires: new Date(Date.now() + 3600000).toISOString() },
    ]) {
      const result = await client.admin.createUser({
        email,
        name: "Target",
        password: "password123",
        data,
      });
      expect(result.error).toMatchObject({ status: 403, code: "YOU_ARE_NOT_ALLOWED_TO_BAN_USERS" });
      expect(await read()).toEqual(before);
      denied.push(result);
    }
    const accepted = await client.admin.createUser({
      email,
      name: "Target",
      password: "password123",
    });
    expect(accepted.error).toBeNull();
    const after = (await read()) as any;
    expect(after.user.id).toBe(accepted.data!.user.id);
    expect(after.accounts).toHaveLength(1);
    expect(after.sessions).toEqual([]);
    const signin = await ctx
      .actor("target", profile)
      .client.signIn.email({ email, password: "password123" });
    expect(signin.error).toBeNull();
    expect(signin.data!.user.id).toBe(accepted.data!.user.id);
    return ctx.snapshot({ creator, before, denied, accepted, after, signin });
  },
  ["POST /admin/create-user", "POST /sign-in/email"],
);
