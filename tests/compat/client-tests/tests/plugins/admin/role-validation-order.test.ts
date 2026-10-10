import { expect } from "bun:test";

import { createAuthClient } from "better-auth/client";
import { adminClient } from "better-auth/client/plugins";

import { authProfilePath } from "../../../support/profiles";
import { compatScenario } from "../../../support/scenario";

compatScenario(
  "admin validates configured role before looking up a missing target",
  async (ctx) => {
    const profile = "admin-role-manager";
    const client = createAuthClient({
      baseURL: ctx.baseURL + authProfilePath(profile),
      plugins: [adminClient()],
      fetchOptions: { customFetchImpl: ctx.actor("manager", profile).fetch },
    });
    const signup = await client.signUp.email({
      email: ctx.uniqueEmail("role-order"),
      name: "Manager",
      password: "password123",
    });
    expect(signup.error).toBeNull();
    const before = await ctx.readUserState({ userId: signup.data!.user.id });
    // @ts-expect-error Exercise server validation with a role outside the client enum.
    const invalid = await client.admin.setRole({ userId: "missing-target", role: "ghost" });
    expect(invalid.error).toMatchObject({
      status: 400,
      code: "YOU_ARE_NOT_ALLOWED_TO_SET_NON_EXISTENT_VALUE",
    });
    const missing = await client.admin.setRole({ userId: "missing-target", role: "user" });
    expect(missing.error).toMatchObject({ status: 404, code: "USER_NOT_FOUND" });
    expect(await ctx.readUserState({ userId: signup.data!.user.id })).toEqual(before);
    return ctx.snapshot({ signup, before, invalid, missing });
  },
  ["POST /admin/set-role"],
);
