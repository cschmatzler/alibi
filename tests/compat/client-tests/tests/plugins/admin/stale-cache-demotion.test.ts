import { expect } from "bun:test";

import { createAuthClient } from "better-auth/client";
import { adminClient } from "better-auth/client/plugins";

import { authProfilePath } from "../../../support/profiles";
import { compatScenario } from "../../../support/scenario";
compatScenario(
  "demoted admin stale cookie cache cannot restore its grants or impersonate another principal",
  async (ctx) => {
    const profile = "admin-banned-message-error-cache";
    const client = (name: string) =>
      createAuthClient({
        baseURL: ctx.baseURL + authProfilePath(profile),
        plugins: [adminClient()],
        fetchOptions: { customFetchImpl: ctx.actor(name, profile).fetch },
      });
    const first = client("first");
    const second = client("second");
    const signup = await first.signUp.email({
      email: ctx.uniqueEmail("stale-admin"),
      name: "First",
      password: "password123",
    });
    expect(signup.error).toBeNull();
    const other = await second.signUp.email({
      email: ctx.uniqueEmail("live-admin"),
      name: "Second",
      password: "password123",
    });
    expect(other.error).toBeNull();
    const id = signup.data!.user.id;
    const otherId = other.data!.user.id;
    const issued = await first.getSession();
    expect(issued.data!.user.role).toBe("admin");
    const demoted = await second.admin.setRole({ userId: id, role: "user" });
    expect(demoted.error).toBeNull();
    const cached = await first.getSession();
    expect(cached.data!.user.role).toBe("admin");
    const read = async () => ({
      first: await ctx.readUserState({ userId: id }),
      second: await ctx.readUserState({ userId: otherId }),
      visible: await second.admin.getUser({ query: { id } }),
    });
    const before = await read();
    expect(before.visible.data!.role).toBe("user");
    const escalate = await first.admin.setRole({ userId: id, role: "admin" });
    expect(escalate.error).toMatchObject({
      status: 403,
      code: "YOU_ARE_NOT_ALLOWED_TO_CHANGE_USERS_ROLE",
    });
    expect(await read()).toEqual(before);
    const permission = await first.admin.hasPermission({ permissions: { user: ["set-role"] } });
    expect(permission.error).toBeNull();
    expect(permission.data).toMatchObject({ success: false });
    const impersonate = await first.admin.impersonateUser({ userId: otherId });
    expect(impersonate.error).toMatchObject({
      status: 403,
      code: "YOU_ARE_NOT_ALLOWED_TO_IMPERSONATE_USERS",
    });
    const after = await read();
    expect(after).toEqual(before);
    const live = await second.getSession();
    expect(live.data!.user.id).toBe(otherId);
    expect(live.data!.user.role).toBe("admin");
    return ctx.snapshot({
      signup,
      other,
      issued,
      demoted,
      cached,
      before,
      escalate,
      permission,
      impersonate,
      after,
      live,
    });
  },
  ["POST /admin/set-role", "POST /admin/impersonate-user", "POST /admin/has-permission"],
);
