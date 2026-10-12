import { expect } from "bun:test";

import { compatScenario } from "../../../support/scenario";
import { readUserState } from "../../../support/verification";

compatScenario(
  "server adminUpdateUser validates scoped updates and retires only banned target sessions",
  async (ctx) => {
    async function signup(name: string, profile?: "admin-standard" | "admin-role-manager") {
      const actor = ctx.actor(name, profile);
      let cookie = "";
      const result = await actor.client.signUp.email({
        email: ctx.uniqueEmail(name),
        name,
        password: "Password123!",
        fetchOptions: {
          onSuccess({ response }) {
            cookie = response.headers
              .getSetCookie()
              .map((raw) => raw.split(";")[0])
              .join("; ");
          },
        },
      });
      expect(result.error).toBeNull();
      return { actor, result, headers: { cookie } };
    }
    const admin = await signup("update-admin", "admin-standard");
    const manager = await signup("update-manager", "admin-role-manager");
    const target = await signup("update-target");
    const foreign = await signup("update-foreign");
    const id = target.result.data!.user.id;
    const adminId = admin.result.data!.user.id;
    const state = async () => ({
      admin: await readUserState(ctx, adminId),
      manager: await readUserState(ctx, manager.result.data!.user.id),
      target: await readUserState(ctx, id),
      foreign: await readUserState(ctx, foreign.result.data!.user.id),
    });
    const before = await state();
    async function invoke(input: Record<string, unknown>) {
      const response = await ctx
        .actor("update-control")
        .fetch(ctx.baseURL + "/__test/admin/server-api", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ operation: "adminUpdateUser", ...input }),
        });
      const text = await response.text();
      return {
        status: response.status,
        body: text ? JSON.parse(text) : null,
        principal: response.headers.get("x-admin-principal"),
        cookies: response.headers.getSetCookie(),
      };
    }
    const rejected = [];
    for (const [input, status, code] of [
      [{}, 400, "VALIDATION_ERROR"],
      [{ body: null }, 400, "VALIDATION_ERROR"],
      [{ body: { userId: id, data: [] } }, 400, "VALIDATION_ERROR"],
      [{ body: { userId: id, data: { name: "Denied" } } }, 401, undefined],
      [
        { body: { userId: id, data: { name: "Denied" } }, headers: target.headers },
        403,
        "YOU_ARE_NOT_ALLOWED_TO_UPDATE_USERS",
      ],
      [{ body: { userId: id, data: {} }, headers: admin.headers }, 400, "NO_DATA_TO_UPDATE"],
      [
        {
          body: { userId: adminId, data: { password: "x", banned: true, username: "x" } },
          headers: admin.headers,
        },
        400,
        "PASSWORD_CANNOT_BE_UPDATED_VIA_UPDATE_USER",
      ],
      [
        { body: { userId: adminId, data: { banned: true } }, headers: admin.headers },
        400,
        "YOU_CANNOT_BAN_YOURSELF",
      ],
      [
        { body: { userId: id, data: { username: "x", name: "Denied" } }, headers: admin.headers },
        400,
        "USERNAME_TOO_SHORT",
      ],
      [
        { body: { userId: id, data: { role: 7, name: "Denied" } }, headers: admin.headers },
        400,
        "INVALID_ROLE_TYPE",
      ],
      [
        {
          body: { userId: "missing", data: { role: "ghost" } },
          profile: "admin-role-manager",
          headers: manager.headers,
        },
        400,
        "YOU_ARE_NOT_ALLOWED_TO_SET_NON_EXISTENT_VALUE",
      ],
      [
        {
          body: { userId: id, data: { banned: false, name: "Denied" } },
          profile: "admin-role-manager",
          headers: manager.headers,
        },
        403,
        "YOU_ARE_NOT_ALLOWED_TO_BAN_USERS",
      ],
      [
        {
          body: { userId: id, data: { emailVerified: true, name: "Denied" } },
          profile: "admin-role-manager",
          headers: manager.headers,
        },
        403,
        "YOU_ARE_NOT_ALLOWED_TO_SET_USERS_EMAIL",
      ],
      [
        {
          body: { userId: id, data: { email: foreign.result.data!.user.email, name: "Denied" } },
          headers: admin.headers,
        },
        400,
        "USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL",
      ],
      [
        { body: { userId: "missing", data: { name: "Denied" } }, headers: admin.headers },
        404,
        "USER_NOT_FOUND",
      ],
    ] as const) {
      const result = await invoke(input);
      expect(result.status).toBe(status);
      if (code) {
        expect(result.body.code).toBe(code);
      } else {
        expect(result.body).toBeNull();
      }
      rejected.push(result);
    }
    expect(await state()).toEqual(before);
    const changed = [];
    for (const data of [
      { name: "Managed", image: "https://example.test/avatar.png" },
      { image: null },
      { username: "MANAGED_USER", displayUsername: "Managed Label" },
      { role: ["user", "admin"] },
      { email: ctx.uniqueEmail("replacement").toUpperCase(), emailVerified: true },
    ]) {
      const result = await invoke({
        body: { userId: id, data, ignored: "value" },
        query: { userId: foreign.result.data!.user.id },
        headers: admin.headers,
      });
      expect(result.status).toBe(200);
      expect(result.body.id).toBe(id);
      expect(result.body).not.toHaveProperty("user");
      expect(result.body).not.toHaveProperty("password");
      for (const [key, value] of Object.entries(data)) {
        expect(result.body[key]).toEqual(
          key === "email" || key === "username"
            ? (value as string).toLowerCase()
            : key === "role"
              ? (value as string[]).join(",")
              : value,
        );
      }
      expect(result.principal).toBe(admin.result.data!.user.email);
      expect(result.cookies).toEqual([
        "application_a=first; Path=/; HttpOnly",
        "application_b=second; Path=/; HttpOnly",
      ]);
      const after = await state();
      expect(after.admin).toEqual(before.admin);
      expect(after.manager).toEqual(before.manager);
      expect(after.foreign).toEqual(before.foreign);
      expect(after.target.accounts).toEqual(before.target.accounts);
      expect(after.target.sessions).toEqual(before.target.sessions);
      changed.push({ result, after: after.target });
    }
    const duplicateUsername = await invoke({
      body: { userId: id, data: { username: "managed_user", name: "Denied" } },
      headers: admin.headers,
    });
    expect(duplicateUsername.status).toBe(400);
    expect(duplicateUsername.body.code).toBe("USERNAME_IS_ALREADY_TAKEN");
    const email = changed.at(-1)!.result.body.email;
    const login = await ctx
      .actor("managed-login")
      .client.signIn.email({ email, password: "Password123!" });
    expect(login.error).toBeNull();
    expect(login.data!.user.id).toBe(id);
    const beforeBan = await state();
    expect(beforeBan.target.sessions).toHaveLength(2);
    const banned = await invoke({
      body: { userId: id, data: { banned: true, banReason: "review" } },
      headers: admin.headers,
    });
    expect(banned.status).toBe(200);
    expect(banned.body).toMatchObject({ id, banned: true, banReason: "review" });
    const after = await state();
    expect(after.target.sessions).toEqual([]);
    expect(after.target.accounts).toEqual(beforeBan.target.accounts);
    expect(after.admin).toEqual(before.admin);
    expect(after.manager).toEqual(before.manager);
    expect(after.foreign).toEqual(before.foreign);
    const refused = await ctx
      .actor("banned-login")
      .client.signIn.email({ email, password: "Password123!" });
    expect(refused.error).toMatchObject({ status: 403, code: "BANNED_USER" });
    return ctx.snapshot({
      admin: admin.result,
      manager: manager.result,
      target: target.result,
      foreign: foreign.result,
      before,
      rejected,
      changed,
      duplicateUsername,
      login,
      beforeBan,
      banned,
      after,
      refused,
    });
  },
);
