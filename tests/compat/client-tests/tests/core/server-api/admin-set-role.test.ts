import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";
import { readUserState } from "../../../support/verification";

compatScenario(
  "server admin setRole validates body and configured roles before scoped mutation",
  async (ctx) => {
    async function signup(name: string, profile?: "admin-standard" | "admin-role-manager") {
      const actor = ctx.actor(name, profile);
      let cookie = "";
      const result = await actor.client.signUp.email({
        email: ctx.uniqueEmail(name),
        password: "Password123!",
        name,
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
      return { result, headers: { cookie } };
    }
    const owner = await signup("role-admin", "admin-standard");
    const member = await signup("role-member");
    const foreign = await signup("role-foreign");
    const manager = await signup("role-manager", "admin-role-manager");
    const target = member.result.data!.user.id;
    const state = async () => ({
      owner: await readUserState(ctx, owner.result.data!.user.id),
      member: await readUserState(ctx, target),
      foreign: await readUserState(ctx, foreign.result.data!.user.id),
      manager: await readUserState(ctx, manager.result.data!.user.id),
    });
    const before = await state();
    async function invoke(input: Record<string, unknown>) {
      const response = await ctx
        .actor("role-control")
        .fetch(ctx.baseURL + "/__test/admin/server-api", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ operation: "setRole", ...input }),
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
    for (const [input, status] of [
      [{}, 400],
      [{ body: null }, 400],
      [{ body: 7 }, 400],
      [{ body: {} }, 400],
      [{ body: { userId: target, role: 7 }, headers: owner.headers }, 400],
      [{ body: { userId: target, role: ["admin", 7] }, headers: owner.headers }, 400],
      [{ body: { userId: target, role: "admin" } }, 400],
      [{ body: { userId: target, role: "admin" }, headers: {} }, 401],
      [
        {
          body: { userId: target, role: "admin" },
          query: { role: "admin", userId: owner.result.data!.user.id },
          headers: member.headers,
        },
        403,
      ],
      [
        {
          body: { userId: "missing-target", role: "ghost" },
          profile: "admin-role-manager",
          headers: manager.headers,
        },
        400,
      ],
      [
        {
          body: { userId: "missing-target", role: "user" },
          profile: "admin-role-manager",
          headers: manager.headers,
        },
        404,
      ],
      ...[null, 7, true, [], {}, { toString: "bad" }].map(
        (userId) =>
          [
            { body: { userId, role: "user" }, headers: owner.headers },
            typeof userId === "object" &&
            userId !== null &&
            !Array.isArray(userId) &&
            Object.hasOwn(userId, "toString")
              ? 400
              : 404,
          ] as const,
      ),
    ] as const) {
      const response = await invoke(input);
      expect(response.status).toBe(status);
      if (status === 401) expect(response.body).toBeNull();
      if (status === 403) {
        expect(response.body).toEqual({
          code: "YOU_ARE_NOT_ALLOWED_TO_CHANGE_USERS_ROLE",
          message: "You are not allowed to change users role",
        });
      }
      rejected.push(response);
    }
    expect(await state()).toEqual(before);
    const changed = [];
    for (const [role, stored] of [
      ["admin", "admin"],
      [["user", "admin"], "user,admin"],
      [[], ""],
      ["", ""],
      ["user", "user"],
    ] as const) {
      const response = await invoke({
        body: { userId: target, role, ignored: "value" },
        query: { userId: foreign.result.data!.user.id, role: "admin" },
        headers: owner.headers,
      });
      expect(response.status).toBe(200);
      expect(response.body).toMatchObject({
        user: { id: target, email: member.result.data!.user.email, role: stored },
      });
      expect(response.body.user).not.toHaveProperty("password");
      expect(response.principal).toBe(owner.result.data!.user.email);
      expect(response.cookies).toEqual([
        "application_a=first; Path=/; HttpOnly",
        "application_b=second; Path=/; HttpOnly",
      ]);
      const persisted = await ctx.rawRequest({
        path:
          "/__test/admin-role-state?email=" + encodeURIComponent(member.result.data!.user.email),
      });
      expect(persisted.body).toMatchObject({ user: { id: target, role: stored } });
      const after = await state();
      expect(after.owner).toEqual(before.owner);
      expect(after.foreign).toEqual(before.foreign);
      expect(after.manager).toEqual(before.manager);
      expect(after.member.accounts).toEqual(before.member.accounts);
      expect(after.member.sessions).toEqual(before.member.sessions);
      changed.push({ response, persisted });
    }
    return ctx.snapshot({
      owner,
      member,
      foreign,
      manager,
      before,
      rejected,
      changed,
      after: await state(),
    });
  },
);
