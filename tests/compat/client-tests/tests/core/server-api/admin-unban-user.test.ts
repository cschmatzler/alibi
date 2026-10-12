import { expect } from "bun:test";

import { authProfilePath } from "../../../support/profiles";
import { compatScenario } from "../../../support/scenario";
import { readUserState } from "../../../support/verification";

compatScenario(
  "server admin unbanUser clears stored ban state without restoring revoked sessions",
  async (ctx) => {
    async function signup(name: string, profile?: "admin-standard") {
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
    const admin = await signup("unban-admin", "admin-standard");
    const target = await signup("unban-target");
    const foreign = await signup("unban-foreign");
    const id = target.result.data!.user.id;
    const ban = await admin.actor.fetch(
      ctx.baseURL + authProfilePath("admin-standard") + "/admin/ban-user",
      {
        method: "POST",
        headers: { "content-type": "application/json", ...admin.headers },
        body: JSON.stringify({ userId: id, banReason: "review", banExpiresIn: 3600 }),
      },
    );
    expect(ban.status).toBe(200);
    const banned = await ban.json();
    expect(banned.user).toMatchObject({ id, banned: true, banReason: "review" });
    expect(banned.user.banExpires).not.toBeNull();
    async function stored() {
      return (
        await ctx.rawRequest({
          path:
            "/__test/admin-role-state?email=" + encodeURIComponent(target.result.data!.user.email),
        })
      ).body;
    }
    const before = {
      admin: await readUserState(ctx, admin.result.data!.user.id),
      target: await readUserState(ctx, id),
      foreign: await readUserState(ctx, foreign.result.data!.user.id),
      ban: await stored(),
    };
    expect(before.target.sessions).toEqual([]);
    async function invoke(input: Record<string, unknown>) {
      const response = await ctx
        .actor("unban-control")
        .fetch(ctx.baseURL + "/__test/admin/server-api", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ operation: "unbanUser", ...input }),
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
      [{ body: 7 }, 400, "VALIDATION_ERROR"],
      [{ body: { userId: { toString: "bad" } }, headers: admin.headers }, 400, "VALIDATION_ERROR"],
      [{ body: { userId: id } }, 401, undefined],
      [{ body: { userId: id }, headers: {} }, 401, undefined],
      [{ body: { userId: id }, headers: foreign.headers }, 403, "YOU_ARE_NOT_ALLOWED_TO_BAN_USERS"],
      [
        { body: { userId: id }, profile: "admin-role-manager", headers: admin.headers },
        403,
        "YOU_ARE_NOT_ALLOWED_TO_BAN_USERS",
      ],
      ...["missing-user", null, 7, []].map(
        (userId) => [{ body: { userId }, headers: admin.headers }, 404, "USER_NOT_FOUND"] as const,
      ),
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
    expect(await stored()).toEqual(before.ban);
    expect(await readUserState(ctx, id)).toEqual(before.target);
    const cleared = [];
    for (let repeat = 0; repeat < 2; repeat++) {
      const result = await invoke({
        body: { userId: id, banReason: "forged", banned: true },
        query: { userId: foreign.result.data!.user.id },
        headers: admin.headers,
      });
      expect(result.status).toBe(200);
      expect(result.body.user).toMatchObject({
        id,
        email: target.result.data!.user.email,
        name: "unban-target",
        role: "user",
        banned: false,
        banReason: null,
        banExpires: null,
      });
      expect(result.body.user).not.toHaveProperty("password");
      expect(result.principal).toBe(admin.result.data!.user.email);
      expect(result.cookies).toEqual([
        "application_a=first; Path=/; HttpOnly",
        "application_b=second; Path=/; HttpOnly",
      ]);
      expect(await readUserState(ctx, id)).toEqual(before.target);
      expect(await readUserState(ctx, admin.result.data!.user.id)).toEqual(before.admin);
      expect(await readUserState(ctx, foreign.result.data!.user.id)).toEqual(before.foreign);
      const physical = await stored();
      expect(physical).toMatchObject({
        user: { id, banned: false, banReason: null, banExpires: null },
        sessions: [],
      });
      cleared.push({ result, physical });
    }
    const old = await ctx.rawRequest({ path: "/api/auth/get-session", headers: target.headers });
    expect(old.body).toBeNull();
    const login = await ctx
      .actor("unbanned-login")
      .client.signIn.email({ email: target.result.data!.user.email, password: "Password123!" });
    expect(login.error).toBeNull();
    expect(login.data!.user.id).toBe(id);
    expect((await readUserState(ctx, id)).sessions).toHaveLength(1);
    return ctx.snapshot({
      admin: admin.result,
      target: target.result,
      foreign: foreign.result,
      banned,
      before,
      rejected,
      cleared,
      old,
      login,
      after: await readUserState(ctx, id),
    });
  },
);
