import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";
import { readUserState } from "../../../support/verification";

compatScenario(
  "server admin banUser applies policy and revokes only the target sessions",
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
      return { result, headers: { cookie } };
    }
    const admin = await signup("ban-admin", "admin-standard");
    const target = await signup("ban-target");
    const foreign = await signup("ban-foreign");
    const id = target.result.data!.user.id;
    const second = await ctx.actor("ban-second-session").client.signIn.email({
      email: target.result.data!.user.email,
      password: "Password123!",
    });
    expect(second.error).toBeNull();
    const before = {
      admin: await readUserState(ctx, admin.result.data!.user.id),
      target: await readUserState(ctx, id),
      foreign: await readUserState(ctx, foreign.result.data!.user.id),
    };
    expect(before.target.sessions).toHaveLength(2);
    async function invoke(input: Record<string, unknown>) {
      const response = await ctx
        .actor("ban-control")
        .fetch(ctx.baseURL + "/__test/admin/server-api", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ operation: "banUser", ...input }),
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
      [{ body: { userId: id, banReason: null } }, 400, "VALIDATION_ERROR"],
      [{ body: { userId: id, banExpiresIn: "60" } }, 400, "VALIDATION_ERROR"],
      [{ body: { userId: id } }, 401, undefined],
      [{ body: { userId: id }, headers: foreign.headers }, 403, "YOU_ARE_NOT_ALLOWED_TO_BAN_USERS"],
      [
        { body: { userId: id }, headers: admin.headers, profile: "admin-role-manager" },
        403,
        "YOU_ARE_NOT_ALLOWED_TO_BAN_USERS",
      ],
      [
        { body: { userId: admin.result.data!.user.id }, headers: admin.headers },
        400,
        "YOU_CANNOT_BAN_YOURSELF",
      ],
      [{ body: { userId: null }, headers: admin.headers }, 404, "USER_NOT_FOUND"],
      [{ body: { userId: "missing" }, headers: admin.headers }, 404, "USER_NOT_FOUND"],
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
    expect(await readUserState(ctx, id)).toEqual(before.target);
    const receipts = [];
    for (const [profile, body, reason, expires] of [
      [
        "admin-standard",
        { userId: id, banReason: "review", banExpiresIn: 60, banned: false },
        "review",
        true,
      ],
      ["admin-duration-zero", { userId: id, banReason: "", banExpiresIn: 0 }, "No reason", false],
      [
        "admin-duration-fractional",
        { userId: id, banReason: "", banExpiresIn: 0 },
        "configured reason",
        true,
      ],
    ] as const) {
      const result = await invoke({
        profile,
        body,
        headers: admin.headers,
        query: { userId: foreign.result.data!.user.id },
      });
      expect(result.status).toBe(200);
      expect(result.body.user).toMatchObject({ id, banned: true, banReason: reason });
      expect(result.body.user.banExpires === null).toBe(!expires);
      expect(result.principal).toBe(admin.result.data!.user.email);
      expect(result.cookies).toEqual([
        "application_a=first; Path=/; HttpOnly",
        "application_b=second; Path=/; HttpOnly",
      ]);
      expect(result.body.user).not.toHaveProperty("password");
      const physical = (
        await ctx.rawRequest({
          path:
            "/__test/admin-role-state?email=" + encodeURIComponent(target.result.data!.user.email),
        })
      ).body as {
        user: { id: string; banned: boolean; banReason: string; banExpires: string | null };
      };
      expect(physical.user).toMatchObject({ id, banned: true, banReason: reason });
      expect(physical.user.banExpires).toEqual(result.body.user.banExpires);
      const after = await readUserState(ctx, id);
      expect(after.sessions).toEqual([]);
      expect(after.accounts).toEqual(before.target.accounts);
      expect(after.user).toEqual(before.target.user);
      expect(await readUserState(ctx, admin.result.data!.user.id)).toEqual(before.admin);
      expect(await readUserState(ctx, foreign.result.data!.user.id)).toEqual(before.foreign);
      receipts.push({ result, physical });
    }
    const old = await ctx.rawRequest({ path: "/api/auth/get-session", headers: target.headers });
    expect(old.body).toBeNull();
    const deniedLogin = await ctx.actor("banned-fresh-login").client.signIn.email({
      email: target.result.data!.user.email,
      password: "Password123!",
    });
    expect(deniedLogin.error?.status).toBe(403);
    expect(deniedLogin.error?.code).toBe("BANNED_USER");
    expect((await readUserState(ctx, id)).sessions).toEqual([]);
    return ctx.snapshot({
      admin: admin.result,
      target: target.result,
      foreign: foreign.result,
      second,
      before,
      rejected,
      receipts,
      old,
      deniedLogin,
    });
  },
);
