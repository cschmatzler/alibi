import { expect } from "bun:test";

import { compatScenario } from "../../../support/scenario";
import { readUserState } from "../../../support/verification";

compatScenario(
  "server admin createUser admits trusted calls and scopes authenticated provisioning",
  async (ctx) => {
    async function signup(name: string, profile?: "admin-standard" | "admin-role-creator") {
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
    const admin = await signup("provision-admin", "admin-standard");
    const member = await signup("provision-member");
    const creator = await signup("provision-creator", "admin-role-creator");
    const before = {
      admin: await readUserState(ctx, admin.result.data!.user.id),
      member: await readUserState(ctx, member.result.data!.user.id),
      creator: await readUserState(ctx, creator.result.data!.user.id),
    };
    async function invoke(input: Record<string, unknown>) {
      const response = await ctx
        .actor("provision-control")
        .fetch(ctx.baseURL + "/__test/admin/server-api", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ operation: "createUser", ...input }),
        });
      const text = await response.text();
      return {
        status: response.status,
        body: text ? JSON.parse(text) : null,
        principal: response.headers.get("x-admin-principal"),
        cookies: response.headers.getSetCookie(),
      };
    }
    const blockedEmail = ctx.uniqueEmail("blocked-provision");
    const base = { email: blockedEmail, name: "Blocked" };
    const rejected = [];
    for (const [input, status] of [
      [{}, 400],
      [{ body: null }, 400],
      [{ body: {} }, 400],
      [{ body: { ...base, password: null } }, 400],
      [{ body: { ...base, role: null } }, 400],
      [{ body: { ...base, data: null } }, 400],
      [{ body: base, headers: {} }, 401],
      [{ body: base, headers: member.headers }, 403],
      [{ body: { ...base, email: "invalid" }, headers: member.headers }, 403],
      [
        {
          body: { ...base, data: { role: "user" } },
          profile: "admin-role-creator",
          headers: creator.headers,
        },
        403,
      ],
      [
        {
          body: { ...base, data: { banned: false } },
          profile: "admin-role-creator",
          headers: creator.headers,
        },
        403,
      ],
      [{ body: { ...base, data: { role: 7 } } }, 400],
      [{ body: { ...base, role: "ghost" }, profile: "admin-role-creator" }, 400],
      [{ body: { ...base, email: "invalid" } }, 400],
      [{ body: { ...base, password: "x".repeat(129) } }, 400],
      [{ body: { ...base, email: member.result.data!.user.email } }, 400],
    ] as const) {
      const result = await invoke(input);
      expect(result.status).toBe(status);
      rejected.push(result);
    }
    expect(
      (
        await ctx.rawRequest({
          path: "/__test/admin-role-state?email=" + encodeURIComponent(blockedEmail),
        })
      ).body,
    ).toEqual({ user: null, accounts: [], sessions: [] });
    expect(await readUserState(ctx, admin.result.data!.user.id)).toEqual(before.admin);
    expect(await readUserState(ctx, member.result.data!.user.id)).toEqual(before.member);
    expect(await readUserState(ctx, creator.result.data!.user.id)).toEqual(before.creator);
    const created = [];
    for (const [label, input, password, role, principal, profile] of [
      ["trusted", {}, undefined, "admin", null, "admin-standard"],
      ["empty-password", { password: "" }, undefined, "admin", null, "admin-standard"],
      [
        "credential",
        { password: "short", role: ["user", "admin"], headers: admin.headers },
        "short",
        "user,admin",
        admin.result.data!.user.email,
        "admin-standard",
      ],
      [
        "creator",
        { password: "Password123!", headers: creator.headers },
        "Password123!",
        "creator",
        creator.result.data!.user.email,
        "admin-role-creator",
      ],
      ["role-precedence", { role: [], data: { role: 7 } }, undefined, "", null, "admin-standard"],
    ] as const) {
      const email = ctx.uniqueEmail(label);
      const { headers, ...body } = input as Record<string, unknown>;
      const result = await invoke({
        profile,
        ...(headers ? { headers } : {}),
        query: { email: blockedEmail },
        body: { ...body, email: email.toUpperCase(), name: "Provisioned", ignored: "value" },
      });
      expect(result.status).toBe(200);
      expect(result.body).toMatchObject({ user: { email, name: "Provisioned", role } });
      expect(result.body.user).not.toHaveProperty("password");
      expect(result.principal).toBe(principal);
      expect(result.cookies).toEqual([
        "application_a=first; Path=/; HttpOnly",
        "application_b=second; Path=/; HttpOnly",
      ]);
      const stored = await readUserState(ctx, result.body.user.id);
      expect(stored.sessions).toEqual([]);
      expect(stored.accounts).toHaveLength(password ? 1 : 0);
      let login;
      if (password) {
        login = await ctx.actor(label, profile).client.signIn.email({ email, password });
        expect(login.error).toBeNull();
        expect(login.data!.user.id).toBe(result.body.user.id);
      }
      created.push({ result, stored, ...(login ? { login } : {}) });
    }
    expect(await readUserState(ctx, admin.result.data!.user.id)).toEqual(before.admin);
    expect(await readUserState(ctx, member.result.data!.user.id)).toEqual(before.member);
    expect(await readUserState(ctx, creator.result.data!.user.id)).toEqual(before.creator);
    return ctx.snapshot({
      admin: admin.result,
      member: member.result,
      creator: creator.result,
      before,
      rejected,
      created,
    });
  },
);
