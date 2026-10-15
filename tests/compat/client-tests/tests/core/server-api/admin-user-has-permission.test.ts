import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";
import { readUserState } from "../../../support/verification";

compatScenario(
  "server admin userHasPermission resolves trusted selectors and actual session authority",
  async (ctx) => {
    async function signup(name: string, profile?: "admin-standard") {
      let cookie = "";
      const result = await ctx.actor(name, profile).client.signUp.email({
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
    const admin = await signup("permission-admin", "admin-standard");
    const member = await signup("permission-member");
    const adminId = admin.result.data!.user.id;
    const memberId = member.result.data!.user.id;
    const before = {
      admin: await readUserState(ctx, adminId),
      member: await readUserState(ctx, memberId),
    };
    async function invoke(input: Record<string, unknown>) {
      const response = await ctx
        .actor("permission-control")
        .fetch(ctx.baseURL + "/__test/admin/server-api", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ operation: "userHasPermission", ...input }),
        });
      const text = await response.text();
      return {
        status: response.status,
        body: text ? JSON.parse(text) : null,
        principal: response.headers.get("x-admin-principal"),
        cookies: response.headers.getSetCookie(),
      };
    }
    const checks = { user: ["get"] };
    const rejected = [];
    for (const [input, status, message] of [
      [{}, 400, undefined],
      [{ body: null }, 400, undefined],
      [{ body: {} }, 400, undefined],
      [{ body: { role: null, permissions: checks } }, 400, undefined],
      [{ body: { role: "admin", permissions: { user: [7] } } }, 400, undefined],
      [{ body: { role: "admin", permission: checks, permissions: checks } }, 400, undefined],
      [
        { body: { role: "admin", permission: checks }, headers: admin.headers },
        400,
        "invalid permission check. no permission(s) were passed.",
      ],
      [{ body: { permissions: checks } }, 400, "user id or role is required"],
      [
        { body: { role: "", permissions: checks }, query: { role: "admin" } },
        400,
        "user id or role is required",
      ],
      [{ body: { userId: [], permissions: checks } }, 400, "user id or role is required"],
      [{ body: { userId: null, permissions: checks } }, 400, "user not found"],
      [{ body: { userId: 7, permissions: checks } }, 400, "user not found"],
      [{ body: { userId: "missing-user", permissions: checks } }, 400, "user not found"],
      [{ body: { role: "admin", permissions: checks }, headers: {} }, 401, undefined],
    ] as const) {
      const result = await invoke(input);
      expect(result.status).toBe(status);
      if (message) {
        expect(result.body).toEqual({ message });
      }
      if (status === 401) {
        expect(result.body).toBeNull();
      }
      rejected.push(result);
    }
    const granted = [];
    for (const [input, success, principal] of [
      [{ body: { role: "admin", permissions: checks } }, true, null],
      [{ body: { role: "admin", userId: "missing-user", permissions: checks } }, true, null],
      [{ body: { userId: adminId, permissions: checks } }, true, null],
      [{ body: { userId: memberId, role: "", permissions: checks } }, false, null],
      [{ body: { role: "user, admin", permissions: checks } }, false, null],
      [{ body: { role: "ghost", permissions: {} } }, false, null],
      [{ body: { role: "user", permissions: {} } }, false, null],
      [{ body: { role: "admin", permissions: { user: [] } } }, false, null],
      [{ body: { role: "admin", permissions: { missing: ["get"] } } }, false, null],
      [{ body: { role: "admin", permissions: checks }, profile: "admin-deny-all" }, false, null],
      [
        {
          body: { role: "creator", permissions: { user: ["create"] } },
          profile: "admin-role-manager",
        },
        true,
        null,
      ],
      [
        {
          body: { role: "creator", permissions: { user: ["set-role"] } },
          profile: "admin-role-manager",
        },
        false,
        null,
      ],
      [
        { body: { role: "user", userId: memberId, permissions: checks }, headers: admin.headers },
        true,
        admin.result.data!.user.email,
      ],
      [
        { body: { role: "admin", userId: adminId, permissions: checks }, headers: member.headers },
        false,
        member.result.data!.user.email,
      ],
    ] as const) {
      const result = await invoke(input);
      expect(result.status).toBe(200);
      expect(result.body).toEqual({ error: null, success });
      expect(result.principal).toBe(principal);
      expect(result.cookies).toEqual([
        "application_a=first; Path=/; HttpOnly",
        "application_b=second; Path=/; HttpOnly",
      ]);
      granted.push(result);
    }
    expect(await readUserState(ctx, adminId)).toEqual(before.admin);
    expect(await readUserState(ctx, memberId)).toEqual(before.member);
    return ctx.snapshot({ admin: admin.result, member: member.result, before, rejected, granted });
  },
);
