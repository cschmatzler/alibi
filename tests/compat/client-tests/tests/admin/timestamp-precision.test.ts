import { expect } from "bun:test";
import { createAuthClient } from "better-auth/client";
import { adminClient } from "better-auth/client/plugins";
import { compatScenario } from "../../support/scenario";
import { adminActor, signUpAndPromoteAdmin } from "./helpers";

compatScenario(
  "admin stored timestamp precision survives official read, update and list without shifting dates",
  async (ctx) => {
    const owner = await signUpAndPromoteAdmin(ctx, "owner", "timestamp-owner", "Timestamp Owner");
    expect(owner.signup.error).toBeNull();
    if (!owner.signup.data?.token) throw new Error("actual owner session required");
    const target = adminActor(ctx, "target"),
      email = ctx.uniqueEmail("timestamp-target");
    const signup = await target.client.signUp.email({
      email,
      password: "password123",
      name: "Timestamp Target",
    });
    expect(signup.error).toBeNull();
    if (!signup.data?.token) throw new Error("actual target session required");
    const userId = signup.data.user.id,
      token = signup.data.token;
    const wireUsers: Record<string, unknown>[] = [];
    const reader = createAuthClient({
      baseURL: ctx.baseURL,
      plugins: [adminClient()],
      fetchOptions: {
        customFetchImpl: async (input, init) => {
          const response = await owner.fetch(input, init);
          const body = await response.clone().json();
          const users = Array.isArray(body.users) ? body.users : [body.user ?? body];
          for (const user of users) if (user?.id === userId) wireUsers.push(user);
          return response;
        },
      },
    });
    const before = await ctx.readUserState({ userId }),
      observations = [];
    for (const fraction of ["145927", "145927123", "145000"]) {
      const createdAt = `2026-09-30T22:11:23.${fraction}Z`,
        updatedAt = "2026-09-30T22:12:34.321456Z";
      const stored = await ctx.rawRequest({
        actor: "timestamp-control",
        path: "/__test/admin-user-timestamps",
        method: "POST",
        json: { userId, createdAt, updatedAt },
      });
      expect(stored).toMatchObject({
        status: 200,
        body: { userId, createdAt, updatedAt },
      });
      const read = await reader.admin.getUser({ query: { id: userId } });
      expect(read.error).toBeNull();
      expect(read.data?.createdAt).toBeInstanceOf(Date);
      expect(read.data?.updatedAt).toBeInstanceOf(Date);
      expect(read.data?.createdAt.getTime()).toBe(Date.parse("2026-09-30T22:11:23.145Z"));
      expect(read.data?.updatedAt.getTime()).toBe(Date.parse("2026-09-30T22:12:34.321Z"));
      const readWire = wireUsers.at(-1)!;
      expect(readWire.createdAt).toBe("2026-09-30T22:11:23.145Z");
      expect(readWire.updatedAt).toBe("2026-09-30T22:12:34.321Z");
      const denied = await target.adminClient.admin.setRole({
        userId: owner.signup.data.user.id,
        role: "user",
      });
      expect(denied.error?.status).toBe(403);
      const update = await reader.admin.setRole({ userId, role: "user" });
      expect(update.error).toBeNull();
      expect(update.data?.user.id).toBe(userId);
      expect(update.data?.user.createdAt).toBeInstanceOf(Date);
      expect(update.data?.user.updatedAt).toBeInstanceOf(Date);
      expect(update.data?.user.createdAt.getTime()).toBe(Date.parse("2026-09-30T22:11:23.145Z"));
      const updateWire = wireUsers.at(-1)!;
      expect(updateWire.createdAt).toBe("2026-09-30T22:11:23.145Z");
      expect(updateWire.updatedAt).toMatch(/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/);
      expect(update.data?.user.updatedAt.getTime()).toBe(
        Date.parse(updateWire.updatedAt as string),
      );
      const listed = await reader.admin.listUsers({
        query: {
          searchField: "email",
          searchOperator: "contains",
          searchValue: email,
        },
      });
      expect(listed.error).toBeNull();
      expect(listed.data?.users).toHaveLength(1);
      expect(listed.data?.users[0]?.id).toBe(userId);
      expect(listed.data?.users[0]?.createdAt).toBeInstanceOf(Date);
      expect(listed.data?.users[0]?.createdAt.getTime()).toBe(
        Date.parse("2026-09-30T22:11:23.145Z"),
      );
      const listWire = wireUsers.at(-1)!;
      expect(listWire).toEqual(updateWire);
      const state = await ctx.readUserState({ userId });
      expect(state).toEqual(before);
      const persisted = await ctx.rawRequest({
        actor: "timestamp-control",
        path: `/__test/admin-role-state?email=${encodeURIComponent(email)}`,
      });
      expect(persisted.status).toBe(200);
      const storedUser = (
        persisted.body as {
          user: { id: string; createdAt: string; role: string };
        }
      ).user;
      expect(storedUser.id).toBe(userId);
      expect(storedUser.role).toBe("user");
      expect(storedUser.createdAt).toMatch(
        new RegExp(
          `^2026-09-30T22:11:23\\.${fraction === "145000" ? "(?:145000|145)" : fraction}Z$`,
        ),
      );
      const current = await target.client.getSession();
      expect(current.data?.user.id).toBe(userId);
      expect(current.data?.session.token).toBe(token);
      observations.push({
        stored,
        read: ctx.snapshot(read),
        readWire,
        denied: ctx.snapshot(denied),
        update: ctx.snapshot(update),
        updateWire,
        listed: ctx.snapshot(listed),
        listWire,
        state,
        persisted,
        current: ctx.snapshot(current),
      });
    }
    const ownerSession = await owner.client.getSession();
    expect(ownerSession.data?.user.id).toBe(owner.signup.data.user.id);
    expect(ownerSession.data?.session.token).toBe(owner.signup.data.token);
    return {
      owner: ctx.snapshot(owner.signup),
      signup: ctx.snapshot(signup),
      before,
      observations,
      ownerSession: ctx.snapshot(ownerSession),
    };
  },
  ["GET /admin/get-user", "GET /admin/list-users", "POST /admin/set-role"],
);
