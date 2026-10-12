import { expect } from "bun:test";

import { compatScenario } from "../../../support/scenario";
import { readUserState } from "../../../support/verification";

compatScenario(
  "server admin listUserSessions returns persisted target sessions including expired rows",
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
    const admin = await signup("session-list-admin", "admin-standard");
    const target = await signup("session-list-target");
    const foreign = await signup("session-list-foreign");
    const peer = await ctx
      .actor("session-list-peer")
      .client.signIn.email({ email: target.result.data!.user.email, password: "Password123!" });
    expect(peer.error).toBeNull();
    const expiredToken = target.result.data!.token!;
    const id = target.result.data!.user.id;
    const clock = await ctx.rawRequest({
      path: "/__test/expire-session",
      method: "POST",
      json: { token: expiredToken, expiresAt: "2020-01-01T00:00:00.000Z" },
    });
    expect(clock.body).toEqual({ updated: 1 });
    const before = {
      admin: await readUserState(ctx, admin.result.data!.user.id),
      target: await readUserState(ctx, id),
      foreign: await readUserState(ctx, foreign.result.data!.user.id),
    };
    async function invoke(input: Record<string, unknown>) {
      const response = await ctx
        .actor("session-list-control")
        .fetch(ctx.baseURL + "/__test/admin/server-api", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ operation: "listUserSessions", ...input }),
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
      [{ body: { userId: { toString: "bad" } }, headers: admin.headers }, 400],
      [{ body: { userId: id } }, 401],
      [{ body: { userId: id }, headers: {} }, 401],
      [{ body: { userId: id }, headers: foreign.headers }, 403],
      [{ body: { userId: id }, profile: "admin-role-manager", headers: admin.headers }, 403],
    ] as const) {
      const result = await invoke(input);
      expect(result.status).toBe(status);
      if (status === 401) {
        expect(result.body).toBeNull();
      }
      if (status === 403) {
        expect(result.body.code).toBe("YOU_ARE_NOT_ALLOWED_TO_LIST_USERS_SESSIONS");
      }
      rejected.push(result);
    }
    const listed = [];
    for (const [userId, tokens] of [
      [id, [expiredToken, peer.data!.token!]],
      [foreign.result.data!.user.id, [foreign.result.data!.token!]],
      ["missing-user", []],
      [null, []],
      [7, []],
      [[], []],
    ] as const) {
      const result = await invoke({
        body: { userId, onlyActiveSessions: true },
        query: { userId: admin.result.data!.user.id },
        headers: admin.headers,
      });
      expect(result.status).toBe(200);
      expect(
        result.body.sessions.map((session: { token: string }) => session.token).sort(),
      ).toEqual([...tokens].sort());
      for (const session of result.body.sessions) {
        expect(session.userId).toBe(userId);
        expect(session).not.toHaveProperty("user");
        expect(session).not.toHaveProperty("password");
        const stored = (userId === id ? before.target : before.foreign).sessions.find(
          (row) => row.token === session.token,
        )!;
        expect(session.id).toBe(stored.id);
        expect(session.expiresAt).toBe(stored.expiresAt);
      }
      if (userId === id) {
        expect(
          result.body.sessions.find((session: { token: string }) => session.token === expiredToken)
            .expiresAt,
        ).toBe("2020-01-01T00:00:00.000Z");
      }
      expect(result.principal).toBe(admin.result.data!.user.email);
      expect(result.cookies).toEqual([
        "application_a=first; Path=/; HttpOnly",
        "application_b=second; Path=/; HttpOnly",
      ]);
      listed.push(result);
    }
    expect(await readUserState(ctx, id)).toEqual(before.target);
    expect(await readUserState(ctx, admin.result.data!.user.id)).toEqual(before.admin);
    expect(await readUserState(ctx, foreign.result.data!.user.id)).toEqual(before.foreign);
    return ctx.snapshot({
      admin: admin.result,
      target: target.result,
      foreign: foreign.result,
      peer,
      clock,
      before,
      rejected,
      listed,
    });
  },
);
