import { expect } from "bun:test";

import { compatScenario } from "../../../support/scenario";
import { readUserState } from "../../../support/verification";

compatScenario(
  "server admin revokeUserSessions deletes all target rows including expired sessions",
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
    const admin = await signup("revoke-all-admin", "admin-standard");
    const target = await signup("revoke-all-target");
    const foreign = await signup("revoke-all-foreign");
    const peerActor = ctx.actor("revoke-all-peer");
    const peer = await peerActor.client.signIn.email({
      email: target.result.data!.user.email,
      password: "Password123!",
    });
    expect(peer.error).toBeNull();
    const adminPeer = await ctx
      .actor("revoke-all-admin-peer")
      .client.signIn.email({ email: admin.result.data!.user.email, password: "Password123!" });
    expect(adminPeer.error).toBeNull();
    const clock = await ctx.rawRequest({
      path: "/__test/expire-session",
      method: "POST",
      json: { token: target.result.data!.token!, expiresAt: "2020-01-01T00:00:00.000Z" },
    });
    expect(clock.body).toEqual({ updated: 1 });
    const id = target.result.data!.user.id;
    const before = {
      admin: await readUserState(ctx, admin.result.data!.user.id),
      target: await readUserState(ctx, id),
      foreign: await readUserState(ctx, foreign.result.data!.user.id),
    };
    expect(before.target.sessions).toHaveLength(2);
    expect(before.admin.sessions).toHaveLength(2);
    async function invoke(input: Record<string, unknown>) {
      const response = await ctx
        .actor("revoke-all-control")
        .fetch(ctx.baseURL + "/__test/admin/server-api", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ operation: "revokeUserSessions", ...input }),
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
      [{ body: {} }, 400, "VALIDATION_ERROR"],
      [{ body: { userId: { toString: "bad" } } }, 400, "VALIDATION_ERROR"],
      [{ body: { userId: id } }, 401, undefined],
      [{ body: { userId: id }, headers: {} }, 401, undefined],
      [
        { body: { userId: id }, headers: foreign.headers },
        403,
        "YOU_ARE_NOT_ALLOWED_TO_REVOKE_USERS_SESSIONS",
      ],
      [
        { body: { userId: id }, headers: admin.headers, profile: "admin-role-manager" },
        403,
        "YOU_ARE_NOT_ALLOWED_TO_REVOKE_USERS_SESSIONS",
      ],
    ] as const) {
      const receipt = await invoke(input);
      expect(receipt.status).toBe(status);
      if (code) {
        expect(receipt.body.code).toBe(code);
      } else {
        expect(receipt.body).toBeNull();
      }
      rejected.push(receipt);
    }
    expect(await readUserState(ctx, id)).toEqual(before.target);
    const noops = [];
    for (const userId of ["missing-user", null, 7, [], {}, false]) {
      const receipt = await invoke({ body: { userId }, headers: admin.headers });
      expect(receipt.status).toBe(200);
      expect(receipt.body).toEqual({ success: true });
      expect(await readUserState(ctx, id)).toEqual(before.target);
      noops.push(receipt);
    }
    const revoked = [];
    for (let repeat = 0; repeat < 2; repeat++) {
      const receipt = await invoke({
        body: { userId: id, sessionToken: foreign.result.data!.token },
        query: { userId: foreign.result.data!.user.id },
        headers: admin.headers,
      });
      expect(receipt.status).toBe(200);
      expect(receipt.body).toEqual({ success: true });
      expect(receipt.principal).toBe(admin.result.data!.user.email);
      expect(receipt.cookies).toEqual([
        "application_a=first; Path=/; HttpOnly",
        "application_b=second; Path=/; HttpOnly",
      ]);
      expect(await readUserState(ctx, id)).toEqual({ ...before.target, sessions: [] });
      expect(await readUserState(ctx, admin.result.data!.user.id)).toEqual(before.admin);
      expect(await readUserState(ctx, foreign.result.data!.user.id)).toEqual(before.foreign);
      revoked.push(receipt);
    }
    const peerSession = await peerActor.client.getSession();
    expect(peerSession.data).toBeNull();
    const self = await invoke({
      body: { userId: admin.result.data!.user.id },
      headers: admin.headers,
    });
    expect(self.status).toBe(200);
    expect(self.body).toEqual({ success: true });
    expect(self.principal).toBe(admin.result.data!.user.email);
    expect(await readUserState(ctx, admin.result.data!.user.id)).toEqual({
      ...before.admin,
      sessions: [],
    });
    const stale = await invoke({
      body: { userId: foreign.result.data!.user.id },
      headers: admin.headers,
    });
    expect(stale.status).toBe(401);
    expect(stale.body).toBeNull();
    expect(await readUserState(ctx, foreign.result.data!.user.id)).toEqual(before.foreign);
    const login = await ctx
      .actor("revoke-all-new-login")
      .client.signIn.email({ email: target.result.data!.user.email, password: "Password123!" });
    expect(login.error).toBeNull();
    expect(login.data!.user.id).toBe(id);
    expect((await readUserState(ctx, id)).sessions).toHaveLength(1);
    return ctx.snapshot({
      admin: admin.result,
      target: target.result,
      foreign: foreign.result,
      peer,
      adminPeer,
      clock,
      before,
      rejected,
      noops,
      revoked,
      peerSession,
      self,
      stale,
      login,
    });
  },
);
