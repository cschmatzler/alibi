import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";
import { readUserState } from "../../../support/verification";

compatScenario(
  "server admin revokeUserSession deletes a token while preserving peer sessions",
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
    const admin = await signup("revoke-admin", "admin-standard");
    const target = await signup("revoke-target");
    const foreign = await signup("revoke-foreign");
    const peer = await ctx
      .actor("revoke-peer")
      .client.signIn.email({ email: target.result.data!.user.email, password: "Password123!" });
    expect(peer.error).toBeNull();
    const id = target.result.data!.user.id;
    const token = target.result.data!.token!;
    const before = {
      admin: await readUserState(ctx, admin.result.data!.user.id),
      target: await readUserState(ctx, id),
      foreign: await readUserState(ctx, foreign.result.data!.user.id),
    };
    expect(before.target.sessions).toHaveLength(2);
    async function invoke(input: Record<string, unknown>) {
      const response = await ctx
        .actor("revoke-control")
        .fetch(ctx.baseURL + "/__test/admin/server-api", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ operation: "revokeUserSession", ...input }),
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
      [{ body: {} }, 400, "VALIDATION_ERROR"],
      [{ body: { sessionToken: 7 } }, 400, "VALIDATION_ERROR"],
      [{ body: { sessionToken: null } }, 400, "VALIDATION_ERROR"],
      [{ body: { sessionToken: token } }, 401, undefined],
      [{ body: { sessionToken: token }, headers: {} }, 401, undefined],
      [
        { body: { sessionToken: token }, headers: foreign.headers },
        403,
        "YOU_ARE_NOT_ALLOWED_TO_REVOKE_USERS_SESSIONS",
      ],
      [
        { body: { sessionToken: token }, headers: admin.headers, profile: "admin-role-manager" },
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
    const receipts = [];
    const selected = before.target.sessions.find((session) => session.token === token)!;
    for (const sessionToken of ["", "missing-session-token", selected.id, token, token]) {
      const receipt = await invoke({
        body: { sessionToken, userId: foreign.result.data!.user.id },
        query: { sessionToken: foreign.result.data!.token },
        headers: admin.headers,
      });
      expect(receipt.status).toBe(200);
      expect(receipt.body).toEqual({ success: true });
      expect(receipt.principal).toBe(admin.result.data!.user.email);
      expect(receipt.cookies).toEqual([
        "application_a=first; Path=/; HttpOnly",
        "application_b=second; Path=/; HttpOnly",
      ]);
      const expected =
        sessionToken === token
          ? before.target.sessions.filter((session) => session.token !== token)
          : before.target.sessions;
      expect(await readUserState(ctx, id)).toEqual({ ...before.target, sessions: expected });
      expect(await readUserState(ctx, admin.result.data!.user.id)).toEqual(before.admin);
      expect(await readUserState(ctx, foreign.result.data!.user.id)).toEqual(before.foreign);
      receipts.push(receipt);
    }
    const revoked = await ctx.rawRequest({
      path: "/api/auth/get-session",
      headers: target.headers,
    });
    expect(revoked.body).toBeNull();
    const peerSession = await ctx.actor("revoke-peer").client.getSession();
    expect(peerSession.data?.user.id).toBe(id);
    expect(peerSession.data?.session.token).toBe(peer.data!.token!);
    const self = await invoke({
      body: { sessionToken: admin.result.data!.token! },
      headers: admin.headers,
    });
    expect(self.status).toBe(200);
    expect(self.body).toEqual({ success: true });
    expect(self.principal).toBe(admin.result.data!.user.email);
    expect((await readUserState(ctx, admin.result.data!.user.id)).sessions).toEqual([]);
    const stale = await invoke({
      body: { sessionToken: peer.data!.token! },
      headers: admin.headers,
    });
    expect(stale.status).toBe(401);
    expect(stale.body).toBeNull();
    expect((await readUserState(ctx, id)).sessions).toEqual(
      before.target.sessions.filter((session) => session.token !== token),
    );
    return ctx.snapshot({
      admin: admin.result,
      target: target.result,
      foreign: foreign.result,
      peer,
      before,
      rejected,
      receipts,
      revoked,
      peerSession,
      self,
      stale,
    });
  },
);
