import { expect } from "bun:test";

import { compatScenario } from "../../../support/scenario";
import { readUserState } from "../../../support/verification";

compatScenario(
  "server admin removeUser deletes only the target user, accounts and sessions",
  async (ctx) => {
    async function signup(name: string, profile?: "admin-standard") {
      let cookie = "";
      const result = await ctx.actor(name, profile).client.signUp.email({
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
    const admin = await signup("remove-admin", "admin-standard");
    const target = await signup("remove-target");
    const foreign = await signup("remove-foreign");
    const id = target.result.data!.user.id;
    const peerActor = ctx.actor("remove-peer");
    const peer = await peerActor.client.signIn.email({
      email: target.result.data!.user.email,
      password: "Password123!",
    });
    expect(peer.error).toBeNull();
    await ctx.seedOAuthAccount({
      email: target.result.data!.user.email,
      providerId: "mock",
      accountId: ctx.uniqueToken("remove-remote"),
    });
    const clock = await ctx.rawRequest({
      path: "/__test/expire-session",
      method: "POST",
      json: { token: target.result.data!.token!, expiresAt: "2020-01-01T00:00:00.000Z" },
    });
    expect(clock.body).toEqual({ updated: 1 });
    const before = {
      admin: await readUserState(ctx, admin.result.data!.user.id),
      target: await readUserState(ctx, id),
      foreign: await readUserState(ctx, foreign.result.data!.user.id),
    };
    expect(before.target.accounts).toHaveLength(2);
    expect(before.target.sessions).toHaveLength(2);
    async function invoke(input: Record<string, unknown>) {
      const response = await ctx
        .actor("remove-control")
        .fetch(ctx.baseURL + "/__test/admin/server-api", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ operation: "removeUser", ...input }),
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
        "YOU_ARE_NOT_ALLOWED_TO_DELETE_USERS",
      ],
      [
        { body: { userId: id }, headers: admin.headers, profile: "admin-role-manager" },
        403,
        "YOU_ARE_NOT_ALLOWED_TO_DELETE_USERS",
      ],
      [
        { body: { userId: admin.result.data!.user.id }, headers: admin.headers },
        400,
        "YOU_CANNOT_REMOVE_YOURSELF",
      ],
      ...["missing-user", null, 7, [], {}].map(
        (userId) => [{ body: { userId }, headers: admin.headers }, 404, "USER_NOT_FOUND"] as const,
      ),
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
    expect(await readUserState(ctx, admin.result.data!.user.id)).toEqual(before.admin);
    expect(await readUserState(ctx, foreign.result.data!.user.id)).toEqual(before.foreign);
    const removed = await invoke({
      body: { userId: id, sessionToken: foreign.result.data!.token },
      query: { userId: foreign.result.data!.user.id },
      headers: admin.headers,
    });
    expect(removed.status).toBe(200);
    expect(removed.body).toEqual({ success: true });
    expect(removed.principal).toBe(admin.result.data!.user.email);
    expect(removed.cookies).toEqual([
      "application_a=first; Path=/; HttpOnly",
      "application_b=second; Path=/; HttpOnly",
    ]);
    const after = await readUserState(ctx, id);
    expect(after).toEqual({ user: null, accounts: [], sessions: [], twoFactorExists: false });
    expect(await readUserState(ctx, admin.result.data!.user.id)).toEqual(before.admin);
    expect(await readUserState(ctx, foreign.result.data!.user.id)).toEqual(before.foreign);
    const revoked = await peerActor.client.getSession();
    expect(revoked.data).toBeNull();
    const login = await ctx
      .actor("removed-login")
      .client.signIn.email({ email: target.result.data!.user.email, password: "Password123!" });
    expect(login.error).toMatchObject({ status: 401, code: "INVALID_EMAIL_OR_PASSWORD" });
    const repeated = await invoke({ body: { userId: id }, headers: admin.headers });
    expect(repeated.status).toBe(404);
    expect(repeated.body.code).toBe("USER_NOT_FOUND");
    expect(await readUserState(ctx, id)).toEqual(after);
    const adminSession = await ctx.rawRequest({
      path: "/api/auth/get-session",
      headers: admin.headers,
    });
    expect((adminSession.body as { user: { id: string } }).user.id).toBe(
      admin.result.data!.user.id,
    );
    return ctx.snapshot({
      admin: admin.result,
      target: target.result,
      foreign: foreign.result,
      peer,
      clock,
      before,
      rejected,
      removed,
      after,
      revoked,
      login,
      repeated,
      adminSession,
    });
  },
);
