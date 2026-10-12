import { expect } from "bun:test";

import { compatScenario } from "../../../support/scenario";
import { readUserState } from "../../../support/verification";

compatScenario(
  "server admin setUserPassword replaces or creates credentials without revoking sessions",
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
    const admin = await signup("password-admin", "admin-standard");
    const target = await signup("password-target");
    const fresh = await signup("password-no-credential");
    const foreign = await signup("password-foreign");
    await ctx.removeCredentialAccount({ email: fresh.result.data!.user.email });
    for (const owner of [target, fresh]) {
      await ctx.seedOAuthAccount({
        email: owner.result.data!.user.email,
        providerId: "mock",
        accountId: ctx.uniqueToken("password-remote"),
      });
    }
    const id = target.result.data!.user.id;
    const before = {
      admin: await readUserState(ctx, admin.result.data!.user.id),
      target: await readUserState(ctx, id),
      fresh: await readUserState(ctx, fresh.result.data!.user.id),
      foreign: await readUserState(ctx, foreign.result.data!.user.id),
    };
    expect(before.target.accounts).toHaveLength(2);
    expect(before.fresh.accounts).toHaveLength(1);
    async function invoke(input: Record<string, unknown>) {
      const response = await ctx
        .actor("password-control")
        .fetch(ctx.baseURL + "/__test/admin/server-api", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ operation: "setUserPassword", ...input }),
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
      [{ body: { userId: id, newPassword: "" } }, 400, "VALIDATION_ERROR"],
      [{ body: { userId: "", newPassword: "Changed123!" } }, 400, "VALIDATION_ERROR"],
      [{ body: { userId: id, newPassword: 7 } }, 400, "VALIDATION_ERROR"],
      [{ body: { userId: id, newPassword: "Changed123!" } }, 401, undefined],
      [
        { body: { userId: id, newPassword: "short" }, headers: foreign.headers },
        403,
        "YOU_ARE_NOT_ALLOWED_TO_SET_USERS_PASSWORD",
      ],
      [
        {
          body: { userId: id, newPassword: "Changed123!" },
          headers: admin.headers,
          profile: "admin-role-manager",
        },
        403,
        "YOU_ARE_NOT_ALLOWED_TO_SET_USERS_PASSWORD",
      ],
      [
        { body: { userId: "missing-user", newPassword: "short" }, headers: admin.headers },
        400,
        "PASSWORD_TOO_SHORT",
      ],
      [
        { body: { userId: id, newPassword: "x".repeat(129) }, headers: admin.headers },
        400,
        "PASSWORD_TOO_LONG",
      ],
      [
        { body: { userId: id, newPassword: "🔐".repeat(65) }, headers: admin.headers },
        400,
        "PASSWORD_TOO_LONG",
      ],
      [
        { body: { userId: null, newPassword: "Changed123!" }, headers: admin.headers },
        404,
        "USER_NOT_FOUND",
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
    expect(await readUserState(ctx, fresh.result.data!.user.id)).toEqual(before.fresh);
    const changed = [];
    for (const [owner, newPassword] of [
      [target, "🔐🔐🔐🔐"],
      [fresh, "Fresh123!"],
      [admin, "AdminNew123!"],
    ] as const) {
      const ownerId = owner.result.data!.user.id;
      const prior = await readUserState(ctx, ownerId);
      const receipt = await invoke({
        body: { userId: ownerId, newPassword, revokeOtherSessions: true },
        query: { userId: foreign.result.data!.user.id },
        headers: admin.headers,
      });
      expect(receipt.status).toBe(200);
      expect(receipt.body).toEqual({ status: true });
      expect(receipt.principal).toBe(admin.result.data!.user.email);
      expect(receipt.cookies).toEqual([
        "application_a=first; Path=/; HttpOnly",
        "application_b=second; Path=/; HttpOnly",
      ]);
      const after = await readUserState(ctx, ownerId);
      expect(after.user).toEqual(prior.user);
      expect(after.sessions).toEqual(prior.sessions);
      expect(after.accounts.filter((account) => account.providerId !== "credential")).toEqual(
        prior.accounts.filter((account) => account.providerId !== "credential"),
      );
      const credential = after.accounts.filter((account) => account.providerId === "credential");
      expect(credential).toHaveLength(1);
      expect(credential[0]!.accountId).toBe(ownerId);
      const oldCredential = prior.accounts.find((account) => account.providerId === "credential");
      if (oldCredential) {
        expect(credential[0]!.id).toBe(oldCredential.id);
      }
      expect(await readUserState(ctx, foreign.result.data!.user.id)).toEqual(before.foreign);
      const live = await ctx.rawRequest({ path: "/api/auth/get-session", headers: owner.headers });
      expect((live.body as { user: { id: string } }).user.id).toBe(ownerId);
      const old = await ctx
        .actor("password-old-" + owner.result.data!.user.name)
        .client.signIn.email({ email: owner.result.data!.user.email, password: "Password123!" });
      expect(old.error).toMatchObject({ status: 401, code: "INVALID_EMAIL_OR_PASSWORD" });
      const login = await ctx
        .actor("password-new-" + owner.result.data!.user.name)
        .client.signIn.email({ email: owner.result.data!.user.email, password: newPassword });
      expect(login.error).toBeNull();
      expect(login.data!.user.id).toBe(ownerId);
      changed.push({ receipt, after, live, old, login });
    }
    return ctx.snapshot({
      admin: admin.result,
      target: target.result,
      fresh: fresh.result,
      foreign: foreign.result,
      before,
      rejected,
      changed,
    });
  },
);
