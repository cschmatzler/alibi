import { expect } from "bun:test";

import { compatScenario } from "../../../support/scenario";

compatScenario(
  "request-password-reset: missing sender denies before real adapter lookup or proof creation",
  async (ctx) => {
    async function control(mode?: string) {
      const response = await fetch(`${ctx.baseURL}/__test/session-adapter-failure`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(mode === undefined ? {} : { mode }),
      });
      expect(response.status).toBe(200);
      return response.json() as Promise<{ events: string[] }>;
    }
    async function physical() {
      const response = await fetch(`${ctx.baseURL}/__test/provider-batch/sql-state`);
      expect(response.status).toBe(200);
      return response.json();
    }
    await control("");
    const owner = ctx.actor("no-reset-owner", "password-reset-no-sender");
    const guest = ctx.actor("no-reset-guest", "password-reset-no-sender");
    const email = ctx.uniqueEmail("no-reset-owner");
    const signup = await owner.client.signUp.email({
      email,
      password: "password123",
      name: "No Reset Sender",
    });
    expect(signup.error).toBeNull();
    const before = await physical();
    const results = [];
    const mismatches = [];
    for (const requested of [email, ctx.uniqueEmail("no-reset-missing")]) {
      await control("get_user_by_email");
      const result = await guest.client.requestPasswordReset({
        email: requested,
        redirectTo: "/reset",
      });
      const receipts = await control();
      expect(receipts.events).toEqual([]);
      expect(await physical()).toEqual(before);
      expect(result.data).toBeNull();
      expect(result.error?.status).toBe(400);
      if (
        result.error?.code !== "RESET_PASSWORD_DISABLED" ||
        result.error?.message !== "Reset password isn't enabled"
      ) {
        mismatches.push(ctx.snapshot(result));
      }
      results.push(ctx.snapshot(result));
    }
    await control("");
    expect((await owner.client.getSession()).data?.user.id).toBe(signup.data!.user.id);
    await ctx.setResetPasswordMode("capture");
    const enabled = await ctx
      .actor("enabled-reset-guest")
      .client.requestPasswordReset({ email, redirectTo: "/reset" });
    expect(enabled.error).toBeNull();
    const delivery = await ctx.rawRequest({
      path: `/__test/reset-password-token?email=${encodeURIComponent(email)}`,
    });
    expect(delivery.status).toBe(200);
    const proof = delivery.body as { token: string; url: string };
    expect(proof.token.length).toBeGreaterThan(0);
    const verification = await ctx.readVerificationState({
      identifier: `reset-password:${proof.token}`,
    });
    expect(verification).toBeArray();
    expect(verification).toHaveLength(1);
    expect((verification as { identifier: string }[])[0]!.identifier).toBe(
      `reset-password:${proof.token}`,
    );
    const reset = await ctx
      .actor("enabled-reset-guest")
      .client.resetPassword({ token: proof.token, newPassword: "newPassword123!" });
    expect(reset.error).toBeNull();
    const login = await ctx
      .actor("enabled-reset-login", "password-reset-no-sender")
      .client.signIn.email({ email, password: "newPassword123!" });
    expect(login.error).toBeNull();
    expect(login.data?.user.id).toBe(signup.data!.user.id);
    expect(mismatches).toEqual([]);
    return {
      signup: ctx.snapshot(signup),
      results,
      enabled: ctx.snapshot(enabled),
      delivery,
      reset: ctx.snapshot(reset),
      login: ctx.snapshot(login),
    };
  },
  ["POST /request-password-reset"],
);
