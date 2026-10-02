import { expect } from "bun:test";
import { createAuthClient } from "better-auth/client";
import { twoFactorClient } from "better-auth/client/plugins";
import { z } from "zod";
import { authProfilePath } from "../../support/profiles";
import { compatScenario } from "../../support/scenario";

compatScenario(
  "two-factor skip enrollment rejects a configured user update before factor persistence or session rotation",
  async (ctx) => {
    const profile = "two-factor-skip-user-hook";
    const client = createAuthClient({
      baseURL: `${ctx.baseURL}${authProfilePath(profile)}`,
      plugins: [twoFactorClient()],
      fetchOptions: { customFetchImpl: ctx.actor("owner", profile).fetch },
    });
    const signup = await client.signUp.email({
      email: ctx.uniqueEmail("skip-hook-owner"),
      name: "Hook Owner",
      password: "password123",
    });
    expect(signup.error).toBeNull();
    if (!signup.data) throw new Error("owner required");
    const original = await client.getSession();
    expect(original.data?.user.id).toBe(signup.data.user.id);
    const before = await ctx.readUserState({ userId: signup.data.user.id });
    const wrong = await client.twoFactor.enable({ password: "wrong-password" });
    expect(wrong.error?.code).toBe("INVALID_PASSWORD");
    const rejected = await client.twoFactor.enable({ password: "password123" });
    expect(rejected.error).toMatchObject({
      status: 400,
      code: "USER_UPDATE_DENIED",
      message: "Configured user update denied",
    });
    const after = z
      .object({
        twoFactorExists: z.boolean(),
        sessions: z.array(z.object({ token: z.string(), userId: z.string() })),
      })
      .parse(await ctx.readUserState({ userId: signup.data.user.id }));
    expect(after.twoFactorExists).toBe(false);
    expect(after.sessions).toHaveLength(1);
    expect(after.sessions[0]).toMatchObject({
      token: original.data?.session.token,
      userId: signup.data.user.id,
    });
    expect(await ctx.readUserState({ userId: signup.data.user.id })).toEqual(before);
    const current = await client.getSession();
    expect(current.data?.user.twoFactorEnabled).toBe(false);
    expect(current.data?.session.token).toBe(original.data?.session.token);
    const factor = await ctx.rawRequest({
      path: "/__test/two-factor-policy",
      method: "POST",
      json: { userId: signup.data.user.id },
    });
    expect(factor).toMatchObject({ status: 200, body: null });
    return ctx.snapshot({ signup, original, before, wrong, rejected, after, current, factor });
  },
  ["POST /two-factor/enable"],
);

for (const profile of [
  "two-factor-skip-session-cancel",
  "two-factor-skip-session-forbidden",
] as const) {
  compatScenario(
    `two-factor skip enrollment ${profile.endsWith("cancel") ? "cancellation returns an empty 500" : "preserves a genuine identical-message 403"} without factor or token mutation`,
    async (ctx) => {
      const receipts: Array<{ status: number; body: string }> = [];
      const actor = ctx.actor("owner", profile);
      const client = createAuthClient({
        baseURL: `${ctx.baseURL}${authProfilePath(profile)}`,
        plugins: [twoFactorClient()],
        fetchOptions: {
          customFetchImpl: async (input, init) => {
            const response = await actor.fetch(input, init);
            const url = input instanceof Request ? input.url : input.toString();
            if (url.endsWith("/two-factor/enable"))
              receipts.push({ status: response.status, body: await response.clone().text() });
            return response;
          },
        },
      });
      const signup = await client.signUp.email({
        email: ctx.uniqueEmail(profile),
        name: "Session Hook Owner",
        password: "password123",
      });
      expect(signup.error).toBeNull();
      if (!signup.data) throw new Error("owner required");
      const original = await client.getSession();
      expect(original.data?.user.twoFactorEnabled).toBe(false);
      const before = z
        .object({ sessions: z.array(z.unknown()) })
        .parse(await ctx.readUserState({ userId: signup.data.user.id }));
      const wrong = await client.twoFactor.enable({ password: "wrong-password" });
      expect(wrong.error?.code).toBe("INVALID_PASSWORD");
      const rejected = await client.twoFactor.enable({ password: "password123" });
      expect(rejected.error?.status).toBe(profile.endsWith("cancel") ? 500 : 403);
      expect(receipts).toHaveLength(2);
      expect(receipts[1]).toEqual(
        profile.endsWith("cancel")
          ? { status: 500, body: "" }
          : {
              status: 403,
              body: JSON.stringify({ message: "session creation cancelled by database hook" }),
            },
      );
      const after = z
        .object({ twoFactorExists: z.boolean(), sessions: z.array(z.unknown()) })
        .parse(await ctx.readUserState({ userId: signup.data.user.id }));
      expect(after.twoFactorExists).toBe(false);
      expect(after.sessions).toHaveLength(1);
      expect(after.sessions).toEqual(before.sessions);
      const current = await client.getSession();
      expect(current.data?.user.id).toBe(signup.data.user.id);
      expect(current.data?.user.twoFactorEnabled).toBe(true);
      expect(current.data?.session.token).toBe(original.data?.session.token);
      const factor = await ctx.rawRequest({
        path: "/__test/two-factor-policy",
        method: "POST",
        json: { userId: signup.data.user.id },
      });
      expect(factor).toMatchObject({ status: 200, body: null });
      return ctx.snapshot({
        signup,
        original,
        before,
        wrong,
        rejected,
        receipt: receipts[1],
        after,
        current,
        factor,
      });
    },
    ["POST /two-factor/enable"],
  );
}
