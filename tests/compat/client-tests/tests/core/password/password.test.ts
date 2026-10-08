import { expect } from "bun:test";

import { z } from "zod";

import { compatScenario } from "../../../support/scenario";

const deliveredReset = z.object({
  token: z.string().min(1),
  url: z.string().url(),
});

compatScenario(
  "request password reset then reset password updates credentials",
  async (ctx) => {
    const primary = ctx.actor();
    const fresh = ctx.actor("fresh");
    const email = ctx.uniqueEmail("core-reset");

    const signup = await primary.client.signUp.email({
      email,
      password: "password123",
      name: "Reset User",
    });
    const requestReset = await primary.client.requestPasswordReset({
      email,
      redirectTo: "/reset",
    });
    expect(signup.error).toBeNull();
    expect(signup.data?.user).toMatchObject({ username: null, displayUsername: null });
    expect(requestReset.error).toBeNull();

    const delivery = await ctx.rawRequest({
      path: `/__test/reset-password-token?email=${encodeURIComponent(email)}`,
    });
    expect(delivery.status).toBe(200);

    const { token, url } = deliveredReset.parse(delivery.body);
    const callback = await ctx.rawRequest({ path: url, redirect: "manual" });
    expect(callback.status).toBe(302);
    expect(new URL(callback.location!, ctx.baseURL).searchParams.get("token")).toBe(token);

    const reset = await primary.client.resetPassword({
      newPassword: "newPassword123!",
      token,
    });
    const signin = await fresh.client.signIn.email({
      email,
      password: "newPassword123!",
    });
    expect(reset.error).toBeNull();
    expect(signin.error).toBeNull();
    expect(signin.data?.user.id).toBe(signup.data?.user.id);
    expect(signin.data?.user).toMatchObject({ username: null, displayUsername: null });

    const oldPassword = await ctx
      .actor("old-password")
      .client.signIn.email({ email, password: "password123" });
    expect(oldPassword.error?.status).toBe(401);

    return {
      signup: ctx.snapshot(signup),
      requestReset: ctx.snapshot(requestReset),
      reset: ctx.snapshot(reset),
      signin: ctx.snapshot(signin),
      delivery,
      callback,
      oldPassword: ctx.snapshot(oldPassword),
    };
  },
  ["POST /request-password-reset", "POST /reset-password"],
);

compatScenario("request password reset masks nonexistent email", async (ctx) => {
  const primary = ctx.actor();
  const result = await primary.client.requestPasswordReset({
    email: ctx.uniqueEmail("core-missing"),
    redirectTo: "/reset",
  });

  return {
    requestReset: ctx.snapshot(result),
  };
});

compatScenario("request password reset masks sender failure", async (ctx) => {
  const primary = ctx.actor();
  const email = ctx.uniqueEmail("core-sender-failure");

  await primary.client.signUp.email({
    email,
    password: "password123",
    name: "Sender Failure User",
  });
  await ctx.setResetPasswordMode("throw");

  const result = await primary.client.requestPasswordReset({
    email,
    redirectTo: "/reset",
  });

  return {
    requestReset: ctx.snapshot(result),
  };
});

compatScenario("reset password rejects invalid token", async (ctx) => {
  const primary = ctx.actor();
  const result = await primary.client.resetPassword({
    newPassword: "newPassword123!",
    token: "invalid-reset-token",
  });

  return {
    reset: ctx.snapshot(result),
  };
});

compatScenario("reset password token cannot be reused", async (ctx) => {
  const primary = ctx.actor();
  const email = ctx.uniqueEmail("core-reuse");

  await primary.client.signUp.email({
    email,
    password: "password123",
    name: "Reuse Token User",
  });
  await primary.client.requestPasswordReset({
    email,
    redirectTo: "/reset",
  });
  const delivery = await ctx.rawRequest({
    path: `/__test/reset-password-token?email=${encodeURIComponent(email)}`,
  });
  expect(delivery.status).toBe(200);

  const { token } = deliveredReset.parse(delivery.body);

  const first = await primary.client.resetPassword({
    newPassword: "newPassword123!",
    token,
  });
  const second = await primary.client.resetPassword({
    newPassword: "anotherPassword123!",
    token,
  });
  expect(first.error).toBeNull();
  expect(second.error).not.toBeNull();

  return {
    first: ctx.snapshot(first),
    second: ctx.snapshot(second),
    delivery,
  };
});

compatScenario(
  "reset password callback redirects with token and preserves callbackURL query params",
  async (ctx) => {
    const primary = ctx.actor();
    const email = ctx.uniqueEmail("core-reset-callback");
    const callbackURL = "/callback?foo=bar&baz=qux";

    await primary.client.signUp.email({
      email,
      password: "password123",
      name: "Reset Callback User",
    });
    const requested = await primary.client.requestPasswordReset({
      email,
      redirectTo: callbackURL,
    });
    expect(requested.error).toBeNull();

    const delivery = await ctx.rawRequest({
      path: `/__test/reset-password-token?email=${encodeURIComponent(email)}`,
    });
    expect(delivery.status).toBe(200);

    const { token, url } = deliveredReset.parse(delivery.body);

    const callback = await ctx.rawRequest({
      path: url,
      redirect: "manual",
    });
    expect(callback.status).toBe(302);

    const location = new URL(callback.location!, ctx.baseURL);
    expect(location.searchParams.get("token")).toBe(token);
    expect(location.searchParams.get("foo")).toBe("bar");
    expect(location.searchParams.get("baz")).toBe("qux");

    return {
      callback: ctx.snapshot(callback),
      delivery,
    };
  },
);

compatScenario("reset password callback redirects invalid token to error callback", async (ctx) => {
  const callbackURL = "/callback?foo=bar&baz=qux";

  const callback = await ctx.rawRequest({
    path: `/api/auth/reset-password/invalid-reset-token?callbackURL=${encodeURIComponent(callbackURL)}`,
    redirect: "manual",
  });
  const deniedURL = new URL(callbackURL, ctx.baseURL);
  deniedURL.searchParams.set("error", "INVALID_TOKEN");
  expect(callback.status).toBe(302);
  expect(callback.location).toBe(deniedURL.href);

  return {
    callback: ctx.snapshot(callback),
  };
});

compatScenario(
  "password reset validates foreign redirect before delivery or proof persistence",
  async (ctx) => {
    const owner = ctx.actor();
    const email = ctx.uniqueEmail("reset-redirect-owner");
    const signup = await owner.client.signUp.email({
      email,
      password: "password123",
      name: "Reset redirect owner",
    });
    expect(signup.error).toBeNull();
    const before = await ctx.readUserState({ userId: signup.data!.user.id });
    const readSql = async () =>
      (await (await fetch(`${ctx.baseURL}/__test/provider-batch/sql-state`)).json()) as Record<
        string,
        any[]
      >;
    const physicalBefore = await readSql();
    const source = "verification" in physicalBefore;
    expect(physicalBefore[source ? "verification" : "verifications"]).toEqual([]);
    const denied = await owner.client.requestPasswordReset({
      email,
      redirectTo: "https://foreign.fixture.test/reset",
    });
    expect(denied.error).toMatchObject({ status: 403, code: "INVALID_REDIRECT_URL" });
    const undelivered = await ctx.rawRequest({
      path: `/__test/reset-password-token?email=${encodeURIComponent(email)}`,
    });
    expect(undelivered.status).toBe(404);
    expect(await readSql()).toEqual(physicalBefore);
    expect(await ctx.readUserState({ userId: signup.data!.user.id })).toEqual(before);
    const trusted = "/reset?next=%2Fdone";
    const accepted = await owner.client.requestPasswordReset({ email, redirectTo: trusted });
    expect(accepted.error).toBeNull();
    const delivery = await ctx.rawRequest({
      path: `/__test/reset-password-token?email=${encodeURIComponent(email)}`,
    });
    const record = deliveredReset.parse(delivery.body);
    expect(new URL(record.url).searchParams.get("callbackURL")).toBe(trusted);
    const rows = (await readSql())[source ? "verification" : "verifications"]!;
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      identifier: `reset-password:${record.token}`,
      value: signup.data!.user.id,
    });
    const callback = await ctx.rawRequest({ path: record.url, redirect: "manual" });
    expect(callback.status).toBe(302);
    expect(new URL(callback.location!, ctx.baseURL).searchParams.get("next")).toBe("/done");
    expect(await ctx.readUserState({ userId: signup.data!.user.id })).toEqual(before);
    return {
      denied: ctx.snapshot(denied),
      undelivered,
      accepted: ctx.snapshot(accepted),
      delivery,
      callback,
    };
  },
  ["POST /request-password-reset", "GET /reset-password/{}"],
);

compatScenario(
  "expired stored reset proof replaces callback error without changing credentials",
  async (ctx) => {
    const owner = ctx.actor();
    const email = ctx.uniqueEmail("expired-reset-owner");
    const signup = await owner.client.signUp.email({
      email,
      password: "password123",
      name: "Expired reset owner",
    });
    expect(signup.error).toBeNull();
    const before = await ctx.readUserState({ userId: signup.data!.user.id });
    const readSql = async () =>
      (await (await fetch(`${ctx.baseURL}/__test/provider-batch/sql-state`)).json()) as Record<
        string,
        any[]
      >;
    const physical = await readSql();
    const source = "verification" in physical;
    const callbackURL = "/done?error=old&keep=a%2Bb#details";
    expect(
      (await owner.client.requestPasswordReset({ email, redirectTo: callbackURL })).error,
    ).toBeNull();
    const delivery = await ctx.rawRequest({
      path: `/__test/reset-password-token?email=${encodeURIComponent(email)}`,
    });
    const record = deliveredReset.parse(delivery.body);
    const identifier = `reset-password:${record.token}`;
    const expiredAt = "2020-01-01T00:00:00.000Z";
    const expire = await ctx.rawRequest({
      path: "/__test/verification-state",
      method: "POST",
      json: { action: "expire", identifier, expiresAt: expiredAt },
    });
    expect(expire.status).toBe(200);
    const proofBefore = await ctx.readVerificationState({ identifier });
    expect(proofBefore).toMatchObject([
      { identifier, value: signup.data!.user.id, expiresAt: expiredAt },
    ]);
    const rejected = await ctx.rawRequest({ path: record.url, redirect: "manual" });
    expect(rejected.status).toBe(302);
    const expected = new URL(callbackURL, ctx.baseURL);
    expected.searchParams.set("error", "INVALID_TOKEN");
    expect(rejected.location).toBe(expected.href);
    const proofAfter = await ctx.readVerificationState({ identifier });
    expect(await ctx.readUserState({ userId: signup.data!.user.id })).toEqual(before);
    const sqlAfter = await readSql();
    expect(sqlAfter[source ? "account" : "accounts"]).toEqual(
      physical[source ? "account" : "accounts"],
    );
    expect(sqlAfter[source ? "session" : "sessions"]).toEqual(
      physical[source ? "session" : "sessions"],
    );
    expect(
      (await owner.client.requestPasswordReset({ email, redirectTo: callbackURL })).error,
    ).toBeNull();
    const freshDelivery = await ctx.rawRequest({
      path: `/__test/reset-password-token?email=${encodeURIComponent(email)}`,
    });
    const fresh = deliveredReset.parse(freshDelivery.body);
    expect(fresh.token).not.toBe(record.token);
    const accepted = await ctx.rawRequest({ path: fresh.url, redirect: "manual" });
    expect(accepted.status).toBe(302);
    expect(new URL(accepted.location!, ctx.baseURL).searchParams.get("token")).toBe(fresh.token);
    const reset = await owner.client.resetPassword({
      token: fresh.token,
      newPassword: "replacementPassword123",
    });
    expect(reset.error).toBeNull();
    const login = await ctx
      .actor("fresh-login")
      .client.signIn.email({ email, password: "replacementPassword123" });
    expect(login.data?.user.id).toBe(signup.data!.user.id);
    return {
      delivery,
      rejected,
      proofBefore: ctx.snapshot(proofBefore),
      proofAfter: ctx.snapshot(proofAfter),
      freshDelivery,
      accepted,
      reset: ctx.snapshot(reset),
      login: ctx.snapshot(login),
    };
  },
  ["GET /reset-password/{}", "POST /request-password-reset", "POST /reset-password"],
);
