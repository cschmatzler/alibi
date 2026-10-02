import { compatScenario } from "../../support/scenario";
import { expect } from "bun:test";
import { z } from "zod";

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
    expect(requestReset.error).toBeNull();
    const delivery = await ctx.rawRequest({
      path: `/__test/reset-password-token?email=${encodeURIComponent(email)}`,
    });
    expect(delivery.status).toBe(200);
    const { token, url } = deliveredReset.parse(delivery.body);
    const callback = await ctx.rawRequest({ path: url, redirect: "manual" });
    expect(callback.status).toBe(302);
    expect(
      new URL(callback.location!, ctx.baseURL).searchParams.get("token"),
    ).toBe(token);
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

compatScenario(
  "request password reset masks nonexistent email",
  async (ctx) => {
    const primary = ctx.actor();
    const result = await primary.client.requestPasswordReset({
      email: ctx.uniqueEmail("core-missing"),
      redirectTo: "/reset",
    });

    return {
      requestReset: ctx.snapshot(result),
    };
  },
);

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

compatScenario(
  "reset password callback redirects invalid token to error callback",
  async (ctx) => {
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
  },
);
