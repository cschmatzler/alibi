import { expect } from "bun:test";

import { compatScenario } from "../../../support/scenario";

compatScenario("send verification email then verify marks the user verified", async (ctx) => {
  const primary = ctx.actor();
  const email = ctx.uniqueEmail("user-management-verify");

  const signup = await primary.client.signUp.email({
    email,
    password: "password123",
    name: "Verify User",
  });
  const send = await primary.client.sendVerificationEmail({
    email,
  });
  const record = (await ctx.readVerificationEmail({ email })) as { token: string };
  const verify = await primary.client.verifyEmail({
    query: {
      token: record.token,
    },
  });
  const session = await primary.client.getSession();

  return {
    signup: ctx.snapshot(signup),
    send: ctx.snapshot(send),
    verify: ctx.snapshot(verify),
    session: ctx.snapshot(session),
  };
});

compatScenario(
  "send verification email rejects email mismatch for authenticated user",
  async (ctx) => {
    const primary = ctx.actor();
    const email = ctx.uniqueEmail("user-management-verify-mismatch");

    const signup = await primary.client.signUp.email({
      email,
      password: "password123",
      name: "Mismatch Verify User",
    });
    const send = await primary.client.sendVerificationEmail({
      email: ctx.uniqueEmail("user-management-verify-mismatch-other"),
    });

    return {
      signup: ctx.snapshot(signup),
      send: ctx.snapshot(send),
    };
  },
);

compatScenario("send verification email rejects already verified user", async (ctx) => {
  const primary = ctx.actor();
  const email = ctx.uniqueEmail("user-management-verify-already");

  const signup = await primary.client.signUp.email({
    email,
    password: "password123",
    name: "Already Verified User",
  });
  await primary.client.sendVerificationEmail({
    email,
  });
  const record = (await ctx.readVerificationEmail({ email })) as { token: string };
  const verify = await primary.client.verifyEmail({
    query: {
      token: record.token,
    },
  });
  const sendAgain = await primary.client.sendVerificationEmail({
    email,
  });

  return {
    signup: ctx.snapshot(signup),
    verify: ctx.snapshot(verify),
    sendAgain: ctx.snapshot(sendAgain),
  };
});

compatScenario("verify email callback redirects to callbackURL", async (ctx) => {
  const primary = ctx.actor();
  const email = ctx.uniqueEmail("user-management-verify-callback");
  const callbackURL = "/callback?foo=bar&baz=qux";

  const signup = await primary.client.signUp.email({
    email,
    password: "password123",
    name: "Verify Callback User",
  });
  await primary.client.sendVerificationEmail({
    email,
  });
  const record = (await ctx.readVerificationEmail({ email })) as { token: string };
  const verify = await ctx.rawRequest({
    path: `/api/auth/verify-email?token=${encodeURIComponent(record.token)}&callbackURL=${encodeURIComponent(callbackURL)}`,
    redirect: "manual",
  });

  return {
    signup: ctx.snapshot(signup),
    verify: ctx.snapshot(verify),
  };
});

compatScenario("verify email rejects untrusted callbackURL", async (ctx) => {
  const primary = ctx.actor();
  const email = ctx.uniqueEmail("user-management-verify-evil-redirect");

  await primary.client.signUp.email({
    email,
    password: "password123",
    name: "Redirect Guard User",
  });
  await primary.client.sendVerificationEmail({ email });
  const record = (await ctx.readVerificationEmail({ email })) as { token: string };

  const verify = await ctx.rawRequest({
    path: `/api/auth/verify-email?token=${encodeURIComponent(record.token)}&callbackURL=${encodeURIComponent("https://evil.com/phish")}`,
    redirect: "manual",
  });

  return {
    verify: ctx.snapshot(verify),
  };
});

compatScenario(
  "verification delivery preserves encoded callback query and fragment bytes",
  async (ctx) => {
    const owner = ctx.actor("callback-owner");
    const email = ctx.uniqueEmail("callback-bytes");
    const signup = await owner.client.signUp.email({
      email,
      password: "password123",
      name: "Callback owner",
    });
    const userId = signup.data!.user.id;
    const before: any = await ctx.readUserState({ userId });
    const callbackURL =
      "/sign-in?verifiedEmail=a%2Bb%40fixture.test&next=%2Fdashboard%3Fx%3D1#done";
    const send = await owner.client.sendVerificationEmail({ email, callbackURL });
    expect(send.error).toBeNull();
    const delivery: any = await ctx.readVerificationEmail({ email });
    const deliveredURL = new URL(delivery.url);
    expect(deliveredURL.searchParams.get("callbackURL")).toBe(callbackURL);
    expect(deliveredURL.searchParams.get("token")).toBe(delivery.token);
    const guest = ctx.actor("callback-guest");
    const response = await fetch(delivery.url, { redirect: "manual" });
    expect(response.status).toBe(302);
    expect(response.headers.get("location")).toBe(callbackURL);
    expect(
      response.headers.getSetCookie().filter((cookie) => cookie.startsWith("better-auth.session")),
    ).toEqual([]);
    const after: any = await ctx.readUserState({ userId });
    expect(after.user).toEqual({ ...before.user, emailVerified: true });
    expect(after.accounts).toEqual(before.accounts);
    expect(after.sessions).toEqual(before.sessions);
    const guestSession = await guest.client.getSession();
    expect(guestSession.data).toBeNull();
    const ownerSession = await owner.client.getSession();
    expect(ownerSession.data?.user.id).toBe(userId);
    expect(ownerSession.data?.user.emailVerified).toBe(true);
    return {
      send: ctx.snapshot(send),
      callbackURL: deliveredURL.searchParams.get("callbackURL"),
      response: {
        status: response.status,
        location: response.headers.get("location"),
        cookies: response.headers.getSetCookie(),
      },
      before: ctx.snapshot(before),
      after: ctx.snapshot(after),
      guestSession: ctx.snapshot(guestSession),
      ownerSession: ctx.snapshot(ownerSession),
    };
  },
  ["POST /send-verification-email", "GET /verify-email", "GET /get-session"],
);
