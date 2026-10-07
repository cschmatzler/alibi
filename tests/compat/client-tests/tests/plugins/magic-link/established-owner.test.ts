import { expect } from "bun:test";

import { compatScenario } from "../../../support/scenario";
import { magicLinkClient, readMagicLink } from "./helpers";
compatScenario(
  "magic-link returning verified credential owner preserves established accounts and browser sessions",
  async (ctx) => {
    const previous = ctx.actor("previous");
    const second = ctx.actor("second");
    const email = ctx.uniqueEmail("established-owner");
    const password = "established-password123";
    const signup = await previous.client.signUp.email({
      email,
      password,
      name: "Established owner",
    });
    expect(signup.error).toBeNull();
    const sent = await previous.client.sendVerificationEmail({ email });
    expect(sent.error).toBeNull();
    const receipt = await ctx.rawRequest({
      path: `/__test/verification-email?email=${encodeURIComponent(email)}`,
    });
    expect(receipt.status).toBe(200);
    const proof = await previous.client.verifyEmail({
      query: { token: (receipt.body as any).token },
    });
    expect(proof.error).toBeNull();
    const login = await second.client.signIn.email({ email, password });
    expect(login.error).toBeNull();
    expect(login.data!.user.emailVerified).toBe(true);
    await ctx.seedOAuthAccount({ email, providerId: "google", accountId: "established-google" });
    const userId = signup.data!.user.id;
    const before = (await ctx.readUserState({ userId })) as any;
    expect(before.accounts).toHaveLength(2);
    expect(before.sessions).toHaveLength(2);
    const browser = magicLinkClient(ctx, "new-browser");
    const issued = await browser.signIn.magicLink({ email, name: "Ignored incoming name" });
    expect(issued.error).toBeNull();
    const delivered = await readMagicLink(ctx, email);
    const verified = await browser.magicLink.verify({ query: { token: delivered.token } });
    expect(verified.error).toBeNull();
    expect(verified.data!.user).toMatchObject({
      id: userId,
      name: "Established owner",
      emailVerified: true,
    });
    const after = (await ctx.readUserState({ userId })) as any;
    expect(after.user).toEqual(before.user);
    expect(after.accounts).toEqual(before.accounts);
    expect(after.sessions).toHaveLength(3);
    for (const session of before.sessions) expect(after.sessions).toContainEqual(session);
    const previousSession = await previous.client.getSession();
    const secondSession = await second.client.getSession();
    const newSession = await browser.getSession();
    for (const result of [previousSession, secondSession, newSession])
      expect(result.data!.user.id).toBe(userId);
    const passwordStillWorks = await ctx
      .actor("password-control")
      .client.signIn.email({ email, password });
    expect(passwordStillWorks.error).toBeNull();
    expect(passwordStillWorks.data!.user.id).toBe(userId);
    expect(
      await ctx.readVerificationState({ identifier: `magic-link:${delivered.token}` }),
    ).toEqual([]);
    return ctx.snapshot({
      signup,
      sent,
      proof,
      login,
      before,
      issued,
      delivered,
      verified,
      after,
      previousSession,
      secondSession,
      newSession,
      passwordStillWorks,
    });
  },
  ["GET /magic-link/verify"],
);
