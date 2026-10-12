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
    async function proofCount() {
      const control = await ctx.rawRequest({
        path: "/__test/magic-link/generator-control",
        method: "POST",
        json: {},
      });
      expect(control.status).toBe(200);
      return (control.body as { proofCount: number }).proofCount;
    }
    const proofsBefore = await proofCount();
    const browser = magicLinkClient(ctx, "new-browser");
    async function issue(body: unknown, headers?: Record<string, string>) {
      return ctx.rawRequest({
        path: "/__test/server-api/magic-link-sign-in",
        method: "POST",
        json: { body, ...(headers ? { headers } : {}) },
      });
    }
    const missingHeaders = await issue({ email });
    expect(missingHeaders.status).toBe(400);
    expect(missingHeaders.body).toEqual({
      code: "VALIDATION_ERROR",
      message: "Headers is required",
    });
    const invalid = await issue({ email, metadata: [] }, {});
    expect(invalid.status).toBe(400);
    expect((invalid.body as any).code).toBe("VALIDATION_ERROR");
    expect(await ctx.readUserState({ userId })).toEqual(before);
    expect(await proofCount()).toBe(proofsBefore);
    const absent = await ctx.rawRequest({
      path: `/__test/magic-link?email=${encodeURIComponent(email)}`,
    });
    expect(absent.body).toBeNull();
    const issuedEmail = email.toUpperCase();
    const metadata = { scope: "server", nested: { one: true } };
    const issued = await issue(
      {
        email: issuedEmail,
        name: "Ignored incoming name",
        metadata,
        callbackURL: "/returning",
        newUserCallbackURL: "/welcome",
        errorCallbackURL: "/oops",
        userId: "foreign-selector",
      },
      { origin: "https://foreign.example" },
    );
    expect(issued.status).toBe(200);
    expect(issued.body).toEqual({ status: true });
    expect(await ctx.readUserState({ userId })).toEqual(before);
    const delivered = await readMagicLink(ctx, issuedEmail);
    expect(delivered.metadata).toEqual(metadata);
    const url = new URL(delivered.url);
    for (const [key, value] of [
      ["callbackURL", "/returning"],
      ["newUserCallbackURL", "/welcome"],
      ["errorCallbackURL", "/oops"],
    ] as const) {
      expect(url.searchParams.get(key!)).toBe(value);
    }
    const stored = await ctx.readVerificationState({ identifier: `magic-link:${delivered.token}` });
    expect(stored).toHaveLength(1);
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
    for (const result of [previousSession, secondSession, newSession]) {
      expect(result.data!.user.id).toBe(userId);
    }
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
      missingHeaders,
      invalid,
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
