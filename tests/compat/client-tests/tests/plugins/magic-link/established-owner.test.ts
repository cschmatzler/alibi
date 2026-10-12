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
    let foreignCookie = "";
    const foreignActor = ctx.actor("foreign");
    const foreign = await foreignActor.client.signUp.email({
      email: ctx.uniqueEmail("magic-foreign"),
      password,
      name: "Foreign",
      fetchOptions: {
        onSuccess({ response }) {
          foreignCookie = response.headers
            .getSetCookie()
            .map((raw) => raw.split(";")[0])
            .join("; ");
        },
      },
    });
    expect(foreign.error).toBeNull();
    const foreignBefore = await ctx.readUserState({ userId: foreign.data!.user.id });
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
    async function issue(body: unknown, headers?: Record<string, string>, originalRequest = false) {
      return ctx.rawRequest({
        path: "/__test/server-api/magic-link-sign-in",
        method: "POST",
        headers: { origin: new URL(ctx.baseURL).origin },
        json: { body, originalRequest, ...(headers ? { headers } : {}) },
      });
    }
    const missingHeaders = await issue({ email });
    expect(missingHeaders.status).toBe(400);
    expect(missingHeaders.body).toEqual({
      code: "VALIDATION_ERROR",
      message: "Headers is required",
    });
    const requestOnlyIssue = await issue({ email }, undefined, true);
    expect(requestOnlyIssue.status).toBe(400);
    expect(requestOnlyIssue.body).toEqual(missingHeaders.body);
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
    let delivered = await readMagicLink(ctx, issuedEmail);
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
    async function verify(
      query: unknown,
      headers?: Record<string, string>,
      originalRequest = false,
    ) {
      const response = await ctx
        .actor("new-browser")
        .fetch(`${ctx.baseURL}/__test/server-api/magic-link-verify`, {
          method: "POST",
          redirect: "manual",
          headers: { "content-type": "application/json", origin: new URL(ctx.baseURL).origin },
          body: JSON.stringify({ query, originalRequest, ...(headers ? { headers } : {}) }),
        });
      return {
        status: response.status,
        body: response.status === 302 ? null : ((await response.json()) as any),
        location: response.headers.get("location"),
        cookieCount: response.headers.getSetCookie().length,
      };
    }
    const noHeaders = await verify({ token: delivered.token });
    expect(noHeaders.status).toBe(400);
    expect(noHeaders.body).toEqual({ code: "VALIDATION_ERROR", message: "Headers is required" });
    const requestOnlyVerify = await verify({ token: delivered.token }, undefined, true);
    expect(requestOnlyVerify.status).toBe(400);
    expect(requestOnlyVerify.body).toEqual(noHeaders.body);
    expect(
      await ctx.readVerificationState({ identifier: `magic-link:${delivered.token}` }),
    ).toEqual(stored);
    const invalidQuery = await verify({ token: 42 }, {});
    expect(invalidQuery.status).toBe(400);
    expect(invalidQuery.body.code).toBe("VALIDATION_ERROR");
    expect(
      await ctx.readVerificationState({ identifier: `magic-link:${delivered.token}` }),
    ).toEqual(stored);
    expect(await ctx.readUserState({ userId })).toEqual(before);
    const trustedRedirect = await verify(
      { token: delivered.token, callbackURL: "https://foreign.example/steal" },
      {},
    );
    expect(trustedRedirect.status).toBe(302);
    expect(trustedRedirect.location).toBe("https://foreign.example/steal");
    expect(trustedRedirect.cookieCount).toBeGreaterThan(0);
    expect((await browser.getSession()).data!.user.id).toBe(userId);
    expect(
      await ctx.readVerificationState({ identifier: `magic-link:${delivered.token}` }),
    ).toEqual([]);
    const reissued = await issue({ email: issuedEmail }, {});
    expect(reissued.status).toBe(200);
    delivered = await readMagicLink(ctx, issuedEmail);
    const verified = await verify(
      { token: delivered.token, userId: foreign.data!.user.id },
      { cookie: foreignCookie, "user-agent": "Magic-SDK", "x-forwarded-for": "203.0.113.65" },
    );
    expect(verified.status).toBe(200);
    expect(verified.cookieCount).toBeGreaterThan(0);
    expect(verified.body.user).toMatchObject({
      id: userId,
      name: "Established owner",
      emailVerified: true,
    });
    expect(verified.body.session).toMatchObject({
      userId,
      userAgent: "Magic-SDK",
      ipAddress: "203.0.113.65",
    });
    const after = (await ctx.readUserState({ userId })) as any;
    expect(after.user).toEqual(before.user);
    expect(after.accounts).toEqual(before.accounts);
    expect(after.sessions).toHaveLength(4);
    for (const session of before.sessions) expect(after.sessions).toContainEqual(session);
    const replay = await verify({ token: delivered.token }, {});
    expect(replay.status).toBe(302);
    expect(new URL(replay.location!).searchParams.get("error")).toBe("INVALID_TOKEN");
    expect(replay.body).toBeNull();
    expect(await ctx.readUserState({ userId })).toEqual(after);
    expect(await ctx.readUserState({ userId: foreign.data!.user.id })).toEqual(foreignBefore);
    expect((await foreignActor.client.getSession()).data!.user.id).toBe(foreign.data!.user.id);
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
      requestOnlyIssue,
      requestOnlyVerify,
      missingHeaders,
      invalid,
      issued,
      delivered,
      noHeaders,
      invalidQuery,
      trustedRedirect,
      reissued,
      verified,
      replay,
      after,
      previousSession,
      secondSession,
      newSession,
      passwordStillWorks,
    });
  },
  ["GET /magic-link/verify"],
);
