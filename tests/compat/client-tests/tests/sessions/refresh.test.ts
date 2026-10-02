import { expect } from "bun:test";

import { z } from "zod";

import { compatScenario, type ScenarioContext } from "../../support/scenario";

const signupToken = z.object({ token: z.string(), user: z.object({ id: z.string() }) });

const state = z
  .object({
    sessions: z.array(
      z
        .object({ id: z.string(), token: z.string(), userId: z.string(), expiresAt: z.string() })
        .passthrough(),
    ),
  })
  .passthrough();

async function persisted(ctx: ScenarioContext, userId: string) {
  return state.parse(
    (await ctx.rawRequest({ path: `/__test/user-state?userId=${encodeURIComponent(userId)}` }))
      .body,
  );
}

async function age(ctx: ScenarioContext, token: string, milliseconds = 3_600_000) {
  const expiresAt = new Date(Date.now() + milliseconds).toISOString();
  const result = await ctx.rawRequest({
    path: "/__test/expire-session",
    method: "POST",
    json: { token, expiresAt },
  });
  expect(result.status).toBe(200);
  expect(result.body).toEqual({ updated: 1 });

  return expiresAt;
}

compatScenario(
  "session reads refresh from persisted expiry and renew the signed cookie",
  async (ctx) => {
    const actor = ctx.actor();
    const issued = await actor.client.signUp.email({
      email: ctx.uniqueEmail("expiry-read"),
      name: "Expiry Reader",
      password: "password123",
    });
    const credentials = signupToken.parse(issued.data);
    const oldExpiry = await age(ctx, credentials.token);
    const before = await persisted(ctx, credentials.user.id);
    expect(before.sessions[0]?.expiresAt).toBe(oldExpiry);

    const read = await actor.client.getSession();
    expect(read.error).toBeNull();
    expect(read.data?.session.token).toBe(credentials.token);
    expect(read.data?.session.userId).toBe(credentials.user.id);
    expect(read.data?.session.expiresAt.getTime()).toBeGreaterThan(
      Date.parse(oldExpiry) + 6 * 86_400_000,
    );

    const after = await persisted(ctx, credentials.user.id);
    expect(after.sessions).toHaveLength(1);
    expect(after.sessions[0]?.expiresAt).toBe(read.data?.session.expiresAt.toISOString());
    expect(after.sessions[0]?.id).toBe(before.sessions[0]?.id);

    const repeated = await actor.client.getSession();
    expect(repeated.data?.session.expiresAt.toISOString()).toBe(after.sessions[0]?.expiresAt);

    return { issued, before, read, after, repeated };
  },
  ["GET /get-session"],
);

compatScenario(
  "deferred session GET preserves rows while POST performs refresh and expired cleanup",
  async (ctx) => {
    const actor = ctx.actor("deferred-reader", "session-deferred");
    let issuedCookie: string | null = null;
    const issued = await actor.client.signUp.email(
      { email: ctx.uniqueEmail("deferred-read"), name: "Deferred Reader", password: "password123" },
      {
        onSuccess(result) {
          issuedCookie = result.response.headers.getSetCookie()[0]?.split(";")[0] ?? null;
        },
      },
    );
    const credentials = signupToken.parse(issued.data);
    const oldExpiry = await age(ctx, credentials.token);
    const before = await persisted(ctx, credentials.user.id);
    const deferred = await actor.client.getSession();
    const deferredValue: unknown = deferred.data;
    expect(z.object({ needsRefresh: z.literal(true) }).parse(deferredValue).needsRefresh).toBe(
      true,
    );
    expect((await persisted(ctx, credentials.user.id)).sessions).toEqual(before.sessions);

    const refreshed = await actor.client.getSession({ fetchOptions: { method: "POST" } });
    expect(refreshed.error).toBeNull();
    expect(refreshed.data?.session.token).toBe(credentials.token);
    expect(refreshed.data?.session.expiresAt.getTime()).toBeGreaterThan(
      Date.parse(oldExpiry) + 6 * 86_400_000,
    );

    const renewed = await persisted(ctx, credentials.user.id);
    expect(renewed.sessions[0]?.expiresAt).toBe(refreshed.data?.session.expiresAt.toISOString());

    await age(ctx, credentials.token, -10_000);
    const retained = await persisted(ctx, credentials.user.id);
    const expiredGet = await actor.client.getSession();
    expect(expiredGet.data).toBeNull();
    expect((await persisted(ctx, credentials.user.id)).sessions).toEqual(retained.sessions);

    const cleaner = ctx.actor("deferred-cleaner", "session-deferred");
    const signedCookie = z.string().min(1).parse(issuedCookie);
    const cleanup = await cleaner.fetch("/__test/profiles/session-deferred/api/auth/get-session", {
      method: "POST",
      headers: { cookie: signedCookie },
    });
    expect(cleanup.status).toBe(200);

    const cleanedBody: unknown = await cleanup.json();
    expect(cleanedBody).toBeNull();

    const cleaned = await persisted(ctx, credentials.user.id);
    expect(cleaned.sessions).toEqual([]);

    return { issued, before, deferred, refreshed, renewed, expiredGet, retained, cleaned };
  },
  ["POST /get-session"],
);

compatScenario(
  "session refresh suppression preserves expiry and foreign revocation cannot extend a session",
  async (ctx) => {
    const owner = ctx.actor();
    const attacker = ctx.actor("foreign-revoker");
    const issued = await owner.client.signUp.email({
      email: ctx.uniqueEmail("foreign-owner"),
      name: "Owner",
      password: "password123",
    });
    await attacker.client.signUp.email({
      email: ctx.uniqueEmail("foreign-attacker"),
      name: "Attacker",
      password: "password123",
    });
    const credentials = signupToken.parse(issued.data);
    await age(ctx, credentials.token);
    const before = await persisted(ctx, credentials.user.id);
    const suppressed = await owner.client.getSession({ query: { disableRefresh: true } });
    expect(suppressed.error).toBeNull();
    expect((await persisted(ctx, credentials.user.id)).sessions).toEqual(before.sessions);

    const revoked = await attacker.client.revokeSession({ token: credentials.token });
    expect(revoked.data?.status).toBe(true);

    const untouched = await persisted(ctx, credentials.user.id);
    expect(untouched.sessions).toEqual(before.sessions);

    const empty = await attacker.client.revokeSession({ token: "" });
    expect(empty.data?.status).toBe(true);

    return { issued, before, suppressed, revoked, untouched, empty };
  },
  ["POST /revoke-session"],
);

compatScenario(
  "session refresh preferences use raw query truthiness and configured disabling",
  async (ctx) => {
    const actor = ctx.actor("query-reader");
    const issued = await actor.client.signUp.email({
      email: ctx.uniqueEmail("query-read"),
      name: "Query Reader",
      password: "password123",
    });
    const credentials = signupToken.parse(issued.data);
    await age(ctx, credentials.token);
    const before = await persisted(ctx, credentials.user.id);
    // The pinned Zod coercion treats the URL string "false" as truthy.
    const suppressed = await actor.client.getSession({ query: { disableRefresh: false } });
    expect(suppressed.error).toBeNull();
    expect((await persisted(ctx, credentials.user.id)).sessions).toEqual(before.sessions);

    const emptyQuery = await actor.fetch("/api/auth/get-session?disableRefresh=");
    expect(emptyQuery.status).toBe(200);

    const refreshed: unknown = await emptyQuery.json();
    const after = await persisted(ctx, credentials.user.id);
    expect(Date.parse(z.string().parse(after.sessions[0]?.expiresAt))).toBeGreaterThan(
      Date.parse(z.string().parse(before.sessions[0]?.expiresAt)) + 6 * 86_400_000,
    );

    const profiles = [];

    for (const profile of ["session-no-refresh", "session-deferred-no-refresh"] as const) {
      const disabled = ctx.actor(profile, profile);
      const signedUp = await disabled.client.signUp.email({
        email: ctx.uniqueEmail(profile),
        name: "Disabled Reader",
        password: "password123",
      });
      const identity = signupToken.parse(signedUp.data);
      await age(ctx, identity.token);
      const original = await persisted(ctx, identity.user.id);
      const read = await disabled.client.getSession();
      expect(read.error).toBeNull();

      const returned: unknown = read.data;

      if (profile === "session-deferred-no-refresh") {
        expect(z.object({ needsRefresh: z.literal(false) }).parse(returned).needsRefresh).toBe(
          false,
        );
      }

      expect((await persisted(ctx, identity.user.id)).sessions).toEqual(original.sessions);

      profiles.push({ profile, signedUp, original, read });
    }

    return { issued, before, suppressed, refreshed, after, profiles };
  },
  ["GET /get-session"],
);

compatScenario(
  "session refresh uses the first signed dont-remember cookie",
  async (ctx) => {
    const actor = ctx.actor("remember-reader");
    const email = ctx.uniqueEmail("remember-order");
    await actor.client.signUp.email({ email, name: "Remember Reader", password: "password123" });
    await actor.client.signOut();
    let signedCookies: string[] = [];
    const signedIn = await actor.client.signIn.email(
      { email, password: "password123", rememberMe: false },
      {
        onSuccess(result) {
          signedCookies = result.response.headers
            .getSetCookie()
            .map((value) => value.split(";")[0] ?? "");
        },
      },
    );
    const credentials = signupToken.parse(signedIn.data);
    const sessionCookie = z
      .string()
      .min(1)
      .parse(signedCookies.find((value) => value.startsWith("better-auth.session_token=")));
    const preference = z
      .string()
      .min(1)
      .parse(signedCookies.find((value) => value.startsWith("better-auth.dont_remember=")));
    const issuedState = await persisted(ctx, credentials.user.id);
    expect(issuedState.sessions).toHaveLength(1);
    expect(Date.parse(z.string().parse(issuedState.sessions[0]?.expiresAt))).toBeLessThan(
      Date.now() + 86_400_000,
    );

    const cookieName = "better-auth.dont_remember";
    const observations = [];

    for (const [name, header, renew] of [
      ["invalid first", `${sessionCookie}; ${cookieName}=invalid; ${preference}`, true],
      ["valid first", `${sessionCookie}; ${preference}; ${cookieName}=invalid`, false],
    ] as const) {
      await age(ctx, credentials.token);
      const before = await persisted(ctx, credentials.user.id);
      const reader = ctx.actor(name);
      const response = await reader.fetch("/api/auth/get-session", { headers: { cookie: header } });
      expect(response.status).toBe(200);

      const value: unknown = await response.json();
      const after = await persisted(ctx, credentials.user.id);

      if (renew) {
        expect(Date.parse(z.string().parse(after.sessions[0]?.expiresAt))).toBeGreaterThan(
          Date.parse(z.string().parse(before.sessions[0]?.expiresAt)) + 6 * 86_400_000,
        );
        expect(
          response.headers.getSetCookie().some((cookie) => cookie.includes("Max-Age=604800")),
        ).toBe(true);
      } else {
        expect(after.sessions).toEqual(before.sessions);
        expect(response.headers.getSetCookie()).toEqual([]);
      }

      observations.push({ name, before, value, after });
    }

    return { signedIn, issuedState, observations };
  },
  ["GET /get-session"],
);

compatScenario(
  "session nested middleware clears expired cookies and rejects invalid revocation bodies",
  async (ctx) => {
    const actor = ctx.actor();
    const signedUp = await actor.client.signUp.email({
      email: ctx.uniqueEmail("middleware-expiry"),
      name: "Expired Reader",
      password: "password123",
    });
    const credentials = signupToken.parse(signedUp.data);
    const invalid = [];

    for (const body of [
      {},
      { token: null },
      { token: 123 },
      { token: [] },
      { token: false },
      null,
    ]) {
      const result = await ctx.rawRequest({
        actor: "invalid-guest",
        path: "/api/auth/revoke-session",
        method: "POST",
        json: body,
      });
      expect(result.status).toBe(400);
      expect(z.object({ code: z.literal("VALIDATION_ERROR") }).parse(result.body).code).toBe(
        "VALIDATION_ERROR",
      );

      invalid.push(result);
    }

    const stateBefore = await persisted(ctx, credentials.user.id);
    expect(stateBefore.sessions).toHaveLength(1);

    await age(ctx, credentials.token, -10_000);
    const expired = await actor.client.listSessions();
    expect(expired.error?.status).toBe(401);

    const after = await persisted(ctx, credentials.user.id);
    expect(after.sessions).toEqual([]);

    const anonymous = await actor.client.getSession();
    expect(anonymous.data).toBeNull();

    return { signedUp, invalid, stateBefore, expired, after, anonymous };
  },
  ["GET /list-sessions"],
);

compatScenario(
  "session listing enforces default freshness while configured zero permits old sessions",
  async (ctx) => {
    const observations = [];
    for (const profile of [undefined, "session-no-freshness"] as const) {
      const actor = ctx.actor(profile ?? "fresh-default", profile);
      const issued = await actor.client.signUp.email({
        email: ctx.uniqueEmail(profile ?? "fresh-default"),
        name: "Old Reader",
        password: "password123",
      });
      const credentials = signupToken.parse(issued.data);
      const clock = await ctx.rawRequest({
        path: "/__test/expire-session",
        method: "POST",
        json: {
          token: credentials.token,
          expiresAt: new Date(Date.now() + 7 * 86_400_000).toISOString(),
          createdAt: new Date(Date.now() - 25 * 3_600_000).toISOString(),
        },
      });
      expect(clock.body).toEqual({ updated: 1 });

      const before = await persisted(ctx, credentials.user.id);
      const listed = await actor.client.listSessions();

      if (profile === undefined) {
        expect(listed.error?.status).toBe(403);
        expect(listed.error?.code).toBe("SESSION_NOT_FRESH");
      } else {
        expect(listed.error).toBeNull();
        expect(listed.data).toHaveLength(1);
        expect(listed.data?.[0]?.token).toBe(credentials.token);
      }

      const after = await persisted(ctx, credentials.user.id);
      expect(after.sessions).toEqual(before.sessions);

      observations.push({ profile: profile ?? "default", issued, before, listed, after });
    }
    return { observations };
  },
  ["GET /list-sessions"],
);

compatScenario(
  "configured session cleanup clears account and OAuth cookies in upstream order",
  async (ctx) => {
    const actor = ctx.actor("configured-cleanup", "session-cookie-cleanup");
    let clearedNames: string[] = [];
    const issued = await actor.client.signUp.email({
      email: ctx.uniqueEmail("cookie-cleanup"),
      name: "Cleanup Reader",
      password: "password123",
    });
    const credentials = signupToken.parse(issued.data);
    await age(ctx, credentials.token);
    const before = await persisted(ctx, credentials.user.id);
    const signedOut = await actor.client.signOut(
      {},
      {
        onSuccess(result) {
          clearedNames = result.response.headers
            .getSetCookie()
            .map((cookie) => cookie.split("=")[0] ?? "");
        },
      },
    );
    expect(signedOut.data?.success).toBe(true);
    expect(clearedNames).toEqual([
      "better-auth.session_token",
      "better-auth.session_data",
      "better-auth.account_data",
      "better-auth.oauth_state",
      "better-auth.dont_remember",
    ]);

    const after = await persisted(ctx, credentials.user.id);
    expect(after.sessions).toEqual([]);

    const expiredIssued = await actor.client.signIn.email({
      email: ctx.uniqueEmail("cookie-cleanup"),
      password: "password123",
    });
    const expiredIdentity = signupToken.parse(expiredIssued.data);
    await age(ctx, expiredIdentity.token, -10_000);
    const expired = await actor.client.getSession({
      fetchOptions: {
        onSuccess(result) {
          clearedNames = result.response.headers
            .getSetCookie()
            .map((cookie) => cookie.split("=")[0] ?? "");
        },
      },
    });
    expect(expired.data).toBeNull();
    expect(clearedNames).toEqual([
      "better-auth.session_token",
      "better-auth.session_data",
      "better-auth.account_data",
      "better-auth.oauth_state",
      "better-auth.dont_remember",
    ]);
    expect((await persisted(ctx, credentials.user.id)).sessions).toEqual([]);

    return { issued, before, signedOut, after, expiredIssued, expired, clearedNames };
  },
  ["POST /sign-out", "GET /get-session"],
);

compatScenario(
  "temporary credential signup and signin preserve one-day sessions and reject malformed preferences",
  async (ctx) => {
    const observations = [];
    for (const rememberMe of [false, true]) {
      const actor = ctx.actor(`temporary-${rememberMe}`);
      const email = ctx.uniqueEmail(`temporary-${rememberMe}`);
      const issued = await actor.client.signUp.email(
        { email, name: "Temporary Reader", password: "password123" },
        { body: { rememberMe } },
      );
      const credentials = signupToken.parse(issued.data);
      const before = await persisted(ctx, credentials.user.id);
      expect(before.sessions).toHaveLength(1);

      const read = await actor.client.getSession();
      expect(read.error).toBeNull();

      const lifetime =
        z.number().parse(read.data?.session.expiresAt.getTime()) -
        z.number().parse(read.data?.session.createdAt.getTime());
      expect(Math.abs(lifetime - (rememberMe ? 7 : 1) * 86_400_000)).toBeLessThan(1500);
      expect((await persisted(ctx, credentials.user.id)).sessions).toEqual(before.sessions);

      const invalid = [];

      for (const preference of [null, "false", 0, [], {}]) {
        for (const path of ["/sign-up/email", "/sign-in/email"]) {
          const result = await ctx.rawRequest({
            actor: "bad-remember",
            path: `/api/auth${path}`,
            method: "POST",
            json: {
              email,
              name: "Temporary Reader",
              password: "password123",
              rememberMe: preference,
            },
          });
          expect(result.status).toBe(400);
          expect(z.object({ code: z.literal("VALIDATION_ERROR") }).parse(result.body).code).toBe(
            "VALIDATION_ERROR",
          );

          invalid.push({ path, result });
        }
      }

      expect((await persisted(ctx, credentials.user.id)).sessions).toEqual(before.sessions);

      const invalidOrder = [];

      for (const json of [
        { email: "invalid", password: "password123", rememberMe: null },
        { email: "invalid", password: null },
      ]) {
        const result = await ctx.rawRequest({
          actor: "bad-remember",
          path: "/api/auth/sign-in/email",
          method: "POST",
          json,
        });
        expect(result.status).toBe(400);
        expect(z.object({ code: z.literal("VALIDATION_ERROR") }).parse(result.body).code).toBe(
          "VALIDATION_ERROR",
        );

        invalidOrder.push(result);
      }

      expect((await persisted(ctx, credentials.user.id)).sessions).toEqual(before.sessions);

      observations.push({ rememberMe, issued, before, read, invalid, invalidOrder });
    }
    return { observations };
  },
  ["POST /sign-up/email", "POST /sign-in/email", "GET /get-session"],
);
