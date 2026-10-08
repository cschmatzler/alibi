import { expect } from "bun:test";

import { Cookie } from "tough-cookie";

import { compatScenario } from "../../../support/scenario";
import {
  expireVerification,
  readUserState,
  requireUser,
  verificationCount,
} from "../../../support/verification";
import { magicLinkClient, readMagicLink } from "./helpers";

compatScenario(
  "magic links deliver metadata and authenticate a new user with one-time consumption",
  async (ctx) => {
    const client = magicLinkClient(ctx);
    const email = ctx.uniqueEmail("magic-new");
    const issue = await client.signIn.magicLink({
      email,
      name: "Magic Owner",
      metadata: { campaign: "welcome" },
    });
    expect(issue.error).toBeNull();

    const delivery = await readMagicLink(ctx, email);
    expect(delivery.metadata).toEqual({ campaign: "welcome" });

    const url = new URL(delivery.url);
    expect(url.pathname).toBe("/api/auth/magic-link/verify");
    expect(url.searchParams.get("callbackURL")).toBe("/");
    expect(await verificationCount(ctx, `magic-link:${delivery.token}`)).toBe(1);

    // Official verify client omits callbackURL so the successful JSON includes
    // the actual session. The delivered browser URL is tested separately below.
    const verify = await client.magicLink.verify({ query: { token: delivery.token } });
    expect(verify.error).toBeNull();

    const user = requireUser(verify.data?.user);
    const session = await client.getSession();
    expect(session.data?.user.id).toBe(user.id);
    expect(user.emailVerified).toBe(true);

    const state = await readUserState(ctx, user.id);
    expect(state.sessions).toHaveLength(1);
    expect(await verificationCount(ctx, `magic-link:${delivery.token}`)).toBe(0);

    const replay = await ctx.rawRequest({
      path: `/api/auth/magic-link/verify?token=${encodeURIComponent(delivery.token)}`,
      redirect: "manual",
    });
    expect(replay.status).toBe(302);
    expect(new URL(replay.location ?? "", ctx.baseURL).searchParams.get("error")).toBe(
      "INVALID_TOKEN",
    );

    return {
      issue: ctx.snapshot(issue),
      verify: ctx.snapshot(verify),
      session: ctx.snapshot(session),
      replay: ctx.snapshot(replay),
      state: ctx.snapshot(state),
    };
  },
  ["POST /sign-in/magic-link", "GET /magic-link/verify"],
);

compatScenario(
  "magic-link redirect validates origin before consuming and chooses the new-user callback",
  async (ctx) => {
    const client = magicLinkClient(ctx);
    const email = ctx.uniqueEmail("magic-redirect");
    const issue = await client.signIn.magicLink({
      email,
      callbackURL: "/existing?via=magic",
      newUserCallbackURL: "/welcome?via=magic",
      errorCallbackURL: "/failure?via=magic",
    });
    expect(issue.error).toBeNull();

    const delivery = await readMagicLink(ctx, email);
    const forbidden = await ctx.rawRequest({
      path: `/api/auth/magic-link/verify?token=${encodeURIComponent(delivery.token)}&callbackURL=${encodeURIComponent("https://foreign.example/steal")}`,
      redirect: "manual",
    });
    expect(forbidden.status).toBe(403);
    expect(await verificationCount(ctx, `magic-link:${delivery.token}`)).toBe(1);

    const url = new URL(delivery.url);
    const verified = await ctx.rawRequest({
      path: `${url.pathname}${url.search}`,
      redirect: "manual",
    });
    expect(verified.status).toBe(302);
    expect(new URL(verified.location ?? "", ctx.baseURL).pathname).toBe("/welcome");

    const session = await client.getSession();
    expect(session.data?.user.email).toBe(email);

    const replay = await ctx.rawRequest({
      path: `${url.pathname}${url.search}`,
      redirect: "manual",
    });
    expect(replay.status).toBe(302);

    const error = new URL(replay.location ?? "", ctx.baseURL);
    expect(error.pathname).toBe("/failure");
    expect(error.searchParams.get("via")).toBe("magic");
    expect(error.searchParams.get("error")).toBe("INVALID_TOKEN");

    return {
      issue: ctx.snapshot(issue),
      forbidden: ctx.snapshot(forbidden),
      verified: ctx.snapshot(verified),
      session: ctx.snapshot(session),
      replay: ctx.snapshot(replay),
    };
  },
  ["GET /magic-link/verify"],
);

compatScenario(
  "magic-link email proof removes unverified linked access and keeps the user identity",
  async (ctx) => {
    const previous = magicLinkClient(ctx, "previous");
    const owner = magicLinkClient(ctx);
    const email = ctx.uniqueEmail("magic-promote");
    const signup = await previous.signUp.email({
      email,
      password: "unproven-password123",
      name: "Previous",
    });
    const user = requireUser(signup.data?.user);
    await ctx.seedOAuthAccount({ email, providerId: "google", accountId: "unproven-google" });
    const before = await readUserState(ctx, user.id);
    expect(before.accounts).toHaveLength(2);

    await owner.signIn.magicLink({ email });
    const delivery = await readMagicLink(ctx, email);
    const verify = await owner.magicLink.verify({ query: { token: delivery.token } });
    expect(verify.error).toBeNull();
    expect(verify.data?.user.id).toBe(user.id);

    const previousSession = await previous.getSession();
    expect(previousSession.data).toBeNull();

    const state = await readUserState(ctx, user.id);
    expect(state.accounts).toHaveLength(0);
    expect(state.sessions).toHaveLength(1);
    expect(state.user?.emailVerified).toBe(true);

    const password = await previous.signIn.email({ email, password: "unproven-password123" });
    expect(password.error).not.toBeNull();

    return {
      before: ctx.snapshot(before),
      verify: ctx.snapshot(verify),
      previousSession: ctx.snapshot(previousSession),
      password: ctx.snapshot(password),
      state: ctx.snapshot(state),
    };
  },
  ["GET /magic-link/verify"],
);

compatScenario(
  "expired magic links delete verification state and cannot create a session",
  async (ctx) => {
    const client = magicLinkClient(ctx);
    const email = ctx.uniqueEmail("magic-expired");
    await client.signIn.magicLink({ email });
    const delivery = await readMagicLink(ctx, email);
    await expireVerification(ctx, `magic-link:${delivery.token}`);
    const verify = await ctx.rawRequest({
      path: `/api/auth/magic-link/verify?token=${encodeURIComponent(delivery.token)}&errorCallbackURL=${encodeURIComponent("/expired")}`,
      redirect: "manual",
    });
    expect(verify.status).toBe(302);
    expect(new URL(verify.location ?? "", ctx.baseURL).searchParams.get("error")).toBe(
      "INVALID_TOKEN",
    );
    expect(await verificationCount(ctx, `magic-link:${delivery.token}`)).toBe(0);

    const session = await client.getSession();
    expect(session.data).toBeNull();

    return {
      verify: ctx.snapshot(verify),
      session: ctx.snapshot(session),
      remainingVerifications: 0,
    };
  },
  ["GET /magic-link/verify"],
);

compatScenario(
  "magic links reject malformed bodies callbacks and missing query tokens before consumption",
  async (ctx) => {
    const client = magicLinkClient(ctx);
    const email = ctx.uniqueEmail("magic-validation");
    const results = [];

    for (const json of [null, {}, { email: "a@b.c" }, { email, name: null, metadata: [] }]) {
      const response = await ctx.rawRequest({
        path: "/api/auth/sign-in/magic-link",
        method: "POST",
        json,
      });
      expect(response.status).toBe(400);
      results.push(ctx.snapshot(response));
    }

    // 1.7.7 rejects records for another purpose before consuming them or
    // trusting their email as a login identity, even for an existing account.
    const victim = ctx.actor("record-victim");
    const signup = await victim.client.signUp.email({
      email,
      password: "password123",
      name: "Protected",
    });
    expect(signup.error).toBeNull();
    const victimId = requireUser(signup.data?.user).id;
    const protectedBefore = await readUserState(ctx, victimId);
    const recordRejections = [];
    const values = [
      { email },
      { type: "oauth-state", email },
      { type: "magic-link", email, extra: true },
      { type: "magic-link", email, name: null },
      { type: "magic-link", email: "invalid-email" },
      [],
      null,
    ];
    for (const [index, value] of values.entries()) {
      const token = `wrong-purpose-${index}`;
      const identifier = `magic-link:${token}`;
      const seeded = await ctx.rawRequest({
        path: "/__test/verification-state",
        method: "POST",
        json: {
          action: "seed",
          identifier,
          value: JSON.stringify(value),
          expiresAt: "2099-01-01T00:00:00.000Z",
        },
      });
      expect(seeded.status).toBe(200);
      const denied = await ctx.rawRequest({
        path: `/api/auth/magic-link/verify?token=${token}`,
        redirect: "manual",
      });
      expect(denied.status).toBe(302);
      expect(new URL(denied.location ?? "", ctx.baseURL).searchParams.get("error")).toBe(
        "INVALID_TOKEN",
      );
      expect(await verificationCount(ctx, identifier)).toBe(1);
      expect(await readUserState(ctx, victimId)).toEqual(protectedBefore);
      recordRejections.push(ctx.snapshot(denied));
    }
    const legacy = await ctx.rawRequest({
      path: "/__test/verification-state",
      method: "POST",
      json: {
        action: "seed",
        identifier: "legacy-magic",
        value: JSON.stringify({ type: "magic-link", email }),
        expiresAt: "2099-01-01T00:00:00.000Z",
      },
    });
    expect(legacy.status).toBe(200);
    const legacyDenied = await ctx.rawRequest({
      path: "/api/auth/magic-link/verify?token=legacy-magic",
      redirect: "manual",
    });
    expect(new URL(legacyDenied.location ?? "", ctx.baseURL).searchParams.get("error")).toBe(
      "INVALID_TOKEN",
    );
    expect(await verificationCount(ctx, "legacy-magic")).toBe(1);
    expect(await readUserState(ctx, victimId)).toEqual(protectedBefore);

    const missing = await ctx.rawRequest({
      path: "/api/auth/magic-link/verify",
      redirect: "manual",
    });
    expect(missing.status).toBe(400);

    await client.signIn.magicLink({ email });
    const delivery = await readMagicLink(ctx, email);

    for (const field of ["newUserCallbackURL", "errorCallbackURL"]) {
      const response = await ctx.rawRequest({
        path: `/api/auth/magic-link/verify?token=${encodeURIComponent(delivery.token)}&${field}=${encodeURIComponent("https://foreign.example/steal")}`,
        redirect: "manual",
      });
      expect(response.status).toBe(403);

      results.push(ctx.snapshot(response));
      expect(await verificationCount(ctx, `magic-link:${delivery.token}`)).toBe(1);
    }

    const verify = await client.magicLink.verify({ query: { token: delivery.token } });
    expect(verify.error).toBeNull();

    const replay = await ctx.rawRequest({
      path: `/api/auth/magic-link/verify?token=${encodeURIComponent(delivery.token)}&errorCallbackURL=${encodeURIComponent("/error?error=old&error_description=preserved")}`,
      redirect: "manual",
    });
    const target = new URL(replay.location ?? "", ctx.baseURL);
    expect(target.searchParams.get("error")).toBe("INVALID_TOKEN");
    expect(target.searchParams.get("error_description")).toBe("preserved");

    return {
      results,
      missing: ctx.snapshot(missing),
      recordRejections,
      legacyDenied: ctx.snapshot(legacyDenied),
      verify: ctx.snapshot(verify),
      replay: ctx.snapshot(replay),
    };
  },
);

compatScenario(
  "magic-link receiving browser respects genuine signed nonpersistent preference",
  async (ctx) => {
    const preferenceOwner = ctx.actor("preference-owner");
    let signupCookies: string[] = [];
    const preference = await preferenceOwner.client.signUp.email({
      email: ctx.uniqueEmail("preference-owner"),
      password: "password123",
      name: "Preference owner",
    });
    expect(preference.error).toBeNull();
    const preferredSession = await preferenceOwner.client.signIn.email(
      { email: preference.data!.user.email, password: "password123", rememberMe: false },
      {
        onResponse({ response }) {
          signupCookies = response.headers.getSetCookie();
        },
      },
    );
    expect(preferredSession.error).toBeNull();
    const receipt = signupCookies
      .map((cookie) => Cookie.parse(cookie))
      .find((cookie) => cookie?.key.endsWith("dont_remember"));
    if (!receipt)
      throw new Error("rememberMe=false must issue a genuine signed browser preference");
    expect(receipt.value).toContain(".");
    const observations = [];
    for (const persistent of [false, true]) {
      const name = persistent ? "persistent-receiver" : "nonpersistent-receiver";
      const receiver = magicLinkClient(ctx, name);
      expect((await receiver.getSession()).data).toBeNull();
      const email = ctx.uniqueEmail(name);
      expect(
        (await receiver.signIn.magicLink({ email, name: "Magic receiving owner" })).error,
      ).toBeNull();
      const delivery = await readMagicLink(ctx, email);
      let cookies: string[] = [];
      const started = Date.now();
      const verified = await receiver.magicLink.verify({
        query: { token: delivery.token },
        fetchOptions: {
          headers: persistent ? {} : { cookie: receipt.cookieString() },
          onResponse({ response }) {
            cookies = response.headers.getSetCookie();
          },
        },
      });
      const finished = Date.now();
      expect(verified.error).toBeNull();
      const issued = cookies
        .map((cookie) => Cookie.parse(cookie))
        .find((cookie) => cookie?.key.endsWith("session_token"));
      if (!issued) throw new Error("Magic redemption must issue its authenticated session cookie");
      expect(issued.maxAge !== null && issued.maxAge !== undefined).toBe(persistent);
      expect(issued.expires).toBe("Infinity");
      const user = requireUser(verified.data?.user);
      const state = await readUserState(ctx, user.id);
      expect(state.sessions).toHaveLength(1);
      const session = state.sessions[0]!;
      expect(session.token).toBe(verified.data!.token);
      // Magic-link creates the same seven-day database authority for either cookie policy.
      expect(Date.parse(session.expiresAt) - started).toBeGreaterThanOrEqual(604799000);
      expect(Date.parse(session.expiresAt) - finished).toBeLessThanOrEqual(604800000);
      const current = await receiver.getSession();
      expect(current.data?.user.id).toBe(user.id);
      expect(await verificationCount(ctx, `magic-link:${delivery.token}`)).toBe(0);
      observations.push(
        ctx.snapshot({
          verified,
          current,
          state,
          policy: {
            persistent: issued.maxAge != null,
            expires: issued.expires !== "Infinity",
            httpOnly: issued.httpOnly,
            path: issued.path,
          },
        }),
      );
    }
    expect((await preferenceOwner.client.getSession()).data?.user.id).toBe(
      preference.data!.user.id,
    );
    return { observations };
  },
  ["GET /magic-link/verify", "POST /sign-in/magic-link"],
);
