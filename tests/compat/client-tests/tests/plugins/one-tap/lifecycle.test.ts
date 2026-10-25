import { expect } from "vitest";

import { credential, issuedAt, signedRawToken } from "../../../support/id-token";
import { authProfilePath } from "../../../support/profiles";
import { compatScenario } from "../../../support/scenario";
import { oneTap, responseSchema, state, successful } from "./helpers";

compatScenario(
  "One Tap server API binds verified Google accounts and persisted sessions",
  async (ctx) => {
    const baseline = await state(ctx);
    const email = ctx.uniqueEmail("one-tap-owner");
    const sub = ctx.uniqueToken("google-owner");
    const token = await credential({
      sub,
      email: email.toUpperCase(),
      email_verified: "true",
      name: "Google Owner",
      picture: "https://fixture.test/owner.png",
      nonce: "ignored-google-nonce",
      userId: "untrusted-claim-owner",
    });
    async function invoke(
      actorName: string,
      profile: "one-tap-plugin-only" | "one-tap-no-override",
      idToken: string,
      cookie?: string,
    ) {
      const response = await ctx
        .actor(actorName, profile)
        .client.$fetch<any>("/__test/server-callback", {
          method: "POST",
          body: {
            body: { idToken, callbackURL: "https://outside.example/welcome" },
            ...(cookie ? { headers: { cookie } } : {}),
          },
        });
      expect(response.error).toBeNull();
      return response;
    }
    const malformed = await ctx
      .actor("owner", "one-tap-plugin-only")
      .client.$fetch<any>("/__test/server-callback", {
        method: "POST",
        body: { body: { idToken: 42 } },
      });
    expect(malformed.error).toMatchObject({ status: 400, code: "VALIDATION_ERROR" });
    expect(await state(ctx)).toEqual(baseline);
    const denied = await ctx
      .actor("owner", "one-tap-plugin-only")
      .client.$fetch<any>("/one-tap/callback", {
        method: "POST",
        headers: { origin: ctx.baseURL },
        body: { idToken: token, callbackURL: "https://outside.example/welcome" },
      });
    expect(denied.error).toMatchObject({ status: 403, code: "INVALID_CALLBACK_URL" });
    expect(await state(ctx)).toEqual(baseline);
    const result = await invoke("owner", "one-tap-plugin-only", token);

    const user = result.data!.user;
    expect(user).toMatchObject({
      email,
      name: "Google Owner",
      emailVerified: true,
      image: "https://fixture.test/owner.png",
    });

    const initial = await state(ctx);
    expect(initial.users).toMatchObject([{ id: user.id, email }]);
    expect(initial.accounts).toMatchObject([
      {
        userId: user.id,
        providerId: "google",
        accountId: sub,
        scope: "openid,profile,email",
        idToken: token,
      },
    ]);
    expect(initial.sessions).toMatchObject([{ userId: user.id, token: result.data!.token }]);

    const session = await ctx.actor("owner", "one-tap-plugin-only").client.getSession();
    expect(session.data?.user.id).toBe(user.id);
    expect(session.data?.session.token).toBe(result.data!.token);

    const requestful = await ctx
      .actor("requestful", "one-tap-plugin-only")
      .client.$fetch<any>("/__test/server-callback", {
        method: "POST",
        headers: { origin: ctx.baseURL },
        body: {
          body: { idToken: token, callbackURL: "https://outside.example/welcome" },
          originalRequest: true,
        },
      });
    expect(requestful.error).toBeNull();
    expect(requestful.data!.user.id).toBe(user.id);
    const requestfulState = await state(ctx);
    expect(requestfulState.users).toEqual(initial.users);
    expect(requestfulState.accounts).toEqual(initial.accounts);
    expect(requestfulState.sessions).toHaveLength(2);

    const foreign = ctx.actor("foreign", "one-tap-no-override");
    let foreignCookie = "";
    const other = await foreign.client.signUp.email({
      email: ctx.uniqueEmail("cookie-owner"),
      password: "password123",
      name: "Cookie Owner",
      fetchOptions: {
        onSuccess({ response }) {
          foreignCookie = response.headers
            .getSetCookie()
            .map((raw) => raw.split(";")[0])
            .join("; ");
        },
      },
    });
    expect(other.error).toBeNull();

    const changedEmail = ctx.uniqueEmail("changed-google-email");
    const repeat = await invoke(
      "foreign",
      "one-tap-no-override",
      await credential({
        sub,
        email: changedEmail,
        email_verified: true,
        name: "Provider Replacement",
        picture: "https://fixture.test/new.png",
      }),
      foreignCookie,
    );
    // The profile's Google provider sets overrideUserInfoOnSignIn, which One Tap
    // applies since 1.7.12, so the returning owner is refreshed from the token.
    expect(repeat.data?.user).toMatchObject({
      id: user.id,
      email: changedEmail.toLowerCase(),
      name: "Provider Replacement",
      image: "https://fixture.test/new.png",
    });
    expect(repeat.data?.user.id).not.toBe(other.data?.user.id);

    const bound = await foreign.client.getSession();
    expect(bound.data?.session.userId).toBe(user.id);
    expect(bound.data?.user.id).toBe(user.id);

    const after = await state(ctx);
    expect(after.users).toHaveLength(2);
    expect(after.accounts.filter((row) => row.providerId === "google")).toHaveLength(1);
    expect(after.sessions.filter((row) => row.token === repeat.data?.token)).toMatchObject([
      { userId: user.id },
    ]);
    expect(after.users.find((row) => row.id === other.data?.user.id)).toMatchObject({
      name: "Cookie Owner",
    });

    return {
      result,
      session,
      repeat,
      bound,
      initial: {
        ...initial,
        jwksFetches: initial.jwksFetches - baseline.jwksFetches,
      },
      after: { ...after, jwksFetches: after.jwksFetches - initial.jwksFetches },
    };
  },
  [],
);

compatScenario(
  "One Tap disabled signup preserves existing account ownership",
  async (ctx) => {
    const sub = ctx.uniqueToken("disabled-sub");
    const email = ctx.uniqueEmail("disabled-google");
    const token = await credential({
      sub,
      email,
      email_verified: true,
      name: "Existing Google",
    });
    const initial = await state(ctx);
    const denied = [];

    for (const profile of ["one-tap-disabled", "one-tap-provider-disabled"] as const) {
      const result = responseSchema.parse(await oneTap(ctx, token, profile));
      expect(result.response.error).toMatchObject({
        status: 401,
        message: "signup disabled",
      });
      denied.push(result);
    }

    const unchanged = await state(ctx);
    expect(unchanged.users).toEqual(initial.users);
    expect(unchanged.accounts).toEqual(initial.accounts);
    expect(unchanged.sessions).toEqual(initial.sessions);

    const created = await successful(ctx, token);
    const existing = await successful(ctx, token, "one-tap-disabled");
    expect(existing.response.data?.user.id).toBe(created.response.data?.user.id);

    const persisted = await state(ctx);
    expect(persisted.users).toHaveLength(1);
    expect(persisted.accounts).toHaveLength(1);
    expect(persisted.sessions).toHaveLength(2);

    return {
      denied,
      created,
      existing,
      persisted: {
        ...persisted,
        jwksFetches: persisted.jwksFetches - initial.jwksFetches,
      },
    };
  },
  ["POST /one-tap/callback"],
);

compatScenario(
  "One Tap verifies raw JavaScript payload numbers and literal private keys",
  async (ctx) => {
    const baseline = await state(ctx);
    const email = ctx.uniqueEmail("raw-google");
    const sub = ctx.uniqueToken("raw-google");
    const raw = JSON.stringify({
      iss: "accounts.google.com",
      aud: "one-tap-plugin-client",
      iat: issuedAt,
      exp: 1,
      nbf: -1,
      sub,
      email,
      email_verified: true,
      name: 12,
      picture: false,
      ignored: 1,
      nested: {
        "$serde_json::private::RawValue": "literal raw key",
        "$serde_json::private::Number": "literal number key",
      },
    })
      .replace('"exp":1', '"exp":1e400')
      .replace('"nbf":-1', '"nbf":-1e400')
      .replace('"ignored":1', '"ignored":1e400');
    const token = await credential({}, {}, false, raw);
    const accepted = await successful(ctx, token);
    expect(accepted.response.data?.user).toMatchObject({
      email,
      name: "",
      emailVerified: true,
    });

    const persisted = await state(ctx);
    expect(persisted.accounts).toMatchObject([
      {
        accountId: sub,
        idToken: token,
        userId: accepted.response.data?.user.id,
      },
    ]);
    expect(persisted.sessions).toMatchObject([
      {
        userId: accepted.response.data?.user.id,
        token: accepted.response.data?.token,
      },
    ]);

    return {
      accepted,
      persisted: {
        ...persisted,
        jwksFetches: persisted.jwksFetches - baseline.jwksFetches,
      },
    };
  },
  ["POST /one-tap/callback"],
);

compatScenario(
  "One Tap protected header processing preserves Google JWKS lookup order",
  async (ctx) => {
    const baseline = await state(ctx);
    const outcomes = [];
    const expectedTokens: string[] = [];

    for (const header of [
      { alg: "RS256", kid: false, typ: false },
      { alg: "RS256", kid: 0 },
      { alg: "RS256", kid: "" },
      { alg: "RS256" },
    ]) {
      const sub = ctx.uniqueToken(`header-${outcomes.length}`);
      const email = ctx.uniqueEmail(`header-${outcomes.length}`);
      const token = signedRawToken({ sub, email, email_verified: true }, header);
      outcomes.push(await successful(ctx, token));
      expectedTokens.push(token);
    }

    const persisted = await state(ctx);
    expect(persisted.users).toHaveLength(4);
    expect(persisted.accounts).toHaveLength(4);
    expect(persisted.sessions).toHaveLength(4);
    expect(persisted.jwksFetches - baseline.jwksFetches).toBe(4);
    expect(persisted.accounts.map((row) => row.idToken)).toEqual(expectedTokens);

    return {
      outcomes,
      persisted: {
        ...persisted,
        jwksFetches: persisted.jwksFetches - baseline.jwksFetches,
      },
    };
  },
  ["POST /one-tap/callback"],
);

compatScenario(
  "One Tap builds the user with the Google provider mapping or user info, keyed by the verified sub",
  async (ctx) => {
    const baseline = await state(ctx);
    const mappedSub = ctx.uniqueToken("mapped-google");
    const mappedEmail = ctx.uniqueEmail("mapped-google");
    const mapped = await successful(
      ctx,
      await credential({
        sub: mappedSub,
        email: mappedEmail,
        email_verified: true,
        name: "Source Name",
        picture: "https://fixture.test/source.png",
      }),
      "one-tap-mapped",
    );
    expect(mapped.response.data?.user).toMatchObject({
      email: mappedEmail,
      name: "Mapped Source Name",
      image: "https://fixture.test/mapped.png",
      emailVerified: true,
    });

    const customSub = ctx.uniqueToken("custom-google");
    const customEmail = ctx.uniqueEmail("custom-google");
    const custom = await successful(
      ctx,
      await credential({
        sub: customSub,
        email: customEmail,
        email_verified: true,
        name: "Token Name",
      }),
      "one-tap-custom-userinfo",
    );
    expect(custom.response.data?.user).toMatchObject({
      email: `custom-${customEmail}`,
      name: "From Custom User Info",
      emailVerified: false,
    });

    const persisted = await state(ctx);
    expect(persisted.accounts.slice(baseline.accounts.length)).toMatchObject([
      { providerId: "google", accountId: mappedSub, userId: mapped.response.data?.user.id },
      { providerId: "google", accountId: customSub, userId: custom.response.data?.user.id },
    ]);
    return {
      mapped,
      custom,
      persisted: { ...persisted, jwksFetches: persisted.jwksFetches - baseline.jwksFetches },
    };
  },
  ["POST /one-tap/callback"],
);

compatScenario(
  "One Tap sign-in records google as the last login method",
  async (ctx) => {
    const response = await ctx
      .actor("last-login", "one-tap-last-login")
      .fetch(`${ctx.baseURL}${authProfilePath("one-tap-last-login")}/one-tap/callback`, {
        method: "POST",
        headers: { "content-type": "application/json", origin: ctx.baseURL },
        body: JSON.stringify({
          idToken: await credential({
            sub: ctx.uniqueToken("last-login-google"),
            email: ctx.uniqueEmail("last-login-google"),
            email_verified: true,
            name: "Last Login",
          }),
        }),
      });
    expect(response.status).toBe(200);
    const cookies = response.headers
      .getSetCookie()
      .filter((cookie) => cookie.startsWith("better-auth.last_used_login_method="));
    expect(cookies).toHaveLength(1);
    expect(cookies[0]).toMatch(/^better-auth\.last_used_login_method=google;/);
    return { status: response.status, cookies };
  },
  ["POST /one-tap/callback"],
);
