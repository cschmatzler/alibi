import { expect } from "bun:test";
import { credential, issuedAt, signedRawToken } from "../../support/id-token";
import { compatScenario } from "../../support/scenario";
import { oneTap, responseSchema, state, successful } from "./helpers";

compatScenario(
  "One Tap official client binds verified Google accounts and persisted sessions",
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
    const result = await successful(ctx, token, "one-tap-plugin-only", "owner", "/welcome");
    expect(result.location).toBe("/welcome");
    const user = result.response.data!.user;
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
    expect(initial.sessions).toMatchObject([
      { userId: user.id, token: result.response.data!.token },
    ]);
    const session = await ctx.actor("owner", "one-tap-plugin-only").client.getSession();
    expect(session.data?.user.id).toBe(user.id);
    expect(session.data?.session.token).toBe(result.response.data!.token);
    const foreign = ctx.actor("foreign", "one-tap-no-override");
    const other = await foreign.client.signUp.email({
      email: ctx.uniqueEmail("cookie-owner"),
      password: "password123",
      name: "Cookie Owner",
    });
    expect(other.error).toBeNull();
    const repeat = await successful(
      ctx,
      await credential({
        sub,
        email: ctx.uniqueEmail("changed-google-email"),
        email_verified: true,
        name: "Provider Replacement",
        picture: "https://fixture.test/new.png",
      }),
      "one-tap-no-override",
      "foreign",
    );
    expect(repeat.response.data?.user).toMatchObject({
      id: user.id,
      email,
      name: "Google Owner",
      image: "https://fixture.test/owner.png",
    });
    expect(repeat.response.data?.user.id).not.toBe(other.data?.user.id);
    const bound = await foreign.client.getSession();
    expect(bound.data?.session.userId).toBe(user.id);
    expect(bound.data?.user.id).toBe(user.id);
    const after = await state(ctx);
    expect(after.users).toHaveLength(2);
    expect(after.accounts.filter((row) => row.providerId === "google")).toHaveLength(1);
    expect(after.sessions.filter((row) => row.token === repeat.response.data?.token)).toMatchObject(
      [{ userId: user.id }],
    );
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
  ["POST /one-tap/callback"],
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
