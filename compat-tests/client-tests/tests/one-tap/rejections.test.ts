import { expect } from "bun:test";
import { compatScenario } from "../../support/scenario";
import {
  credential,
  signedRawToken,
  issuedAt,
  state,
  oneTap,
  responseSchema,
} from "./helpers";
compatScenario(
  "One Tap cryptographic and Google claim rejections leave identities unchanged",
  async (ctx) => {
    const initial = await state(ctx);
    const claims = {
      sub: ctx.uniqueToken("rejection"),
      email: ctx.uniqueEmail("rejection"),
      email_verified: true,
    };
    const tokens = [
      await credential(claims, {}, true),
      await credential(claims, { kid: "unknown-google-key" }),
      await credential({ ...claims, iss: "https://issuer.fixture.test" }),
      await credential({ ...claims, aud: "wrong-google-audience" }),
      await credential({ ...claims, iat: undefined }),
      await credential({ ...claims, iat: issuedAt - 3700 }),
      await credential({ ...claims, iat: issuedAt + 120 }),
      await credential({ ...claims, exp: issuedAt - 1 }),
      await credential({ ...claims, nbf: issuedAt + 120 }),
      await credential({ ...claims, iat: "yesterday" }),
      await credential({ ...claims, exp: null }),
      await credential({ ...claims, sub: "" }),
      await credential({ ...claims, sub: 0 }),
      await credential({ ...claims, sub: false }),
      await credential({ ...claims, sub: { literal: "subject" } }),
      await credential(claims, { crit: ["unknown"], unknown: true }),
      signedRawToken(claims, { alg: "RS256", kid: 123 }),
      signedRawToken(claims, { alg: "RS256", kid: { literal: "key" } }),
      signedRawToken(claims, { alg: "RS256", crit: "not-an-array" }),
    ];
    const good = await credential(claims);
    const parts = good.split(".");
    tokens.push(
      [
        Buffer.from(
          JSON.stringify({ alg: "HS256", kid: "one-tap-local-rs256" }),
        ).toString("base64url"),
        parts[1],
        parts[2],
      ].join("."),
    );
    const rejected = [];
    for (const token of tokens) {
      const result = responseSchema.parse(await oneTap(ctx, token));
      expect(result.response.error).toMatchObject({
        status: 400,
        message: "invalid id token",
      });
      expect(result.location).toBe("/before");
      rejected.push(result);
    }
    for (const email of [undefined, "", false, {}, 123]) {
      const result = responseSchema.parse(
        await oneTap(ctx, await credential({ ...claims, email })),
      );
      expect(result.response.error).toMatchObject({
        status: 400,
        message: "Email not available in token",
      });
      rejected.push(result);
    }
    const raw = JSON.stringify({
      iss: "https://accounts.google.com",
      aud: "one-tap-plugin-client",
      iat: issuedAt,
      exp: issuedAt + 3600,
      sub: 1,
      email: undefined,
    }).replace('"sub":1', '"sub":1e400');
    const priority = responseSchema.parse(
      await oneTap(ctx, await credential({}, {}, false, raw)),
    );
    expect(priority.response.error?.message).toBe(
      "Email not available in token",
    );
    const nonfiniteRaw = JSON.stringify({
      ...claims,
      iss: "https://accounts.google.com",
      aud: "one-tap-plugin-client",
      iat: 1,
      exp: issuedAt + 3600,
    }).replace('"iat":1', '"iat":1e400');
    const nonfinite = responseSchema.parse(
      await oneTap(ctx, await credential({}, {}, false, nonfiniteRaw)),
    );
    expect(nonfinite.response.error?.message).toBe("invalid id token");
    const persisted = await state(ctx);
    expect(persisted.users).toEqual(initial.users);
    expect(persisted.accounts).toEqual(initial.accounts);
    expect(persisted.sessions).toEqual(initial.sessions);
    expect(persisted.jwksFetches - initial.jwksFetches).toBe(tokens.length + 6);
    return {
      rejected,
      priority,
      nonfinite,
      persisted: {
        ...persisted,
        jwksFetches: persisted.jwksFetches - initial.jwksFetches,
      },
    };
  },
);
compatScenario(
  "One Tap callback origin and request validation precede Google JWKS reads",
  async (ctx) => {
    const initial = await state(ctx);
    const token = await credential({
      sub: ctx.uniqueToken("origin"),
      email: ctx.uniqueEmail("origin"),
    });
    const forbidden = responseSchema.parse(
      await oneTap(
        ctx,
        token,
        "one-tap-default",
        "origin",
        "https://foreign.fixture.test/welcome",
      ),
    );
    expect(forbidden.response.error).toMatchObject({
      status: 403,
      code: "INVALID_CALLBACK_URL",
    });
    const rejected = [];
    for (const json of [
      {},
      { idToken: 123 },
      { idToken: token, callbackURL: 123 },
    ]) {
      const result = await ctx.rawRequest({
        path: "/__test/profiles/one-tap-default/api/auth/one-tap/callback",
        method: "POST",
        json,
      });
      expect(result.status).toBe(400);
      rejected.push(result);
    }
    for (const headers of [
      new Headers(),
      new Headers({ "content-type": "text/plain" }),
    ]) {
      const result = await ctx.rawRequest({
        path: "/__test/profiles/one-tap-default/api/auth/one-tap/callback",
        method: "POST",
        body: JSON.stringify({ idToken: token }),
        headers,
      });
      expect(result.status).toBe(415);
      rejected.push(result);
    }
    const persisted = await state(ctx);
    expect(persisted.jwksFetches).toBe(initial.jwksFetches);
    expect(persisted.users).toEqual(initial.users);
    expect(persisted.accounts).toEqual(initial.accounts);
    expect(persisted.sessions).toEqual(initial.sessions);
    return { forbidden, rejected, persisted: { ...persisted, jwksFetches: 0 } };
  },
);
