import { expect } from "bun:test";

import { decodeJwt } from "jose";
import { z } from "zod";

import { compatScenario } from "../../../support/scenario";
import { jwtActor, verifyWithOfficialJose } from "./helpers";

const storedKeySchema = z.array(
  z.object({
    id: z.string(),
    publicKey: z.record(z.string(), z.unknown()),
    privateKeyEncrypted: z.boolean(),
    createdAt: z.string(),
    expiresAt: z.string().nullable(),
    alg: z.string(),
    crv: z.string().nullable(),
  }),
);

async function advancePastJwtSecond(issuedAt: number): Promise<void> {
  // EdDSA signs identical claims deterministically. Exercise real issuance
  // across explicit clock transitions so repeated-token identity cannot depend
  // on one runtime happening to cross a second boundary first.
  while (Math.floor(Date.now() / 1000) <= issuedAt) {
    await Bun.sleep(Math.max(1, (issuedAt + 1) * 1000 - Date.now()));
  }
}

compatScenario(
  "JWT default JWKS token and get-session header carry the complete authenticated user",
  async (ctx) => {
    const client = jwtActor(ctx);
    const anonymousToken = await jwtActor(ctx, "guest").token();
    expect(anonymousToken.error).toMatchObject({ status: 401, code: "UNAUTHORIZED" });

    const jwksBefore = await client.jwks();
    expect(jwksBefore.error).toBeNull();

    if (!jwksBefore.data) {
      throw new Error("public JWKS must be available without a session");
    }

    expect(jwksBefore.data.keys).toHaveLength(1);
    expect(jwksBefore.data.keys[0]).toMatchObject({ alg: "EdDSA", kty: "OKP", crv: "Ed25519" });

    const persisted = await ctx.rawRequest({ path: "/__test/jwks-state" });
    const persistedKeys = storedKeySchema.parse(persisted.body);
    expect(persistedKeys).toHaveLength(1);
    expect(persistedKeys[0]?.privateKeyEncrypted).toBeTrue();
    expect(persistedKeys[0]?.expiresAt).toBeNull();
    expect(persistedKeys[0]?.id).toBe(jwksBefore.data.keys[0]?.kid);
    expect(persistedKeys[0]?.publicKey.x).toBe(jwksBefore.data.keys[0]?.x);

    const signupCookie: { value: string | null } = { value: null };
    const signup = await client.signUp.email({
      email: ctx.uniqueEmail("jwt-default"),
      password: "password123",
      name: "JWT Owner",
      fetchOptions: {
        onSuccess({ response }) {
          signupCookie.value =
            response.headers
              .getSetCookie()
              .find((cookie) => cookie.startsWith("better-auth.session_token="))
              ?.split(";")[0] ?? null;
        },
      },
    });
    expect(signup.error).toBeNull();

    if (!signupCookie.value || !signup.data?.token) {
      throw new Error("signup must issue a signed persistent session cookie");
    }

    const invalidCookie = "better-auth.session_token=invalid";
    const cookieAuthorizations = [];
    let cookieTokenIssuedAt: number | undefined;

    for (const [name, headers, successful] of [
      ["valid-first", { cookie: `${signupCookie.value}; ${invalidCookie}` }, true],
      ["invalid-first", { cookie: `${invalidCookie}; ${signupCookie.value}` }, false],
      ["unsigned", { cookie: `better-auth.session_token=${signup.data.token}` }, false],
      ["bare-bearer", { authorization: `Bearer ${signup.data.token}` }, false],
    ] as const) {
      const result = await jwtActor(ctx, `cookie-${name}`).token({ fetchOptions: { headers } });
      if (successful) {
        expect(result.error).toBeNull();

        if (!result.data) {
          throw new Error("first valid signed cookie must authorize issuance");
        }

        const checked = await verifyWithOfficialJose(
          result.data.token,
          jwksBefore.data.keys,
          ctx.baseURL,
          ctx.baseURL,
        );
        expect(checked.payload.sub).toBe(signup.data.user.id);

        cookieTokenIssuedAt = z.number().parse(checked.payload.iat);
      } else {
        expect(result.error).toMatchObject({ status: 401, code: "UNAUTHORIZED" });
      }
      cookieAuthorizations.push({ name, result });
    }

    if (cookieTokenIssuedAt === undefined) {
      throw new Error("valid cookie must issue a timestamped JWT");
    }

    await advancePastJwtSecond(cookieTokenIssuedAt);
    const responseHeaders: { token: string | null; exposed: string | null } = {
      token: null,
      exposed: null,
    };
    const session = await client.getSession({
      fetchOptions: {
        onSuccess({ response }) {
          responseHeaders.token = response.headers.get("set-auth-jwt");
          responseHeaders.exposed = response.headers.get("access-control-expose-headers");
        },
      },
    });
    expect(session.error).toBeNull();

    const { token: headerToken, exposed: exposedHeaders } = responseHeaders;

    if (!session.data || !headerToken) {
      throw new Error("authenticated get-session must set a JWT header");
    }

    expect(exposedHeaders?.split(",").map((value) => value.trim())).toContain("set-auth-jwt");

    const verifiedHeader = await verifyWithOfficialJose(
      headerToken,
      jwksBefore.data.keys,
      ctx.baseURL,
      ctx.baseURL,
    );
    const headerIssuedAt = z.number().parse(verifiedHeader.payload.iat);
    expect(headerIssuedAt).toBeGreaterThan(cookieTokenIssuedAt);

    await advancePastJwtSecond(headerIssuedAt);
    const issuedAt = Math.floor(Date.now() / 1000);
    const token = await client.token();
    expect(token.error).toBeNull();

    if (!token.data) {
      throw new Error("JWT endpoint must issue a signed token");
    }

    const verified = await verifyWithOfficialJose(
      token.data.token,
      jwksBefore.data.keys,
      ctx.baseURL,
      ctx.baseURL,
    );
    expect(token.data.token).not.toBe(headerToken);
    expect(verified.header.alg).toBe("EdDSA");
    expect(verified.header.typ).toBeUndefined();
    expect(verified.payload.sub).toBe(session.data.user.id);
    expect(verified.payload.iat).toBeGreaterThanOrEqual(issuedAt);
    expect(verified.payload.iat).toBeGreaterThan(headerIssuedAt);
    expect(verified.payload.exp).toBe((verified.payload.iat ?? 0) + 900);

    const userClaims = { ...verified.payload };

    for (const key of ["iat", "exp", "iss", "aud", "sub"]) {
      delete userClaims[key];
    }

    expect(userClaims).toEqual(
      z.record(z.string(), z.unknown()).parse(ctx.snapshot(session.data.user)),
    );
    expect(verifiedHeader.payload.sub).toBe(session.data.user.id);

    const again = await client.jwks();
    expect(again.data).toEqual(jwksBefore.data);

    const serverVerified = await ctx.rawRequest({
      path: "/__test/jwt",
      method: "POST",
      json: { operation: "verify", profile: "jwt-default", token: token.data.token },
    });
    expect(serverVerified.status).toBe(200);
    expect(
      z.object({ payload: z.record(z.string(), z.unknown()) }).parse(serverVerified.body).payload,
    ).toEqual(verified.payload);

    return {
      anonymousToken: ctx.snapshot(anonymousToken),
      jwksBefore,
      persisted,
      cookieAuthorizations,
      signup: ctx.snapshot(signup),
      session: ctx.snapshot(session),
      token,
      verified,
      headerToken,
      verifiedHeader,
      exposedHeaders,
      again,
      serverVerified,
    };
  },
  ["GET /jwks", "GET /token"],
);

for (const [profile, algorithm, keyType, curve] of [
  ["jwt-es256", "ES256", "EC", "P-256"],
  ["jwt-es512", "ES512", "EC", "P-521"],
  ["jwt-rs256", "RS256", "RSA", undefined],
  ["jwt-ps256", "PS256", "RSA", undefined],
] as const) {
  compatScenario(
    `JWT ${algorithm} configuration produces official JOSE-verifiable signatures`,
    async (ctx) => {
      const client = jwtActor(ctx, "owner", profile);
      const publicKeys = await client.jwks();
      expect(publicKeys.error).toBeNull();

      if (!publicKeys.data) {
        throw new Error("configured JWKS must be public");
      }

      expect(publicKeys.data.keys).toHaveLength(1);
      expect(publicKeys.data.keys[0]?.alg).toBe(algorithm);
      expect(publicKeys.data.keys[0]?.kty).toBe(keyType);
      expect(publicKeys.data.keys[0]?.crv).toBe(curve);

      const signup = await client.signUp.email({
        email: ctx.uniqueEmail(`jwt-${algorithm}`),
        password: "password123",
        name: `JWT ${algorithm} Owner`,
      });
      expect(signup.error).toBeNull();

      const token = await client.token();
      expect(token.error).toBeNull();

      if (!token.data) {
        throw new Error("configured signer must issue JWT");
      }

      const verified = await verifyWithOfficialJose(
        token.data.token,
        publicKeys.data.keys,
        ctx.baseURL,
        ctx.baseURL,
      );
      expect(verified.header.alg).toBe(algorithm);
      expect(verified.payload.sub).toBe(signup.data?.user.id);

      const serverVerified = await ctx.rawRequest({
        path: "/__test/jwt",
        method: "POST",
        json: { operation: "verify", profile, token: token.data.token },
      });
      expect(
        z.object({ payload: z.record(z.string(), z.unknown()) }).parse(serverVerified.body).payload,
      ).toEqual(verified.payload);

      const signatures = [];

      for (let index = 0; index < 2; index++) {
        const signed = await ctx.rawRequest({
          path: "/__test/jwt",
          method: "POST",
          json: {
            operation: "sign",
            profile,
            payload: { sub: "fixed-service", iat: 100, exp: 4102444800 },
          },
        });
        expect(signed.status).toBe(200);
        signatures.push(z.object({ token: z.string() }).parse(signed.body));
      }

      if (!signatures[0] || !signatures[1]) {
        throw new Error("two signatures are required");
      }

      const first = await verifyWithOfficialJose(
        signatures[0].token,
        publicKeys.data.keys,
        ctx.baseURL,
        ctx.baseURL,
      );
      const second = await verifyWithOfficialJose(
        signatures[1].token,
        publicKeys.data.keys,
        ctx.baseURL,
        ctx.baseURL,
      );
      expect(first).toEqual(second);

      if (algorithm === "RS256") {
        expect(signatures[0].token).toBe(signatures[1].token);
      } else {
        expect(signatures[0].token).not.toBe(signatures[1].token);
      }

      return {
        publicKeys,
        signup: ctx.snapshot(signup),
        token,
        verified,
        serverVerified,
        signatures,
        first,
        second,
      };
    },
    ["GET /jwks", "GET /token"],
  );
}

compatScenario(
  "JWT trusted server operations preserve explicit claims and reject invalid signatures or claims",
  async (ctx) => {
    const sign = async (payload: Record<string, unknown>) => {
      const response = await ctx.rawRequest({
        path: "/__test/jwt",
        method: "POST",
        json: { operation: "sign", profile: "jwt-default", payload },
      });
      expect(response.status).toBe(200);
      return z.object({ token: z.string() }).parse(response.body);
    };
    const verify = (token: string, issuer?: string) =>
      ctx.rawRequest({
        path: "/__test/jwt",
        method: "POST",
        json: {
          operation: "verify",
          profile: "jwt-default",
          token,
          ...(issuer === undefined ? {} : { issuer }),
        },
      });
    const explicit = await sign({
      sub: "server-subject",
      iat: 100,
      exp: 4102444800,
      custom: ["a", "b"],
    });
    const checked = await verify(explicit.token);
    expect(checked.status).toBe(200);
    expect(
      z.object({ payload: z.record(z.string(), z.unknown()) }).parse(checked.body).payload,
    ).toEqual({
      sub: "server-subject",
      iat: 100,
      exp: 4102444800,
      custom: ["a", "b"],
      iss: ctx.baseURL,
      aud: ctx.baseURL,
    });

    const emptyIssuer = await verify(explicit.token, "");
    expect(emptyIssuer).toEqual(checked);

    const nullish = await sign({
      sub: "server-subject",
      iat: 4102443800.5,
      exp: null,
      iss: null,
      aud: null,
    });
    const nullishChecked = await verify(nullish.token);
    expect(
      z.object({ payload: z.record(z.string(), z.unknown()) }).parse(nullishChecked.body).payload,
    ).toEqual({
      sub: "server-subject",
      iat: 4102443800.5,
      exp: 4102444700.5,
      iss: ctx.baseURL,
      aud: ctx.baseURL,
    });

    const noIat = await sign({ sub: "server-subject" });
    const noIatChecked = await verify(noIat.token);
    expect(
      z.object({ payload: z.record(z.string(), z.unknown()) }).parse(noIatChecked.body).payload,
    ).not.toHaveProperty("iat");

    const falseIat = await sign({ sub: "server-subject", iat: false });
    const falseIatClaims = z.record(z.string(), z.unknown()).parse(decodeJwt(falseIat.token));
    expect(falseIatClaims).toEqual({
      sub: "server-subject",
      iat: false,
      exp: 900,
      iss: ctx.baseURL,
      aud: ctx.baseURL,
    });

    const falseIatRejected = await verify(falseIat.token);
    expect(falseIatRejected).toMatchObject({ status: 200, body: { payload: null } });

    const relativeStartedAt = Math.floor(Date.now() / 1000);
    const relative = await sign({ sub: "server-subject", exp: "1m" });
    const relativeCompletedAt = Math.floor(Date.now() / 1000);
    const relativeChecked = await verify(relative.token);
    const relativeClaims = z
      .object({ payload: z.object({ exp: z.number(), sub: z.literal("server-subject") }) })
      .parse(relativeChecked.body);
    expect(relativeClaims.payload.exp).toBeGreaterThanOrEqual(relativeStartedAt + 60);
    expect(relativeClaims.payload.exp).toBeLessThanOrEqual(relativeCompletedAt + 60);

    const invalidClaims = [];

    for (const payload of [
      { sub: "server-subject", exp: "invalid" },
      { sub: "server-subject", exp: false },
      { sub: 123 },
      { sub: "server-subject", jti: 123 },
      { sub: "server-subject", aud: [ctx.baseURL, 123] },
      { sub: "server-subject", iat: "1m" },
      { sub: "server-subject", iat: "" },
    ]) {
      const response = await ctx.rawRequest({
        path: "/__test/jwt",
        method: "POST",
        json: { operation: "sign", profile: "jwt-default", payload },
      });
      expect(response).toEqual({
        status: 500,
        location: null,
        body: { message: "Internal server error" },
      });
      invalidClaims.push(response);
    }

    const rejected = [];

    for (const claims of [
      { iss: "wrong" },
      { aud: "wrong" },
      { exp: 0 },
      { sub: "" },
      { nbf: 4102444800 },
    ]) {
      const signed = await sign({ sub: "server-subject", ...claims });
      const result = await verify(signed.token);
      expect(result).toMatchObject({ status: 200, body: { payload: null } });

      rejected.push({ signed, result });
    }

    const parts = explicit.token.split(".");

    if (!parts[0] || !parts[1] || !parts[2]) {
      throw new Error("compact JWT must contain three nonempty segments");
    }

    const signature = parts[2];
    const signatureEncodings = [];
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    const lastIndex = alphabet.indexOf(signature.at(-1) ?? "");

    for (const [label, encoded, accepted] of [
      ["proper padding", `${signature}==`, true],
      ["wrong padding", `${signature}=`, false],
      ["unused trailing bits", `${signature.slice(0, -1)}${alphabet[lastIndex + 1]}`, true],
      ["ASCII whitespace", `${signature.slice(0, 20)} \t\n\r\f${signature.slice(20)}== `, true],
      ["ordinary alphabet", `+${signature.slice(1)}`, false],
      ["vertical tab", `${signature}\v`, false],
      ["nonbreaking space", `${signature}\u00a0`, false],
    ] as const) {
      const token = `${parts[0]}.${parts[1]}.${encoded}`;
      const result = await verify(token);
      expect(result.status).toBe(200);
      expect(result.body).toEqual(accepted ? checked.body : { payload: null });

      signatureEncodings.push({ label, token, result });
    }

    const badSignature = `${parts[0]}.${parts[1]}.${Buffer.from("not-a-signature").toString("base64url")}`;
    const signatureRejected = await verify(badSignature);
    expect(signatureRejected).toMatchObject({ status: 200, body: { payload: null } });

    const issuerRejected = await verify(explicit.token, "different-issuer");
    expect(issuerRejected).toMatchObject({ status: 200, body: { payload: null } });

    const notPublic = [];

    for (const path of ["/sign-jwt", "/verify-jwt", "/jwt/sign", "/jwt/verify"]) {
      const response = await ctx
        .actor("public", "jwt-default")
        .fetch(`${ctx.baseURL}/api/auth${path}`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ payload: { sub: "server-subject" }, token: explicit.token }),
        });
      expect(response.status).toBe(404);

      const responseText = await response.text();
      const body: unknown = responseText.length ? JSON.parse(responseText) : null;
      notPublic.push({ status: response.status, body });
    }

    return {
      explicit,
      checked,
      emptyIssuer,
      nullish,
      nullishChecked,
      noIat,
      noIatChecked,
      falseIat,
      falseIatClaims,
      falseIatRejected,
      relative,
      relativeChecked,
      invalidClaims,
      rejected,
      signatureEncodings,
      signatureRejected,
      issuerRejected,
      notPublic,
    };
  },
  [],
  30_000,
  {
    oracle: {
      unroutedRequests: "asserts the server-only sign/verify operations are not exposed over HTTP",
      collapsedFixtureErrors:
        "the trusted signing control reports rejected claims as a generic 500",
    },
  },
);

compatScenario(
  "JWT configured issuer audience lifetime and path header branches remain observable",
  async (ctx) => {
    const claimsClient = jwtActor(ctx, "claims", "jwt-claims");
    const signup = await claimsClient.signUp.email({
      email: ctx.uniqueEmail("jwt-claims"),
      password: "password123",
      name: "Claims Owner",
    });
    const publicKeys = await claimsClient.jwks();
    const token = await claimsClient.token();

    if (!publicKeys.data || !token.data) {
      throw new Error("configured JWT must be issued");
    }

    const verified = await verifyWithOfficialJose(
      token.data.token,
      publicKeys.data.keys,
      "fixture-issuer",
      "fixture-audience",
    );
    expect(verified.payload.exp).toBe((verified.payload.iat ?? 0) + 60);

    const serverVerified = await ctx.rawRequest({
      path: "/__test/jwt",
      method: "POST",
      json: { operation: "verify", profile: "jwt-claims", token: token.data.token },
    });
    expect(
      z.object({ payload: z.record(z.string(), z.unknown()) }).parse(serverVerified.body).payload,
    ).toEqual(verified.payload);

    const alternate = jwtActor(ctx, "path", "jwt-path-header", "/.well-known/jwks.json");
    const alternateKeys = await alternate.jwks();
    expect(alternateKeys.error).toBeNull();

    const oldPath = await ctx
      .actor("path", "jwt-path-header")
      .fetch(`${ctx.baseURL}/api/auth/jwks`);
    expect(oldPath.status).toBe(404);

    await alternate.signUp.email({
      email: ctx.uniqueEmail("jwt-path"),
      password: "password123",
      name: "Path Owner",
    });
    let authHeader: string | null = "unset";
    const session = await alternate.getSession({
      fetchOptions: {
        onSuccess({ response }) {
          authHeader = response.headers.get("set-auth-jwt");
        },
      },
    });
    expect(authHeader).toBeNull();

    return {
      signup: ctx.snapshot(signup),
      publicKeys,
      token,
      verified,
      serverVerified,
      alternateKeys,
      oldPathStatus: oldPath.status,
      session: ctx.snapshot(session),
      authHeader,
    };
  },
  [],
  30_000,
  {
    oracle: {
      unroutedRequests: "asserts the default JWKS path is gone once a custom path is configured",
    },
  },
);

compatScenario(
  "JWT rotation persists replacement keys and retains expired public keys only through grace",
  async (ctx) => {
    const profile = "jwt-plain-rotation";
    const client = jwtActor(ctx, "owner", profile);
    const startedAt = Date.now();
    const originalKeys = await client.jwks();
    const completedAt = Date.now();

    if (!originalKeys.data?.keys[0]?.kid) {
      throw new Error("rotation requires a persisted signing key");
    }

    const originalKid = originalKeys.data.keys[0].kid;
    const persistedBefore = await ctx.rawRequest({ path: "/__test/jwks-state" });
    const before = storedKeySchema.parse(persistedBefore.body);
    expect(before).toHaveLength(1);
    expect(before[0]?.privateKeyEncrypted).toBeFalse();

    if (!before[0]?.expiresAt) {
      throw new Error("rotation interval must persist a key expiry");
    }

    expect(new Date(before[0].expiresAt).getTime()).toBeGreaterThanOrEqual(startedAt + 3600000);
    expect(new Date(before[0].expiresAt).getTime()).toBeLessThanOrEqual(completedAt + 3600000);

    const signup = await client.signUp.email({
      email: ctx.uniqueEmail("jwt-rotation"),
      password: "password123",
      name: "Rotation Owner",
    });
    const originalToken = await client.token();

    if (!originalToken.data) {
      throw new Error("rotation requires an issued original token");
    }

    const originalVerified = await verifyWithOfficialJose(
      originalToken.data.token,
      originalKeys.data.keys,
      ctx.baseURL,
      ctx.baseURL,
    );
    expect(originalVerified.header.kid).toBe(originalKid);

    const expire = await ctx.rawRequest({
      path: "/__test/expire-jwk",
      method: "POST",
      json: { id: originalKid, expiresAt: new Date(Date.now() - 1000).toISOString() },
    });
    expect(expire.status).toBe(200);

    const replacementToken = await client.token();

    if (!replacementToken.data) {
      throw new Error("expired unpinned key must be replaced");
    }

    const replacementKeys = await client.jwks();

    if (!replacementKeys.data) {
      throw new Error("replacement JWKS must be available");
    }

    expect(replacementKeys.data.keys).toHaveLength(2);
    expect(replacementKeys.data.keys[0]?.kid).toBe(originalKid);

    const replacementVerified = await verifyWithOfficialJose(
      replacementToken.data.token,
      replacementKeys.data.keys,
      ctx.baseURL,
      ctx.baseURL,
    );
    expect(replacementVerified.header.kid).not.toBe(originalKid);

    const persistedAfter = await ctx.rawRequest({ path: "/__test/jwks-state" });
    const after = storedKeySchema.parse(persistedAfter.body);
    expect(after).toHaveLength(2);
    expect(after.map((key) => key.privateKeyEncrypted)).toEqual([false, false]);
    expect(after[0]?.publicKey).toEqual(before[0]?.publicKey);
    expect(after[1]?.id).toBe(replacementVerified.header.kid);

    const oldStillVerifies = await ctx.rawRequest({
      path: "/__test/jwt",
      method: "POST",
      json: { operation: "verify", profile, token: originalToken.data.token },
    });
    expect(
      z.object({ payload: z.record(z.string(), z.unknown()) }).parse(oldStillVerifies.body).payload
        .sub,
    ).toBe(signup.data?.user.id);

    const removeFromPublic = await ctx.rawRequest({
      path: "/__test/expire-jwk",
      method: "POST",
      json: { id: originalKid, expiresAt: new Date(Date.now() - 7200000).toISOString() },
    });
    expect(removeFromPublic.status).toBe(200);

    const afterGrace = await client.jwks();
    expect(afterGrace.data?.keys).toHaveLength(1);
    expect(afterGrace.data?.keys[0]?.kid).toBe(replacementVerified.header.kid);

    // Public retention and server verification intentionally have separate
    // lifecycles: the pinned verifier reads all persisted keys.
    const oldAfterGrace = await ctx.rawRequest({
      path: "/__test/jwt",
      method: "POST",
      json: { operation: "verify", profile, token: originalToken.data.token },
    });
    expect(
      z.object({ payload: z.record(z.string(), z.unknown()) }).parse(oldAfterGrace.body).payload
        .sub,
    ).toBe(signup.data?.user.id);

    return {
      originalKeys,
      persistedBefore,
      signup: ctx.snapshot(signup),
      originalToken,
      originalVerified,
      expire,
      replacementToken,
      replacementKeys,
      replacementVerified,
      persistedAfter,
      oldStillVerifies,
      removeFromPublic,
      afterGrace,
      oldAfterGrace,
    };
  },
  ["GET /jwks", "GET /token"],
);
