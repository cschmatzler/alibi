import { expect } from "bun:test";

import { createAuthClient } from "better-auth/client";
import { jwtClient } from "better-auth/client/plugins";
import { compactVerify, jwtVerify } from "jose";
import { z } from "zod";

import { authProfilePath, type FixtureProfile } from "../../support/profiles";
import { compatScenario, type ScenarioContext } from "../../support/scenario";

const key = new TextEncoder().encode("remote-jwt-application-secret-minimum-32-characters");

async function control(ctx: ScenarioContext, value: Record<string, unknown>) {
  return ctx.rawRequest({
    path: "/__test/jwt-remote",
    method: "POST",
    json: value,
  });
}

async function receipts(ctx: ScenarioContext) {
  const result = await ctx.rawRequest({ path: "/__test/jwt-remote" });
  expect(result.status).toBe(200);
  return z
    .object({
      events: z.array(
        z
          .object({
            payload: z.record(z.string(), z.unknown()),
            ownKeys: z.array(z.string()),
            header: z.unknown(),
            options: z.record(z.string(), z.unknown()),
          })
          .passthrough(),
      ),
    })
    .parse(result.body);
}

function signer(ctx: ScenarioContext, name: string, profile: FixtureProfile) {
  const actor = ctx.actor(name, profile);
  return {
    fetch: actor.fetch,
    client: createAuthClient({
      baseURL: `${ctx.baseURL}${authProfilePath(profile)}`,
      plugins: [jwtClient()],
      fetchOptions: { customFetchImpl: actor.fetch },
    }),
  };
}

async function signed(result: Awaited<ReturnType<typeof control>>) {
  if (result.status !== 200) {
    throw new Error(JSON.stringify(result));
  }

  expect(result.status).toBe(200);

  const token = z.object({ token: z.string() }).parse(result.body).token;
  const verified = await compactVerify(token, key, { algorithms: ["HS256"] });
  const payload = JSON.parse(new TextDecoder().decode(verified.payload));
  expect(verified.protectedHeader.alg).toBe("HS256");
  expect(verified.protectedHeader.kid).toBe("application-remote-key");

  return { token, header: verified.protectedHeader, payload };
}

const cases = [
  {
    name: "undefined",
    literal: '{"10":"ten","2":"two","custom":{"nested":[null,false,"literal"]}}',
  },
  {
    name: "infinity-exp",
    literal: '{"exp":1e400,"iat":-0,"nbf":false,"sub":0,"jti":false}',
  },
  {
    name: "negative-exp",
    literal: '{"exp":-1e400,"iat":0,"nbf":null,"sub":null,"jti":""}',
  },
  {
    name: "infinity-iat",
    literal: '{"iat":1e400,"nbf":1e400,"sub":1e400,"jti":-1e400}',
  },
  {
    name: "negative-iat",
    literal: '{"iat":-1e400,"nbf":-1e400,"sub":false,"jti":0}',
  },
  {
    name: "nan",
    literal: '{"exp":123,"iat":456,"nbf":789,"sub":10,"jti":11}',
    nanFields: ["exp", "iat", "nbf", "sub", "jti"],
  },
  { name: "nan-default", literal: '{"iat":123}', nanFields: ["iat"] },
  {
    name: "null",
    literal: '{"exp":null,"iat":null,"nbf":null,"iss":null,"aud":null,"sub":null,"jti":null}',
  },
  {
    name: "false",
    literal:
      '{"exp":false,"iat":false,"nbf":false,"iss":false,"aud":false,"sub":false,"jti":false}',
  },
  {
    name: "strings",
    literal:
      '{"exp":"1 hour","iat":"100","nbf":"-5 seconds","iss":"explicit-issuer","aud":["first","second"],"sub":"literal-subject","jti":"literal-jti"}',
  },
  { name: "string-default", literal: '{"iat":"100"}' },
  {
    name: "array-default",
    literal: '{"iat":["7",null,false],"nbf":[],"sub":[],"jti":{}}',
  },
  {
    name: "object-default",
    literal: '{"iat":{"custom":true},"extra":{"overflow":1e400,"zero":-0}}',
  },
];

for (const item of cases) {
  compatScenario(
    `remote JWT application signer ${item.name} preserves raw claims full callback input and independently signed output`,
    async (ctx) => {
      await control(ctx, { operation: "clear" });
      const keysBefore = await ctx.rawRequest({ path: "/__test/jwks-state" });
      expect(keysBefore.body).toEqual([]);

      await control(ctx, { operation: "clear" });
      const response = await ctx.rawRequest({
        path: "/__test/jwt-remote",
        method: "POST",
        headers: { "content-type": "application/json" },
        body: `{"operation":"sign","profile":"jwt-remote-raw","payload":${item.literal},"nanFields":${JSON.stringify(item.nanFields ?? [])},"header":{"typ":"application+jwt","custom":"retained"},"signingKeyId":"application-selected-key","signingAlgorithm":"ES256"}`,
      });
      const verified = await signed(response);
      const captured = await receipts(ctx);
      expect(captured.events).toHaveLength(1);

      const event = captured.events[0]!;
      expect(event.header).toEqual({
        typ: "application+jwt",
        custom: "retained",
      });
      expect(event.options).toEqual({
        signingKeyId: "application-selected-key",
        signingAlgorithm: "ES256",
      });
      expect(event.ownKeys).toEqual(Object.keys(event.payload));

      if (item.name === "undefined") {
        expect(event.payload).toMatchObject({ "2": "two", "10": "ten" });
        expect(verified.payload).toMatchObject({ "2": "two", "10": "ten" });
        expect(event.payload.iat).toEqual({ $undefined: true });
        expect(event.payload.nbf).toEqual({ $undefined: true });
        expect(event.ownKeys).toEqual(["2", "10", "custom", "iat", "exp", "nbf", "iss", "aud"]);
        expect(verified.payload).not.toHaveProperty("iat");
        expect(verified.payload).not.toHaveProperty("nbf");
      }

      if (item.name === "infinity-exp") {
        expect(event.payload.exp).toEqual({ $number: "Infinity" });
        expect(event.payload.iat).toEqual({ $number: "-0" });
        expect(event.payload).toMatchObject({ nbf: false, sub: 0, jti: false });
        expect(verified.payload).toMatchObject({
          exp: null,
          iat: 0,
          nbf: false,
          sub: 0,
          jti: false,
        });
      }

      if (item.name === "nan") {
        for (const field of item.nanFields!) {
          expect(event.payload[field]).toEqual({ $number: "NaN" });
          expect(verified.payload[field]).toBeNull();
        }
      }

      if (item.name === "infinity-iat") {
        expect(event.payload.exp).toEqual({ $number: "Infinity" });
      }

      if (item.name === "nan-default") {
        expect(event.payload.exp).toEqual({ $number: "NaN" });
      }

      if (item.name === "false") {
        expect(event.payload).toMatchObject({
          exp: false,
          iat: false,
          nbf: false,
          iss: false,
          aud: false,
          sub: false,
          jti: false,
        });
      }

      if (item.name === "string-default") {
        expect(event.payload.exp).toBe("100900");
      }

      if (item.name === "array-default") {
        expect(event.payload.exp).toBe("7,,false900");
      }

      if (item.name === "object-default") {
        expect(event.payload.exp).toBe("[object Object]900");
      }

      const after = await ctx.rawRequest({ path: "/__test/jwks-state" });
      expect(after.body).toEqual(keysBefore.body);

      return ctx.snapshot({
        name: item.name,
        response,
        verified,
        captured,
        keysBefore,
        after,
      });
    },
  );
}

compatScenario(
  "remote JWT configured defaults preserve custom results and application exceptions without local key creation",
  async (ctx) => {
    await control(ctx, { operation: "clear" });
    const keysBefore = await ctx.rawRequest({ path: "/__test/jwks-state" });
    expect(keysBefore.body).toEqual([]);

    await control(ctx, { operation: "clear" });
    const configured = await signed(
      await control(ctx, {
        operation: "sign",
        profile: "jwt-remote-configured",
        payload: { iat: 100 },
      }),
    );
    expect(configured.payload).toMatchObject({
      iat: 100,
      exp: 160,
      iss: "application-issuer",
      aud: ["application-audience", "alternate-audience"],
    });

    const configuredReceipt = await receipts(ctx);
    const preserved = await control(ctx, {
      operation: "sign",
      profile: "jwt-remote-result",
      payload: { customResult: "application-owned result: exact % bytes" },
    });
    expect(preserved.status).toBe(200);
    expect(preserved.body).toEqual({
      token: "application-owned result: exact % bytes",
    });

    const ordinary = await control(ctx, {
      operation: "sign",
      profile: "jwt-remote-error",
      payload: { applicationError: "ordinary" },
    });
    expect(ordinary.status).toBe(500);
    expect(ordinary.body).toEqual({
      error: { message: "application signer failed" },
    });

    const coded = await control(ctx, {
      operation: "sign",
      profile: "jwt-remote-error",
      payload: { applicationError: "api" },
    });
    expect(coded.status).toBe(403);
    expect(coded.body).toEqual({
      error: {
        status: 403,
        body: {
          code: "APPLICATION_SIGNING_DENIED",
          message: "application denied signing",
        },
      },
    });

    const after = await ctx.rawRequest({ path: "/__test/jwks-state" });
    expect(after.body).toEqual(keysBefore.body);

    return ctx.snapshot({
      configured,
      configuredReceipt,
      preserved,
      ordinary,
      coded,
      after,
      finalReceipts: await receipts(ctx),
    });
  },
);

compatScenario(
  "remote JWT authentication signing retains authoritative owner issuer audience revocation and callback failures",
  async (ctx) => {
    await control(ctx, { operation: "clear" });
    const profile: FixtureProfile = "jwt-remote-error";
    const owner = signer(ctx, "owner", profile);
    const foreign = signer(ctx, "foreign", profile);
    const guest = signer(ctx, "guest", profile);
    const signup = await owner.client.signUp.email({
      email: ctx.uniqueEmail("remote-owner"),
      password: "password123",
      name: "Remote Owner",
    });
    expect(signup.error).toBeNull();

    const other = await foreign.client.signUp.email({
      email: ctx.uniqueEmail("remote-foreign"),
      password: "password123",
      name: "Foreign Owner",
    });
    expect(other.error).toBeNull();

    const ownerBefore = await ctx.readUserState({
      userId: signup.data!.user.id,
    });
    const foreignBefore = await ctx.readUserState({ userId: other.data!.user.id });
    await control(ctx, { operation: "clear" });
    const denied = await guest.client.token();
    expect(denied.error?.status).toBe(401);
    expect((await receipts(ctx)).events).toHaveLength(0);

    const result = await owner.client.token();
    expect(result.error).toBeNull();

    const token = z.object({ token: z.string() }).parse(result.data).token;
    const verified = await jwtVerify(token, key, {
      algorithms: ["HS256"],
      issuer: ctx.baseURL,
      audience: ctx.baseURL,
      subject: signup.data!.user.id,
    });
    expect(verified.payload.sub).toBe(signup.data!.user.id);
    expect(verified.payload.email).toBe(signup.data!.user.email);

    let wrongAudience = false;

    try {
      await jwtVerify(token, key, {
        issuer: ctx.baseURL,
        audience: "foreign-audience",
      });
    } catch {
      wrongAudience = true;
    }

    expect(wrongAudience).toBe(true);

    const original = await receipts(ctx);
    expect(original.events).toHaveLength(1);
    expect(original.events[0]!.payload.sub).toBe(signup.data!.user.id);

    const failures = [];

    for (const failure of ["ordinary", "api"]) {
      await control(ctx, { operation: "failure", failure });
      const rejected = await owner.client.token();
      expect(rejected.error?.status).toBe(failure === "ordinary" ? 500 : 403);
      expect(await ctx.readUserState({ userId: signup.data!.user.id })).toEqual(ownerBefore);
      expect(await ctx.readUserState({ userId: other.data!.user.id })).toEqual(foreignBefore);

      failures.push({ failure, rejected, receipts: await receipts(ctx) });
    }

    await control(ctx, { operation: "failure", failure: null });
    const signout = await owner.client.signOut();
    expect(signout.error).toBeNull();

    const beforeReplay = await receipts(ctx);
    const replay = await owner.client.token();
    expect(replay.error?.status).toBe(401);
    expect(await receipts(ctx)).toEqual(beforeReplay);
    expect(await ctx.readUserState({ userId: other.data!.user.id })).toEqual(foreignBefore);
    expect(
      z
        .object({ sessions: z.array(z.unknown()).length(0) })
        .passthrough()
        .parse(await ctx.readUserState({ userId: signup.data!.user.id })),
    ).toBeDefined();
    expect((await ctx.rawRequest({ path: "/__test/jwks-state" })).body).toEqual([]);

    return ctx.snapshot({
      signup,
      other,
      ownerBefore,
      foreignBefore,
      denied,
      result,
      verified: { header: verified.protectedHeader, payload: verified.payload },
      wrongAudience,
      original,
      failures,
      signout,
      replay,
      finalReceipts: await receipts(ctx),
      ownerAfter: await ctx.readUserState({ userId: signup.data!.user.id }),
      foreignAfter: await ctx.readUserState({ userId: other.data!.user.id }),
    });
  },
  ["POST /sign-up/email", "GET /token", "POST /sign-out"],
);
