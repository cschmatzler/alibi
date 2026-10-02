import { expect } from "bun:test";

import { importJWK, type JWK, jwtVerify } from "jose";
import { z } from "zod";

import { compatScenario } from "../../../support/scenario";

compatScenario(
  "trusted JWT signing normalizes JavaScript numbers and rejects nonfinite registered claims",
  async (ctx) => {
    const before = await ctx.rawRequest({ path: "/__test/jwks-state" });
    expect(before.body).toEqual([]);

    const rejections = [];

    for (const [field, literal] of [
      ["exp", "1e400"],
      ["exp", "-1e400"],
      ["iat", "1e400"],
      ["iat", "-1e400"],
      ["nbf", "1e400"],
      ["nbf", "-1e400"],
      ["sub", "1e400"],
      ["jti", "-1e400"],
      ["iss", "1e400"],
    ]) {
      const response = await ctx.rawRequest({
        path: "/__test/jwt",
        method: "POST",
        headers: { "content-type": "application/json" },
        body: `{"operation":"sign","profile":"jwt-default","payload":{"exp":4102444800,"${field}":${literal}}}`,
      });
      expect(response.status).toBe(500);
      expect(response.body).toEqual({ message: "Internal server error" });

      rejections.push(response);
    }

    const created = await ctx.rawRequest({ path: "/__test/jwks-state" });
    const keys = z
      .array(z.object({ id: z.string(), privateKeyEncrypted: z.literal(true) }).passthrough())
      .parse(created.body);
    expect(keys).toHaveLength(1);

    const issued = await ctx.rawRequest({
      path: "/__test/jwt",
      method: "POST",
      headers: { "content-type": "application/json" },
      body: '{"operation":"sign","profile":"jwt-default","payload":{"sub":"9007199254740993","exp":4102444800,"rounded":9007199254740993,"overflow":1e400,"nested":[-0.0,-1e400],"literal":{"$serde_json::private::Number":"1e400","$serde_json::private::RawValue":"hello"},"singleton":{"$serde_json::private::RawValue":"hello"}}}',
    });
    expect(issued.status).toBe(200);

    const token = z.object({ token: z.string() }).parse(issued.body).token;
    const payloadText = Buffer.from(token.split(".")[1]!, "base64url").toString();
    expect(payloadText).toContain('"rounded":9007199254740992');
    expect(payloadText).toContain('"overflow":null');
    expect(payloadText).toContain('"nested":[0,null]');

    const signed = z.record(z.string(), z.unknown()).parse(JSON.parse(payloadText));
    expect(signed).toMatchObject({
      sub: "9007199254740993",
      exp: 4102444800,
      rounded: 9007199254740992,
      overflow: null,
      nested: [0, null],
      literal: {
        "$serde_json::private::Number": "1e400",
        "$serde_json::private::RawValue": "hello",
      },
      singleton: { "$serde_json::private::RawValue": "hello" },
    });

    const publicKeys = await ctx.rawRequest({ path: "/__test/profiles/jwt-default/api/auth/jwks" });
    const jwks = z
      .object({ keys: z.array(z.record(z.string(), z.unknown())) })
      .parse(publicKeys.body);
    const key = jwks.keys[0] as JWK;
    expect(key.kid).toBe(keys[0]?.id);

    const verified = await jwtVerify(token, await importJWK(key, "EdDSA"), {
      algorithms: ["EdDSA"],
      issuer: ctx.baseURL,
      audience: ctx.baseURL,
    });
    expect(verified.payload).toEqual(signed);

    const serverVerified = await ctx.rawRequest({
      path: "/__test/jwt",
      method: "POST",
      json: { operation: "verify", profile: "jwt-default", token },
    });
    expect(serverVerified.status).toBe(200);
    expect(serverVerified.body).toEqual({ payload: signed });

    const after = await ctx.rawRequest({ path: "/__test/jwks-state" });
    expect(after).toEqual(created);

    const falsy = await ctx.rawRequest({
      path: "/__test/jwt",
      method: "POST",
      json: {
        operation: "sign",
        profile: "jwt-default",
        payload: { exp: 4102444800, sub: 0, jti: false, iat: null, nbf: false },
      },
    });
    expect(falsy.status).toBe(200);

    const falsyToken = z.object({ token: z.string() }).parse(falsy.body).token;
    const falsyPayload: unknown = JSON.parse(
      Buffer.from(falsyToken.split(".")[1]!, "base64url").toString(),
    );
    expect(falsyPayload).toMatchObject({ sub: 0, jti: false, iat: null, nbf: false });

    return {
      rejections,
      created,
      issued,
      signed,
      publicKeys,
      verified: { header: verified.protectedHeader, payload: verified.payload },
      serverVerified,
      after,
      falsy,
      falsyPayload,
    };
  },
);
