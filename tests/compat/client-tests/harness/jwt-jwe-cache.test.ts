import { Database } from "bun:sqlite";
import { expect, test } from "bun:test";
import { hkdfSync } from "node:crypto";

import { getCurrentAdapter } from "@better-auth/core/context";
import { betterAuth } from "better-auth";
import { getCookieCache } from "better-auth/cookies";
import { symmetricDecrypt, symmetricDecodeJWT } from "better-auth/crypto";
import { getMigrations } from "better-auth/db/migration";
import { jwt } from "better-auth/plugins";
import {
  decodeProtectedHeader,
  decodeJwt,
  importJWK,
  SignJWT,
  EncryptJWT,
  jwtVerify,
  jwtDecrypt,
  type JWK,
} from "jose";

import { type ComparisonContext, compareValues } from "../support/compare";

const secret = "session-cache-harness-independent-secret-32";
const issuer = "https://session-cache.fixture.test";
const name = "better-auth.session_data";
async function observed(strategy: "jwt" | "jwe" | "managed", uuid: boolean) {
  const db = new Database(":memory:");
  const options = {
    baseURL: issuer,
    secret,
    database: db,
    rateLimit: { enabled: false },
    emailAndPassword: { enabled: true },
    advanced: {
      useSecureCookies: false,
      ...(uuid ? { database: { generateId: () => crypto.randomUUID() } } : {}),
    },
    plugins:
      strategy === "managed"
        ? [
            jwt({
              sessionCookieCache: true,
              adapter: {
                async createJwk(data, ctx) {
                  await Bun.sleep(1100);
                  const adapter = await getCurrentAdapter(ctx.context.adapter);
                  return adapter.create({ model: "jwks", data });
                },
              },
            }),
          ]
        : [],
    session: {
      cookieCache: {
        enabled: true,
        strategy: strategy === "managed" ? ("jwt" as const) : strategy,
        maxAge: 300,
        version: "1",
      },
    },
  };
  await (await getMigrations(options)).runMigrations();
  const auth = betterAuth(options);
  const start = Date.now();
  const response = await auth.handler(
    new Request(issuer + "/api/auth/sign-up/email", {
      method: "POST",
      headers: { origin: issuer, "content-type": "application/json" },
      body: JSON.stringify({
        email: "owner@fixture.test",
        name: "actual-cache-owner".repeat(500),
        password: "password123",
      }),
    }),
  );
  expect(response.status).toBe(200);
  const signup = await response.json();
  const rawCookies = response.headers.getSetCookie().filter((raw) => raw.startsWith(name));
  const token = rawCookies
    .map((raw) => decodeURIComponent(raw.split(";")[0]!.slice(raw.indexOf("=") + 1)))
    .join("");
  const keys: Record<string, unknown>[] =
    strategy === "managed" ? await (await auth.$context).adapter.findMany({ model: "jwks" }) : [];
  const jwks = keys.map((row) => ({
    ...JSON.parse(row.publicKey as string),
    kid: row.id,
    alg: row.alg,
  })) as JWK[];
  const decoded = await getCookieCache(
    new Headers({ cookie: rawCookies.map((raw) => raw.split(";")[0]).join("; ") }),
    {
      secret,
      isSecure: false,
      strategy: strategy === "managed" ? "jwt" : strategy,
      ...(strategy === "managed" ? { jwt: { jwks: { keys: jwks }, issuer } } : {}),
    },
  );
  expect(decoded).not.toBeNull();
  const header = decodeProtectedHeader(token);
  const payload = JSON.parse(JSON.stringify(decoded));
  const sessionCache = {
    strategy,
    token,
    header,
    payload,
    decoded,
    rawCookies,
    effectiveMaxAgeSeconds: 300,
    ...(strategy === "managed" ? { jwks } : {}),
  };
  const end = Date.now();
  db.close();
  return { signup, sessionCache, start, end, keys };
}
function value(input: Awaited<ReturnType<typeof observed>>) {
  return { signup: input.signup, sessionCache: input.sessionCache };
}
function context(
  left: Awaited<ReturnType<typeof observed>>,
  right: Awaited<ReturnType<typeof observed>>,
): ComparisonContext {
  return {
    leftBaseURL: issuer,
    rightBaseURL: issuer,
    leftStartedAt: left.start,
    rightStartedAt: right.start,
    leftFinishedAt: left.end,
    rightFinishedAt: right.end,
    sessionCookieSecret: secret,
  };
}
for (const strategy of ["jwt", "jwe", "managed"] as const) {
  test(`${strategy} cache comparator authenticates actual pinned issuance and rejects envelope, claims, key and chunk corruption`, async () => {
    const left = await observed(strategy, false),
      right = await observed(strategy, true),
      a = value(left),
      b = value(right),
      ctx = context(left, right);
    expect(left.signup.user.id.length).toBe(32);
    expect(right.signup.user.id.length).toBe(36);
    expect(right.sessionCache.rawCookies.length).toBeGreaterThan(1);
    if (strategy === "managed") {
      expect(Number(left.sessionCache.payload.iat)).toBeGreaterThan(
        Math.floor(Number(left.sessionCache.payload.updatedAt) / 1000),
      );
      expect(Number(right.sessionCache.payload.iat)).toBeGreaterThan(
        Math.floor(Number(right.sessionCache.payload.updatedAt) / 1000),
      );
    }
    expect(compareValues(a, b, ctx)).toEqual([]);
    const rejects = (changed: unknown) =>
      expect(compareValues(a, changed, ctx)).toContainEqual({
        path: "sessionCache",
        reason: "session-cache authentication or provenance differs",
      });
    expect(compareValues(a, b, { ...ctx, sessionCookieSecret: undefined }).length).toBeGreaterThan(
      0,
    );
    const altered = (change: (cache: any) => void) => {
      const copy = structuredClone(b);
      change(copy.sessionCache);
      return copy;
    };
    for (const change of [
      (c: any) => (c.decoded.user.name = "changed"),
      (c: any) => (c.payload.session.token = "foreign"),
      (c: any) => (c.payload.user.id = "foreign"),
      (c: any) => (c.header.extra = "unsigned"),
      (c: any) => (c.effectiveMaxAgeSeconds = 301),
      (c: any) => (c.extra = "omitted-evidence"),
      (c: any) => delete c.decoded,
      (c: any) => delete c.payload.user.email,
      (c: any) => (c.payload.custom = { token: "literal-application-token" }),
    ])
      rejects(altered(change));
    for (const mutate of [
      (raw: string[]) => raw.slice(1),
      (raw: string[]) => [...raw, raw[0]!],
      (raw: string[]) => raw.toReversed(),
      (raw: string[]) => raw.map((r) => r.replace("HttpOnly", "Secure")),
      (raw: string[]) => raw.map((r) => r.replace("Path=/", "Path=/foreign")),
      (raw: string[]) => raw.map((r) => r + "; Priority=High"),
      (raw: string[]) => raw.map((r) => r.replace("session_data.0=", "session_data.00=")),
    ])
      rejects(altered((c) => (c.rawCookies = mutate(c.rawCookies))));
    const key =
      strategy === "jwe"
        ? Buffer.from(
            hkdfSync(
              "sha256",
              secret,
              "better-auth-session",
              "BetterAuth.js Generated Encryption Key",
              64,
            ),
          )
        : strategy === "managed"
          ? await importJWK(
              JSON.parse(
                await symmetricDecrypt({
                  key: secret,
                  data: JSON.parse(
                    right.keys.find((row) => row.id === right.sessionCache.header.kid)!
                      .privateKey as string,
                  ),
                }),
              ),
              "EdDSA",
            )
          : new TextEncoder().encode(secret);
    const publicKey =
      strategy === "managed"
        ? await importJWK(
            right.sessionCache.jwks!.find((row) => row.kid === right.sessionCache.header.kid)!,
            "EdDSA",
          )
        : key;
    function replaceToken(copy: typeof b, token: string) {
      copy.sessionCache.token = token;
      const encoded = encodeURIComponent(token);
      const chunkSize = right.sessionCache.rawCookies[0]!.split(";")[0]!.split("=")[1]!.length;
      copy.sessionCache.rawCookies = Array.from(
        { length: Math.ceil(encoded.length / chunkSize) },
        (_, i) =>
          `${encoded.length <= chunkSize ? name : `${name}.${i}`}=${encoded.slice(i * chunkSize, (i + 1) * chunkSize)}; Max-Age=300; Path=/; HttpOnly; SameSite=Lax`,
      );
    }
    // Keep every non-cryptographic receipt consistent, so JOSE failure is the
    // only reason these controls cannot establish authenticated evidence.
    for (const segment of strategy === "jwe" ? [0, 2, 3, 4] : [0, 1, 2]) {
      const copy = structuredClone(b);
      const parts = copy.sessionCache.token.split(".");
      if (segment === 0) {
        parts[0] = Buffer.from(" " + JSON.stringify(copy.sessionCache.header)).toString(
          "base64url",
        );
      } else if (segment === 1) {
        const claims = structuredClone(copy.sessionCache.payload);
        claims.user.name = "tampered-owner-name";
        parts[1] = Buffer.from(JSON.stringify(claims)).toString("base64url");
        copy.sessionCache.payload = claims;
        copy.sessionCache.decoded = structuredClone(claims);
      } else {
        const bytes = Buffer.from(parts[segment]!, "base64url");
        bytes[0] = bytes[0]! ^ 1;
        parts[segment] = bytes.toString("base64url");
      }
      replaceToken(copy, parts.join("."));
      let code: string | undefined;
      try {
        if (strategy === "jwe") await jwtDecrypt(copy.sessionCache.token, key);
        else await jwtVerify(copy.sessionCache.token, publicKey);
      } catch (error) {
        code = (error as { code: string }).code;
      }
      expect(code).toBe(
        strategy === "jwe" ? "ERR_JWE_DECRYPTION_FAILED" : "ERR_JWS_SIGNATURE_VERIFICATION_FAILED",
      );
      rejects(copy);
    }
    const rewritten = async (change: (claims: any) => void) => {
      const copy = structuredClone(b),
        claims = structuredClone(copy.sessionCache.payload);
      change(claims);
      // The public Source writers reset iat/exp and JWE jti. JOSE directly
      // authenticates the full retained claims to isolate each changed field.
      const token =
        strategy === "jwe"
          ? await new EncryptJWT(claims)
              .setProtectedHeader({ ...copy.sessionCache.header, alg: "dir", enc: "A256CBC-HS512" })
              .encrypt(key)
          : await new SignJWT(claims)
              .setProtectedHeader({
                ...copy.sessionCache.header,
                alg: strategy === "jwt" ? "HS256" : "EdDSA",
              })
              .sign(key);
      replaceToken(copy, token);
      copy.sessionCache.header = decodeProtectedHeader(token);
      const decoded =
        strategy === "jwe"
          ? (await jwtDecrypt(token, key)).payload
          : (await jwtVerify(token, publicKey)).payload;
      copy.sessionCache.payload = JSON.parse(JSON.stringify(decoded));
      copy.sessionCache.decoded = structuredClone(copy.sessionCache.payload);
      return copy;
    };
    // Cross a real second boundary: unchanged re-encryption must still pass,
    // without silently failing because a writer refreshed the issuance clock.
    await Bun.sleep(1100);
    expect(compareValues(a, await rewritten(() => {}), ctx)).toEqual([]);
    const changedName = await rewritten((c) => (c.user.name = "X" + c.user.name.slice(1)));
    const nameDifferences = compareValues(a, changedName, ctx);
    expect(nameDifferences).toEqual([
      { path: "sessionCache.payload.user.name", reason: "value or type differs" },
      { path: "sessionCache.decoded.user.name", reason: "value or type differs" },
    ]);
    for (const change of [
      (c: any) => (c.user.id = "authentic-foreign-id"),
      (c: any) => (c.version = "2"),
      (c: any) => (c.updatedAt += 60000),
    ])
      rejects(await rewritten(change));
    const foreignToken = await rewritten(
      (c) =>
        (c.session.token = (c.session.token[0] === "X" ? "Y" : "X") + c.session.token.slice(1)),
    );
    if (strategy === "managed") rejects(foreignToken);
    else
      expect(compareValues(a, foreignToken, ctx)).toEqual([
        { path: "signup.token", reason: "identity relationship or token rotation differs" },
      ]);
    if (strategy === "managed")
      for (const change of [
        (c: any) => (c.iss = "https://foreign.test"),
        (c: any) => (c.aud = "foreign"),
        (c: any) => (c.sub = "foreign"),
        (c: any) => (c.sid = "foreign"),
      ])
        rejects(await rewritten(change));
    if (strategy === "managed") rejects(altered((c) => (c.jwks[0].x = "invalid-public-key")));
  });
}
