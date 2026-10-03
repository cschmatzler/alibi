import { Database } from "bun:sqlite";
import { expect, test } from "bun:test";

import { betterAuth } from "better-auth";
import { getCookieCache } from "better-auth/cookies";
import {
  signJWT,
  symmetricEncodeJWT,
  symmetricDecrypt,
  symmetricDecodeJWT,
} from "better-auth/crypto";
import { getMigrations } from "better-auth/db/migration";
import { jwt } from "better-auth/plugins";
import { decodeProtectedHeader, decodeJwt, importJWK, SignJWT, type JWK } from "jose";

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
    plugins: strategy === "managed" ? [jwt({ sessionCookieCache: true })] : [],
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
  const keys =
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
    expect(compareValues(a, b, ctx)).toEqual([]);
    const rejects = (changed: unknown) =>
      expect(compareValues(a, changed, ctx).length).toBeGreaterThan(0);
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
    for (const segment of strategy === "jwe" ? [0, 2, 3, 4] : [0, 1, 2])
      rejects(
        altered((c) => {
          const parts = c.token.split("."),
            bytes = Buffer.from(parts[segment], "base64url");
          bytes[0] ^= 1;
          parts[segment] = bytes.toString("base64url");
          c.token = parts.join(".");
        }),
      );
    const rewritten = async (change: (claims: any) => void) => {
      const copy = structuredClone(b),
        claims = structuredClone(copy.sessionCache.payload);
      change(claims);
      let token: string;
      if (strategy === "jwt") token = await signJWT(claims, secret, 300);
      else if (strategy === "jwe")
        token = await symmetricEncodeJWT(claims, secret, "better-auth-session", 300);
      else {
        const row = right.keys.find((row) => row.id === copy.sessionCache.header.kid)!;
        const key = await importJWK(
          JSON.parse(
            await symmetricDecrypt({ key: secret, data: JSON.parse(row.privateKey as string) }),
          ),
          "EdDSA",
        );
        token = await new SignJWT(claims).setProtectedHeader(copy.sessionCache.header).sign(key);
      }
      copy.sessionCache.token = token;
      copy.sessionCache.header = decodeProtectedHeader(token);
      copy.sessionCache.payload =
        strategy === "jwe"
          ? JSON.parse(
              JSON.stringify(await symmetricDecodeJWT(token, secret, "better-auth-session")),
            )
          : decodeJwt(token);
      copy.sessionCache.decoded = structuredClone(copy.sessionCache.payload);
      const encoded = encodeURIComponent(token),
        chunkSize = right.sessionCache.rawCookies[0]!.split(";")[0]!.split("=")[1]!.length;
      copy.sessionCache.rawCookies = Array.from(
        { length: Math.ceil(encoded.length / chunkSize) },
        (_, i) =>
          `${name}.${i}=${encoded.slice(i * chunkSize, (i + 1) * chunkSize)}; Max-Age=300; Path=/; HttpOnly; SameSite=Lax`,
      );
      return copy;
    };
    for (const change of [
      (c: any) => (c.user.name = "authentic-foreign-name"),
      (c: any) => (c.user.id = "authentic-foreign-id"),
      (c: any) => (c.session.token = "authentic-foreign-session"),
      (c: any) => (c.version = "2"),
      (c: any) => (c.updatedAt += 60000),
    ])
      rejects(await rewritten(change));
    if (strategy === "managed")
      for (const change of [
        (c: any) => (c.iss = "https://foreign.test"),
        (c: any) => (c.aud = "foreign"),
        (c: any) => (c.sub = "foreign"),
        (c: any) => (c.sid = "foreign"),
        (c: any) => (c.exp += 60000),
      ])
        rejects(await rewritten(change));
    if (strategy === "managed") rejects(altered((c) => (c.jwks[0].x = "invalid-public-key")));
  });
}
