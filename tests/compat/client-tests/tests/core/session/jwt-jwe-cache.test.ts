import { expect } from "bun:test";
import { hkdfSync } from "node:crypto";

import { createAuthClient } from "better-auth/client";
import { anonymousClient, multiSessionClient, jwtClient } from "better-auth/client/plugins";
import { getCookieCache } from "better-auth/cookies";
import { signJWT, symmetricEncodeJWT, verifyPassword } from "better-auth/crypto";
import { decodeProtectedHeader, jwtVerify, jwtDecrypt, type JWK } from "jose";
import { Cookie } from "tough-cookie";

import { authProfilePath, type FixtureProfile } from "../../../support/profiles";
import { compatScenario, type ScenarioContext } from "../../../support/scenario";
import { verifyWithOfficialJose } from "../../plugins/jwt/helpers";

const secret = "compat-test-only-key-not-real-minimum-32chars";
const cookieName = "better-auth.session_data";
function client(ctx: ScenarioContext, mode: string, name = "owner") {
  const actor = ctx.actor(name, `session-cache-${mode}` as FixtureProfile);
  const headers: Headers[] = [];
  const sdk = createAuthClient({
    baseURL: ctx.baseURL + authProfilePath(`session-cache-${mode}` as FixtureProfile),
    plugins: [anonymousClient(), multiSessionClient(), jwtClient()],
    fetchOptions: {
      customFetchImpl: async (input, init) => {
        const response = await actor.fetch(input, init);
        headers.push(new Headers(response.headers));
        return response;
      },
    },
  });
  return { sdk, headers, fetch: actor.fetch };
}
async function control(ctx: ScenarioContext, mode: string, body: Record<string, unknown>) {
  const response = await ctx.rawRequest({
    path: "/__test/session-cookie-cache/control",
    method: "POST",
    json: { mode, ...body },
  });
  expect(response.status).toBe(200);
  return normalizedState(response.body);
}
async function normalizedState(value: unknown) {
  const state = value as {
    accounts?: Record<string, unknown>[];
    users: Record<string, any>[];
    sessions: Record<string, any>[];
    events: Record<string, any>[];
  };
  if (state.accounts) {
    state.accounts = await Promise.all(
      state.accounts.map(async (account) => {
        if (typeof account.password !== "string") return account;
        const hash = account.password;
        expect(await verifyPassword({ password: "password123", hash })).toBeTrue();
        const [salt, derivedKey] = hash.split(":");
        return {
          ...account,
          password: {
            token: hash,
            salt: { token: salt, length: salt!.length },
            derivedKey: { token: derivedKey, length: derivedKey!.length },
            encoding: "hex-lower",
          },
        };
      }),
    );
  }
  return state;
}
function cookies(headers: Headers) {
  return headers.getSetCookie().map((raw) => raw.split(";")[0]!);
}
function assemble(headers: Headers) {
  return headers
    .getSetCookie()
    .map((raw) => Cookie.parse(raw)!)
    .filter((cookie) => cookie.key === cookieName || cookie.key.startsWith(cookieName + "."))
    .filter((cookie) => cookie.value)
    .map((cookie) => decodeURIComponent(cookie.value))
    .join("");
}
async function raw(
  ctx: ScenarioContext,
  owner: ReturnType<typeof client>,
  mode: string,
  path: string,
  pairs: string[],
  body?: unknown,
) {
  const response = await owner.fetch(
    ctx.baseURL + authProfilePath(`session-cache-${mode}` as FixtureProfile) + path,
    {
      credentials: "omit",
      method: body ? "POST" : "GET",
      headers: {
        cookie: pairs.join("; "),
        origin: ctx.baseURL,
        ...(body ? { "content-type": "application/json" } : {}),
      },
      ...(body ? { body: JSON.stringify(body) } : {}),
    },
  );
  const text = await response.text();
  return { status: response.status, body: text ? JSON.parse(text) : null };
}
async function observation(
  ctx: ScenarioContext,
  owner: ReturnType<typeof client>,
  strategy: "jwt" | "jwe" | "managed",
  headers: Headers,
  cacheSecret = secret,
  authPath?: string,
) {
  const token = assemble(headers);
  const header = decodeProtectedHeader(token);
  const jwks = strategy === "managed" ? ((await owner.sdk.jwks()).data!.keys as JWK[]) : undefined;
  const key = Buffer.from(
    hkdfSync(
      "sha256",
      cacheSecret,
      "better-auth-session",
      "BetterAuth.js Generated Encryption Key",
      64,
    ),
  );
  let payload;
  if (strategy === "jwe") {
    payload = (
      await jwtDecrypt(token, key, {
        keyManagementAlgorithms: ["dir"],
        contentEncryptionAlgorithms: ["A256CBC-HS512"],
      })
    ).payload;
  } else if (strategy === "jwt") {
    payload = (
      await jwtVerify(token, new TextEncoder().encode(cacheSecret), { algorithms: ["HS256"] })
    ).payload;
  } else {
    const { importJWK } = await import("jose");
    const jwk = jwks!.find((key) => key.kid === header.kid)!;
    expect(jwk).toBeDefined();
    payload = (
      await jwtVerify(token, await importJWK(jwk, "EdDSA"), {
        algorithms: ["EdDSA"],
        issuer: "https://session-cache.fixture.test",
        audience: "better-auth:session-cache",
      })
    ).payload;
    expect(header.typ).toBe("better-auth.session-cache+jwt");
  }
  const decoded = await getCookieCache(new Headers({ cookie: cookies(headers).join("; ") }), {
    secret: cacheSecret,
    strategy: strategy === "managed" ? "jwt" : strategy,
    ...(jwks
      ? { jwt: { jwks: { keys: jwks }, issuer: "https://session-cache.fixture.test" } }
      : {}),
  });
  expect(decoded).not.toBeNull();
  expect(payload.exp! - payload.iat!).toBe(300);
  expect(JSON.parse(JSON.stringify(decoded!.session))).toEqual(payload.session);
  expect(JSON.parse(JSON.stringify(decoded!.user))).toEqual(payload.user);
  return {
    sessionCache: {
      strategy,
      ...(authPath ? { authPath } : {}),
      token,
      header,
      payload,
      decoded,
      rawCookies: headers.getSetCookie().filter((raw) => raw.startsWith(cookieName)),
      effectiveMaxAgeSeconds: 300,
      ...(jwks ? { jwks } : {}),
    },
  };
}

for (const mode of ["jwt", "jwe", "managed"] as const) {
  compatScenario(
    `${mode} session cache authenticates real issuance and preserves revoked snapshots while sensitive guards reject`,
    async (ctx) => {
      const owner = client(ctx, mode),
        foreign = client(ctx, mode, "foreign");
      const originalName = "Cached JWT Owner".repeat(500);
      const signup = await owner.sdk.signUp.email({
        email: ctx.uniqueEmail(`cache-${mode}`),
        name: originalName,
        password: "password123",
      });
      const other = await foreign.sdk.signUp.email({
        email: ctx.uniqueEmail(`cache-${mode}-foreign`),
        name: "Foreign JWT Owner",
        password: "password123",
      });
      expect(signup.error).toBeNull();
      expect(other.error).toBeNull();
      const issued = owner.headers.at(-1)!,
        pairs = cookies(issued),
        checked = await observation(ctx, owner, mode, issued);
      const otherChecked = await observation(ctx, foreign, mode, foreign.headers.at(-1)!);
      expect(checked.sessionCache.decoded!.session.token).toBe(signup.data!.token!);
      expect(checked.sessionCache.payload.user).toEqual(
        JSON.parse(JSON.stringify(signup.data!.user)),
      );
      const before = await control(ctx, mode, { action: "rows", userId: signup.data!.user.id! }),
        foreignBefore = await control(ctx, mode, { action: "rows", userId: other.data!.user.id! });
      await control(ctx, mode, {
        action: "rename",
        userId: signup.data!.user.id!,
        name: "Physical Changed Owner",
      });
      const refreshed = await owner.sdk.getSession({ query: { disableCookieCache: true } });
      expect(refreshed.data!.user.name).toBe("Physical Changed Owner");
      const replacement = owner.headers.at(-1)!;
      const clears = replacement.getSetCookie().filter((raw) => Cookie.parse(raw)?.maxAge === 0);
      expect(clears.length).toBeGreaterThan(1);
      expect(replacement.getSetCookie().some((raw) => raw.startsWith(cookieName + "="))).toBeTrue();
      const renewed = await observation(ctx, owner, mode, replacement);
      await control(ctx, mode, { action: "revoke", token: signup.data!.token });
      const cached = await raw(ctx, owner, mode, "/get-session", pairs);
      expect(cached.status).toBe(200);
      expect(cached.body.user.name).toBe(originalName);
      expect(cached.body.session.token).toBe(signup.data!.token!);
      const bypass = await raw(ctx, owner, mode, "/get-session?disableCookieCache=true", pairs);
      expect(bypass.body).toBeNull();
      const sensitive = await raw(ctx, owner, mode, "/change-password", pairs, {
        currentPassword: "password123",
        newPassword: "different-password123",
      });
      expect(sensitive.status).toBe(401);
      const tokenPair = pairs.find((pair) => pair.startsWith("better-auth.session_token="))!;
      const tampered = await raw(ctx, owner, mode, "/get-session", [
        tokenPair,
        `${cookieName}=${checked.sessionCache.token}x`,
      ]);
      expect(tampered.body).toBeNull();
      const crossed = await raw(ctx, owner, mode, "/get-session", [
        tokenPair,
        `${cookieName}=${otherChecked.sessionCache.token}`,
      ]);
      expect(crossed.body).toBeNull();
      let exported: unknown = null;
      if (mode !== "managed") {
        // This calls the pinned published writer, then presents its actual envelope
        // to the native HTTP resolver bound to the native-issued signed token.
        const { session, user, updatedAt, version } = checked.sessionCache.payload;
        const payload = { session, user, updatedAt, version };
        const written =
          mode === "jwt"
            ? await signJWT(payload, secret, 300)
            : await symmetricEncodeJWT(payload, secret, "better-auth-session", 300);
        const imported = await raw(ctx, owner, mode, "/get-session", [
          tokenPair,
          `${cookieName}=${written}`,
        ]);
        expect(imported.body).toEqual(cached.body);
        const wrong =
          mode === "jwt"
            ? await signJWT(payload, "different-auth-secret-at-least-32-chars", 300)
            : await symmetricEncodeJWT(payload, secret, "better-auth-account", 300);
        const denied = await raw(ctx, owner, mode, "/get-session", [
          tokenPair,
          `${cookieName}=${wrong}`,
        ]);
        expect(denied.body).toBeNull();
        const expired =
          mode === "jwt"
            ? await signJWT(payload, secret, -1)
            : await symmetricEncodeJWT(payload, secret, "better-auth-session", -1);
        const expiredRead = await raw(ctx, owner, mode, "/get-session", [
          tokenPair,
          `${cookieName}=${expired}`,
        ]);
        expect(expiredRead.body).toBeNull();
        exported = { imported, denied, expiredRead };
      }
      const after = await control(ctx, mode, { action: "rows", userId: signup.data!.user.id! }),
        foreignAfter = await control(ctx, mode, { action: "rows", userId: other.data!.user.id! });
      expect(foreignAfter).toEqual(foreignBefore);
      return {
        signup,
        other,
        checked,
        otherChecked,
        refreshed,
        renewed,
        clears,
        before,
        foreignBefore,
        cached,
        bypass,
        sensitive,
        tampered,
        crossed,
        exported,
        after,
        foreignAfter,
      };
    },
    [
      "POST /sign-up/email",
      "GET /get-session",
      "POST /change-password",
      ...(mode === "managed" ? ["GET /jwks"] : []),
    ],
  );
}

// This owner crosses the two actual servers, so identity is literally shared;
// it must not use a differential identity mapping or a synthetic signer receipt.
compatScenario(
  "managed session-cache cookies cross actual runtimes and rotate persisted keys without admitting foreign claims",
  async (ctx) => {
    const source = ctx.baseURL;
    const native =
      source === process.env.AUTH_BASE_URL_TS
        ? process.env.AUTH_BASE_URL_RUST!
        : process.env.AUTH_BASE_URL_TS!;
    const transport = ctx.actor("cross-runtime", "session-cache-managed").fetch;
    const reset = await transport(native + "/__test/reset-state", {
      method: "POST",
      credentials: "omit",
    });
    expect(reset.status).toBe(200);
    expect(source).toBeDefined();
    expect(native).toBeDefined();
    const path = authProfilePath("session-cache-managed");
    const send = async (base: string, route: string, body?: unknown, pairs: string[] = []) => {
      const response = await transport(base + route, {
        credentials: "omit",
        method: body ? "POST" : "GET",
        headers: {
          origin: "https://session-cache.fixture.test",
          cookie: pairs.join("; "),
          ...(body ? { "content-type": "application/json" } : {}),
        },
        ...(body ? { body: JSON.stringify(body) } : {}),
      });
      const text = await response.text();
      return {
        status: response.status,
        headers: response.headers,
        body: text ? JSON.parse(text) : null,
      };
    };
    const command = async (base: string, action: string, extra: Record<string, unknown> = {}) => {
      const response = await send(base, "/__test/session-cookie-cache/control", {
        mode: "managed",
        action,
        ...extra,
      });
      expect(response.status).toBe(200);
      return response.body as { keys: Record<string, unknown>[] };
    };
    const actual = await send(source, path + "/sign-up/email", {
      email: ctx.uniqueEmail("source-cache"),
      name: "Actual Source Cache Owner",
      password: "password123",
    });
    expect(actual.status).toBe(200);
    const originalObservation = await observation(
      ctx,
      client(ctx, "managed"),
      "managed",
      actual.headers,
    );
    const sourceCookies = cookies(actual.headers);
    const sourceToken = assemble(actual.headers);
    const sourceHeader = decodeProtectedHeader(sourceToken);
    const sourceKeys = await command(source, "cache-keys");
    const actualKey = sourceKeys.keys.find((key) => key.id === sourceHeader.kid)!;
    expect(actualKey).toBeDefined();
    await command(native, "import-cache-key", { key: actualKey });
    const imported = await send(native, path + "/get-session", undefined, sourceCookies);
    expect(imported.status).toBe(200);
    expect(imported.body.user).toEqual(actual.body.user);
    expect(imported.body.session.token).toBe(actual.body.token);
    const { symmetricDecrypt } = await import("better-auth/crypto");
    const { importJWK, SignJWT, decodeJwt } = await import("jose");
    const privateKey = await importJWK(
      JSON.parse(
        await symmetricDecrypt({ key: secret, data: JSON.parse(actualKey.privateKey as string) }),
      ),
      "EdDSA",
    );
    const claims = decodeJwt(sourceToken);
    const tokenPair = sourceCookies.find((pair) => pair.startsWith("better-auth.session_token="))!;
    for (const change of [
      { iss: "https://foreign-issuer.test" },
      { aud: "foreign-audience" },
      { sid: "foreign-session" },
      { sub: "foreign-owner" },
      { exp: Math.floor(Date.now() / 1000) - 30 },
    ]) {
      const invalid = await new SignJWT({ ...claims, ...change })
        .setProtectedHeader({ ...sourceHeader, alg: "EdDSA" })
        .sign(privateKey);
      const denied = await send(native, path + "/get-session", undefined, [
        tokenPair,
        `${cookieName}=${invalid}`,
      ]);
      expect(denied.body).toBeNull();
      expect(
        await getCookieCache(new Headers({ cookie: `${cookieName}=${invalid}` }), {
          strategy: "jwt",
          jwt: {
            jwks: {
              keys: sourceKeys.keys.map((row) => ({
                ...JSON.parse(row.publicKey as string),
                kid: row.id,
                alg: row.alg,
              })),
            },
            issuer: "https://session-cache.fixture.test",
          },
        }),
      ).toBeNull();
    }
    const priorKeys = (await command(native, "cache-keys")).keys;
    const rotation = await command(native, "rotate-cache-key");
    const newKey = rotation.keys.find((key) => !priorKeys.some((old) => old.id === key.id))!;
    expect(newKey).toBeDefined();
    await command(source, "import-cache-key", { key: newKey });
    const nativeIssuance = await send(native, path + "/sign-up/email", {
      email: ctx.uniqueEmail("native-cache"),
      name: "Actual Native Cache Owner",
      password: "password123",
    });
    expect(nativeIssuance.status).toBe(200);
    const nativeObservation = await observation(
      ctx,
      client(ctx, "managed"),
      "managed",
      nativeIssuance.headers,
    );
    const nativeToken = assemble(nativeIssuance.headers);
    expect(decodeProtectedHeader(nativeToken).kid).toEqual(String(newKey.id));
    const nativeKeys = (await command(native, "cache-keys")).keys;
    const decoded = await getCookieCache(
      new Headers({ cookie: cookies(nativeIssuance.headers).join("; ") }),
      {
        strategy: "jwt",
        jwt: {
          jwks: {
            keys: nativeKeys.map((row) => ({
              ...JSON.parse(row.publicKey as string),
              kid: row.id,
              alg: row.alg,
            })),
          },
          issuer: "https://session-cache.fixture.test",
        },
      },
    );
    expect(decoded!.session.token).toBe(nativeIssuance.body.token);
    expect(JSON.parse(JSON.stringify(decoded!.user))).toEqual(nativeIssuance.body.user);
    const exported = await send(
      source,
      path + "/get-session",
      undefined,
      cookies(nativeIssuance.headers),
    );
    expect(exported.body.user).toEqual(nativeIssuance.body.user);
    expect(exported.body.session.token).toBe(nativeIssuance.body.token);
    expect((await send(native, path + "/get-session", undefined, sourceCookies)).body.user.id).toBe(
      actual.body.user.id,
    );
    await command(native, "retire-cache-key", { token: actualKey.id });
    expect((await send(native, path + "/get-session", undefined, sourceCookies)).body).toBeNull();
    const nativeBefore = await send(native, "/__test/session-cookie-cache/control", {
      mode: "managed",
      action: "rows",
      userId: nativeIssuance.body.user.id,
    });
    expect(nativeBefore.body.sessions).toHaveLength(1);
    expect(nativeBefore.body.sessions[0].token).toBe(nativeIssuance.body.token);
    return {
      actual: actual.body,
      imported: imported.body,
      nativeIssuance: nativeIssuance.body,
      originalObservation,
      nativeObservation,
      exported: exported.body,
      nativeBefore: await normalizedState(nativeBefore.body),
    };
  },
  ["POST /sign-up/email", "GET /get-session"],
);

compatScenario(
  "JWE cache rotation reads retained keys and rejects retired and wrong-kid envelopes across actual runtimes",
  async (ctx) => {
    const current = "cache-managed-new-secret-at-least-32-characters";
    const { makeSignature, symmetricDecodeJWT } = await import("better-auth/crypto");
    const { EncryptJWT } = await import("jose");
    const transport = ctx.actor("rotation", "session-cache-jwe-old").fetch;
    const base = ctx.baseURL;
    {
      const signup = await transport(
        base + authProfilePath("session-cache-jwe-old") + "/sign-up/email",
        {
          method: "POST",
          headers: { origin: base, "content-type": "application/json" },
          body: JSON.stringify({
            email: ctx.uniqueEmail("jwe-rotation"),
            name: "Retained JWE Owner",
            password: "password123",
          }),
        },
      );
      expect(signup.status).toBe(200);
      const issued = (await signup.json()) as { token: string; user: { id: string } };
      const oldObservation = await observation(ctx, client(ctx, "jwe-old"), "jwe", signup.headers);
      const oldToken = assemble(signup.headers);
      const keys = {
        currentVersion: 2,
        keys: new Map([
          [2, current],
          [1, secret],
        ]),
      };
      const decoded = await symmetricDecodeJWT(oldToken, keys, "better-auth-session");
      expect(decoded!.session.token).toBe(issued.token);
      // Cookie HMAC rotation intentionally invalidates old signatures. Independently
      // sign the genuinely issued token through the pinned public signer to isolate
      // the retained JWE reader from that separate current-only credential policy.
      const signed = encodeURIComponent(
        `${issued.token}.${await makeSignature(issued.token, current)}`,
      );
      const retained = await transport(
        base + authProfilePath("session-cache-jwe-retained") + "/get-session",
        { headers: { cookie: `better-auth.session_token=${signed}; ${cookieName}=${oldToken}` } },
      );
      expect(retained.status).toBe(200);
      expect(((await retained.json()) as any).user.id).toBe(issued.user.id);
      // Remove the actual row so a retired envelope cannot be rescued by SQL fallback.
      const revoke = await transport(base + "/__test/session-cookie-cache/control", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ mode: "jwe-old", action: "revoke", token: issued.token }),
      });
      expect(revoke.status).toBe(200);
      const retired = await transport(
        base + authProfilePath("session-cache-jwe-retired") + "/get-session",
        { headers: { cookie: `better-auth.session_token=${signed}; ${cookieName}=${oldToken}` } },
      );
      expect(await retired.json()).toBeNull();
      const key = Buffer.from(
        hkdfSync(
          "sha256",
          secret,
          "better-auth-session",
          "BetterAuth.js Generated Encryption Key",
          64,
        ),
      );
      const noKid = await new EncryptJWT(decoded!)
        .setProtectedHeader({ alg: "dir", enc: "A256CBC-HS512" })
        .encrypt(key);
      const oldReader = await transport(
        base + authProfilePath("session-cache-jwe-retained") + "/get-session",
        { headers: { cookie: `better-auth.session_token=${signed}; ${cookieName}=${noKid}` } },
      );
      expect(((await oldReader.json()) as any).user.id).toBe(issued.user.id);
      const wrongKid = await new EncryptJWT(decoded!)
        .setProtectedHeader({ alg: "dir", enc: "A256CBC-HS512", kid: "foreign-key" })
        .encrypt(key);
      const denied = await transport(
        base + authProfilePath("session-cache-jwe-retained") + "/get-session",
        { headers: { cookie: `better-auth.session_token=${signed}; ${cookieName}=${wrongKid}` } },
      );
      expect(await denied.json()).toBeNull();
      const currentWriter = await transport(
        base + authProfilePath("session-cache-jwe-retained") + "/sign-up/email",
        {
          method: "POST",
          headers: { origin: base, "content-type": "application/json" },
          body: JSON.stringify({
            email: ctx.uniqueEmail("jwe-current"),
            name: "Current JWE Owner",
            password: "password123",
          }),
        },
      );
      expect(currentWriter.status).toBe(200);
      const currentToken = assemble(currentWriter.headers);
      expect(decodeProtectedHeader(currentToken).kid).not.toBe(decodeProtectedHeader(oldToken).kid);
      const currentClaims = await symmetricDecodeJWT(currentToken, keys, "better-auth-session");
      expect(currentClaims).not.toBeNull();
      expect(await symmetricDecodeJWT(currentToken, secret, "better-auth-session")).toBeNull();
      const currentObservation = await observation(
        ctx,
        client(ctx, "jwe-retained"),
        "jwe",
        currentWriter.headers,
        current,
        authProfilePath("session-cache-jwe-retained"),
      );
      return { issued, oldObservation, currentObservation };
    }
  },
  ["POST /sign-up/email", "GET /get-session"],
  30_000,
  {
    sessionCookieSecretsByAuthPath: {
      [authProfilePath("session-cache-jwe-retained")]:
        "cache-managed-new-secret-at-least-32-characters",
      [authProfilePath("session-cache-jwe-retired")]:
        "cache-managed-new-secret-at-least-32-characters",
    },
  },
);

for (const strategy of ["jwt", "jwe"] as const) {
  compatScenario(
    `${strategy} interaction anonymous linking retains the original cached projection while later hooks publish the genuine completed owner`,
    async (ctx) => {
      const mode = `${strategy}-interactions`;
      await control(ctx, mode, { action: "reset" });
      const owner = client(ctx, mode);
      const foreign = client(ctx, mode, "foreign");
      const anonymous = await owner.sdk.signIn.anonymous();
      expect(anonymous.error).toBeNull();

      const original = await observation(ctx, owner, strategy, owner.headers.at(-1)!);
      const anonymousId = anonymous.data!.user.id;
      const other = await foreign.sdk.signUp.email({
        email: ctx.uniqueEmail("compact-anon-foreign"),
        name: "Foreign Anonymous Control",
        password: "password123",
      });
      expect(other.error).toBeNull();

      const foreignBefore = await controlRows(ctx, other.data!.user.id, mode);
      await control(ctx, mode, {
        action: "rename",
        userId: anonymousId,
        name: "Current Physical Anonymous Row",
      });
      const before = await controlRows(ctx, anonymousId, mode);
      await control(ctx, mode, { action: "clear-events" });
      const signup = await owner.sdk.signUp.email({
        email: ctx.uniqueEmail("compact-anon-linked"),
        name: "Actual Linked Owner",
        password: "password123",
      });
      expect(signup.error).toBeNull();

      const headers = owner.headers.at(-1)!;
      const issued = await observation(ctx, owner, strategy, headers);
      expect(issued.sessionCache.decoded!.user.id).toBe(signup.data!.user.id);
      expect(issued.sessionCache.decoded!.session.token).toBe(signup.data!.token!);
      expect(headers.getSetCookie().some((raw) => raw.includes("_multi-"))).toBeTrue();

      const receipts = await control(ctx, mode, { action: "state" });
      const linked = receipts.events.find((event) => event.link)!;
      expect(linked.link.anonymousUser.user).toEqual(
        ctx.snapshot(original.sessionCache.decoded!.user),
      );
      expect(linked.link.anonymousUser.session).toEqual(
        ctx.snapshot(original.sessionCache.decoded!.session),
      );
      expect(linked.link.newUser.user.id).toBe(signup.data!.user.id);
      expect(linked.link.newUser.session.token).toBe(signup.data!.token);

      const retired = await controlRows(ctx, anonymousId, mode);
      expect(retired.users).toEqual([]);
      expect(retired.accounts).toEqual([]);
      expect(retired.sessions).toEqual([]);

      const completed = await controlRows(ctx, signup.data!.user.id, mode);
      expect(completed.sessions).toHaveLength(1);
      expect(completed.sessions[0]!.token).toBe(signup.data!.token);
      expect(await controlRows(ctx, other.data!.user.id, mode)).toEqual(foreignBefore);

      const current = await owner.sdk.getSession();
      expect(current.data!.user.id).toBe(signup.data!.user.id);

      const currentHeaders = owner.headers.at(-1)!;
      const jwks = await owner.sdk.jwks();
      expect(jwks.error).toBeNull();

      const checked = await verifyWithOfficialJose(
        currentHeaders.get("set-auth-jwt")!,
        jwks.data!.keys as JWK[],
        ctx.baseURL,
        ctx.baseURL,
      );
      expect(checked.payload.sub).toBe(signup.data!.user.id);

      return {
        anonymous,
        other,
        original,
        before,
        signup,
        issued,
        receipts,
        retired,
        completed,
        foreignBefore,
        current,
        checked,
      };
    },
    ["POST /sign-in/anonymous", "POST /sign-up/email", "GET /get-session", "GET /jwks"],
  );
}

for (const strategy of ["jwt", "jwe"] as const) {
  compatScenario(
    `${strategy} interaction multi-session selection and revoked-current fallback replace genuine cache with the physically selected owner`,
    async (ctx) => {
      const mode = `${strategy}-interactions`;
      await control(ctx, mode, { action: "reset" });
      const owner = client(ctx, mode);
      const foreign = client(ctx, mode, "foreign");
      const first = await owner.sdk.signUp.email({
        email: ctx.uniqueEmail("compact-multi-first"),
        name: "First Selected Owner",
        password: "password123",
      });
      expect(first.error).toBeNull();

      const firstIssued = await observation(ctx, owner, strategy, owner.headers.at(-1)!);
      const second = await owner.sdk.signUp.email({
        email: ctx.uniqueEmail("compact-multi-second"),
        name: "Second Selected Owner",
        password: "password123",
      });
      expect(second.error).toBeNull();

      const secondIssued = await observation(ctx, owner, strategy, owner.headers.at(-1)!);
      const other = await foreign.sdk.signUp.email({
        email: ctx.uniqueEmail("compact-multi-foreign"),
        name: "Foreign Browser Owner",
        password: "password123",
      });
      expect(other.error).toBeNull();

      const foreignBefore = await controlRows(ctx, other.data!.user.id, mode);
      const list = await owner.sdk.multiSession.listDeviceSessions();
      expect(list.data).toHaveLength(2);

      const selected = await owner.sdk.multiSession.setActive({ sessionToken: first.data!.token! });
      expect(selected.error).toBeNull();

      const selectedCache = await observation(ctx, owner, strategy, owner.headers.at(-1)!);
      expect(selectedCache.sessionCache.decoded!.user.id).toBe(first.data!.user.id);
      expect(selectedCache.sessionCache.decoded!.session.token).toBe(first.data!.token!);

      const active = await owner.sdk.getSession();
      expect(active.data!.user.id).toBe(first.data!.user.id);

      const activeHeader = owner.headers.at(-1)!;
      const jwks = await owner.sdk.jwks();
      expect(jwks.error).toBeNull();

      const checked = await verifyWithOfficialJose(
        activeHeader.get("set-auth-jwt")!,
        jwks.data!.keys as JWK[],
        ctx.baseURL,
        ctx.baseURL,
      );
      expect(checked.payload.sub).toBe(first.data!.user.id);

      await control(ctx, mode, { action: "revoke", token: first.data!.token });
      const firstBefore = await controlRows(ctx, first.data!.user.id, mode);
      expect(firstBefore.sessions).toEqual([]);

      const revoked = await owner.sdk.multiSession.revoke({ sessionToken: first.data!.token! });
      expect(revoked.error).toBeNull();

      const fallbackCache = await observation(ctx, owner, strategy, owner.headers.at(-1)!);
      expect(fallbackCache.sessionCache.decoded!.user.id).toBe(second.data!.user.id);
      expect(fallbackCache.sessionCache.decoded!.session.token).toBe(second.data!.token!);

      const fallback = await owner.sdk.getSession();
      expect(fallback.data!.user.id).toBe(second.data!.user.id);

      const denied = await foreign.sdk.multiSession.setActive({
        sessionToken: second.data!.token!,
      });
      expect(denied.error!.code).toBe("INVALID_SESSION_TOKEN");

      const beforeOut = await controlRows(ctx, second.data!.user.id, mode);
      expect(beforeOut.sessions).toHaveLength(1);

      const signedOut = await owner.sdk.signOut();
      expect(signedOut.error).toBeNull();

      const after = await controlRows(ctx, second.data!.user.id, mode);
      expect(after.sessions).toEqual([]);
      expect(after.users).toEqual(beforeOut.users);
      expect(after.accounts).toEqual(beforeOut.accounts);
      expect(await owner.sdk.multiSession.listDeviceSessions()).toMatchObject({ data: [] });
      expect((await controlRows(ctx, foreignBefore.users[0]!.id as string, mode)).users).toEqual(
        foreignBefore.users,
      );
      expect((await controlRows(ctx, other.data!.user.id, mode)).sessions).toEqual(
        foreignBefore.sessions,
      );

      return {
        first,
        second,
        other,
        firstIssued,
        secondIssued,
        list,
        selected,
        selectedCache,
        active,
        checked,
        firstBefore,
        revoked,
        fallbackCache,
        fallback,
        denied,
        beforeOut,
        signedOut,
        after,
        foreignBefore,
      };
    },
    [
      "GET /multi-session/list-device-sessions",
      "POST /multi-session/set-active",
      "POST /multi-session/revoke",
      "POST /sign-out",
    ],
  );
}

async function controlRows(ctx: ScenarioContext, userId: string, mode: string) {
  return control(ctx, mode, { action: "rows", userId });
}
