import { expect } from "bun:test";
import { createHash } from "node:crypto";
import { apiKeyClient } from "@better-auth/api-key/client";
import { createAuthClient } from "better-auth/client";
import { authProfilePath } from "../../support/profiles";
import { compatScenario, type ScenarioContext } from "../../support/scenario";

type Data = Record<string, any>;
function object(value: unknown): Data {
  expect(value).toBeObject();
  return value as Data;
}
function client(ctx: ScenarioContext, name: string) {
  return createAuthClient({
    baseURL: `${ctx.baseURL}${authProfilePath("api-key-generation")}`,
    plugins: [apiKeyClient()],
    fetchOptions: {
      customFetchImpl: ctx.actor(name, "api-key-generation").fetch,
    },
  });
}
async function control(ctx: ScenarioContext, path: string, json?: unknown) {
  const result = await ctx.rawRequest({
    path: `/__test/api-key-generation/${path}`,
    method: json === undefined ? "GET" : "POST",
    json,
  });
  expect(result.status).toBe(200);
  return result.body;
}
async function setup(ctx: ScenarioContext) {
  await control(ctx, "mode", { mode: "normal", reset: true });
  await control(ctx, "events");
  const owner = client(ctx, "owner"),
    foreign = client(ctx, "foreign");
  const users = [];
  for (const [auth, name] of [
    [owner, "Owner"],
    [foreign, "Foreign"],
  ] as const) {
    const result = await auth.signUp.email({
      email: ctx.uniqueEmail(`generation-${name}`),
      password: "password123",
      name,
    });
    expect(result.error).toBeNull();
    users.push(result.data!.user);
  }
  return { owner, foreign, ownerId: users[0]!.id, foreignId: users[1]!.id };
}
async function events(ctx: ScenarioContext) {
  const result = await control(ctx, "events");
  expect(result).toBeArray();
  return result as Data[];
}
async function state(ctx: ScenarioContext) {
  const result = await control(ctx, "state");
  expect(result).toBeArray();
  return result as Data[];
}
function row(rows: Data[], key: Data) {
  const result = rows.find((row) => row.id === key.id);
  expect(result).toBeDefined();
  if (!result) throw new Error("persisted key required");
  expect(result.referenceId).toBe(key.referenceId);
  expect(result.configId).toBe(key.configId);
  return result!;
}
function defaults(configurationId: string, action = "read") {
  return Object.fromEntries([
    ["zeta", [action]],
    ["10", ["ten"]],
    ["2", ["two"]],
    ["alpha", [configurationId]],
    ["$serde_json::private::RawValue", ["literal"]],
  ]);
}
function generatedEvents(
  observed: Data[],
  key: Data,
  requestPresent: boolean,
  length = 24,
  prefix: string | null = "app_",
  mode = "normal",
  explicit: unknown = null,
) {
  expect(observed).toEqual([
    { kind: "generator", length, prefix, mode },
    {
      kind: "permissions",
      configurationId: key.configId,
      reference: { userId: key.referenceId },
      requestPresent,
      explicit,
      mode,
    },
  ]);
}

compatScenario(
  "api-key application generation and dynamic permissions bind issuing configuration, owner and persisted authorization",
  async (ctx) => {
    const { owner, foreign, ownerId, foreignId } = await setup(ctx);
    const issued = await owner.apiKey.create({
      configId: "generated",
      name: "a-http",
    });
    expect(issued.error).toBeNull();
    const key = object(issued.data);
    expect(key.referenceId).toBe(ownerId);
    expect(key.key).toMatch(/^app_generated-owned-secret-\d+$/);
    expect(key.start).toBe("ap");
    expect(key.permissions).toEqual(defaults("generated"));
    const issuedEvents = await events(ctx);
    generatedEvents(issuedEvents, key, true);
    const foreignIssued = await foreign.apiKey.create({
      configId: "generated",
      name: "b-foreign",
      prefix: "own_",
    });
    expect(foreignIssued.error).toBeNull();
    const foreignKey = object(foreignIssued.data);
    expect(foreignKey.referenceId).toBe(foreignId);
    expect(foreignKey.key).toMatch(/^own_generated-owned-secret-\d+$/);
    expect(foreignKey.permissions).toEqual(defaults("generated", "foreign"));
    const foreignEvents = await events(ctx);
    generatedEvents(foreignEvents, foreignKey, true, 24, "own_");
    const deniedRead = await foreign.apiKey.get({
      query: { id: key.id, configId: "generated" },
    });
    expect(deniedRead.error).toMatchObject({ status: 404, code: "KEY_NOT_FOUND" });
    expect(await events(ctx)).toEqual([]);
    const quota = object(
      await control(ctx, "create", {
        userId: ownerId,
        configId: "generated",
        name: "c-override",
        permissions: { vault: ["read"] },
        remaining: 4,
      }),
    );
    expect(quota.permissions).toEqual({ vault: ["read"] });
    const overrideEvents = await events(ctx);
    generatedEvents(overrideEvents, quota, false);
    const initial = await state(ctx);
    expect(row(initial, key).key).toBe(createHash("sha256").update(key.key).digest("base64url"));
    expect(row(initial, key).permissions).toBe(JSON.stringify(defaults("generated")));
    expect(row(initial, foreignKey).permissions).toBe(
      JSON.stringify(defaults("generated", "foreign")),
    );
    expect(row(initial, quota).permissions).toBe('{"vault":["read"]}');
    expect(row(initial, quota).remaining).toBe(4);
    const permissionDenied = object(
      await control(ctx, "verify", {
        key: quota.key,
        configId: "generated",
        permissions: { vault: ["write"] },
      }),
    );
    expect(permissionDenied.valid).toBe(false);
    expect(permissionDenied.error.code).toBe("KEY_NOT_FOUND");
    expect(await state(ctx)).toEqual(initial);
    const accepted = await foreign.getSession({
      fetchOptions: { headers: { "x-api-key": quota.key } },
    });
    expect(accepted.error).toBeNull();
    expect(accepted.data!.user.id).toBe(ownerId);
    expect(accepted.data!.session.userId).toBe(ownerId);
    expect(accepted.data!.session.id).toBe(quota.id);
    expect(accepted.data!.session.token).toBe(quota.key);
    const afterUse = await state(ctx);
    expect(row(afterUse, quota).remaining).toBe(3);
    expect(row(afterUse, quota).requestCount).toBe(0);
    expect(row(afterUse, foreignKey)).toEqual(row(initial, foreignKey));
    await control(ctx, "mode", { mode: "unicode" });
    const unicode = object(
      await control(ctx, "create", {
        userId: foreignId,
        configId: "plaintext",
        name: "d-unicode",
      }),
    );
    expect(unicode.key).toBe("😀abcdefghijklmnop");
    expect(unicode.start).toBe("😀");
    expect(unicode.prefix).toBe("raw_");
    expect(unicode.permissions).toEqual(defaults("plaintext", "foreign"));
    const unicodeEvents = await events(ctx);
    generatedEvents(unicodeEvents, unicode, false, 31, "raw_", "unicode");
    const unicodeState = await state(ctx);
    expect(row(unicodeState, unicode).key).toBe(unicode.key);
    expect(row(unicodeState, unicode).start).toBe("😀");
    const updated = object(
      await control(ctx, "update", {
        userId: foreignId,
        keyId: unicode.id,
        configId: "plaintext",
        permissions: Object.fromEntries([
          ["zeta", ["read"]],
          ["2", ["two"]],
          ["alpha", ["write"]],
        ]),
      }),
    );
    expect(updated.permissions).toEqual({
      "2": ["two"],
      zeta: ["read"],
      alpha: ["write"],
    });
    const updatedState = await state(ctx);
    expect(row(updatedState, unicode).permissions).toBe(
      '{"2":["two"],"zeta":["read"],"alpha":["write"]}',
    );
    expect(await events(ctx)).toEqual([]);
    const literal = object(
      await control(ctx, "update", {
        userId: foreignId,
        keyId: unicode.id,
        configId: "plaintext",
        permissions: { "$serde_json::private::RawValue": ["literal"] },
      }),
    );
    expect(literal.permissions).toEqual({
      "$serde_json::private::RawValue": ["literal"],
    });
    const readback = await foreign.apiKey.get({
      query: { id: unicode.id, configId: "plaintext" },
    });
    expect(readback.error).toBeNull();
    expect(readback.data!.permissions).toEqual(literal.permissions);
    const final = await state(ctx);
    expect(row(final, unicode).permissions).toBe('{"$serde_json::private::RawValue":["literal"]}');
    await control(ctx, "mode", { mode: "normal" });
    const staticKey = await owner.apiKey.create({
      configId: "static",
      name: "e-static",
    });
    expect(staticKey.error).toBeNull();
    expect(staticKey.data!.permissions).toEqual({
      zeta: ["read"],
      alpha: ["write"],
    });
    const staticState = await state(ctx);
    expect(row(staticState, object(staticKey.data)).permissions).toBe(
      '{"zeta":["read"],"alpha":["write"]}',
    );
    expect(await events(ctx)).toEqual([
      { kind: "generator", length: 64, prefix: null, mode: "normal" },
    ]);
    return ctx.snapshot({
      issued,
      issuedEvents,
      foreignIssued,
      foreignEvents,
      deniedRead,
      quota,
      overrideEvents,
      initial,
      permissionDenied,
      accepted,
      afterUse,
      unicode,
      unicodeEvents,
      unicodeState,
      updated,
      updatedState,
      literal,
      readback,
      final,
      staticKey,
      staticState,
    });
  },
  ["POST /api-key/create", "GET /get-session"],
);

compatScenario(
  "api-key creation rejects client authority before callbacks and preserves deliberate callback errors without secret writes",
  async (ctx) => {
    const { owner, foreign, ownerId, foreignId } = await setup(ctx);
    const before = await state(ctx);
    const results = [];
    for (const input of [
      { userId: foreignId },
      { permissions: { vault: ["admin"] } },
      { remaining: 100 },
    ]) {
      const result = await owner.apiKey.create({
        configId: "generated",
        name: "overposted",
        ...input,
      } as any);
      expect(result.error?.code).toBe(
        "userId" in input ? "UNAUTHORIZED_SESSION" : "SERVER_ONLY_PROPERTY",
      );
      expect(await events(ctx)).toEqual([]);
      expect(await state(ctx)).toEqual(before);
      results.push(result);
    }
    const anonymous = client(ctx, "anonymous");
    const unauthenticated = await anonymous.apiKey.create({
      configId: "generated",
      name: "anonymous",
    });
    expect(unauthenticated.error?.status).toBe(401);
    expect(await events(ctx)).toEqual([]);
    expect(await state(ctx)).toEqual(before);
    for (const mode of [
      "generator-api",
      "generator-throw",
      "generator-public-500",
      "permissions-api",
      "permissions-throw",
    ]) {
      await control(ctx, "mode", { mode });
      const result = await owner.apiKey.create({
        configId: "generated",
        name: mode,
      });
      expect(result.error?.status).toBe(mode.endsWith("api") ? 403 : 500);
      if (mode === "generator-public-500")
        expect(result.error).toMatchObject({
          code: "APPLICATION_GENERATION_DENIED",
          message: "Application generation denied",
        });
      if (mode.endsWith("api"))
        expect(result.error).toMatchObject({
          code: mode.startsWith("generator") ? "GENERATOR_DENIED" : "PERMISSIONS_DENIED",
          message: mode.startsWith("generator")
            ? "Application generator denied"
            : "Application permissions denied",
        });
      const observed = await events(ctx);
      expect(observed).toHaveLength(mode.startsWith("generator") ? 1 : 2);
      expect(observed[0]).toEqual({
        kind: "generator",
        length: 24,
        prefix: "app_",
        mode,
      });
      if (observed[1])
        expect(observed[1]).toEqual({
          kind: "permissions",
          configurationId: "generated",
          reference: { userId: ownerId },
          requestPresent: true,
          explicit: null,
          mode,
        });
      expect(await state(ctx)).toEqual(before);
      results.push({ mode, result, events: observed });
    }
    await control(ctx, "mode", { mode: "permissions-api" });
    const failedOverride = await ctx.rawRequest({
      path: "/__test/api-key-generation/create",
      method: "POST",
      json: {
        userId: ownerId,
        configId: "generated",
        name: "failed-override",
        permissions: { vault: ["read"] },
      },
    });
    expect(failedOverride.status).toBe(500);
    const failedOverrideEvents = await events(ctx);
    expect(failedOverrideEvents).toEqual([
      {
        kind: "generator",
        length: 24,
        prefix: "app_",
        mode: "permissions-api",
      },
      {
        kind: "permissions",
        configurationId: "generated",
        reference: { userId: ownerId },
        requestPresent: false,
        explicit: null,
        mode: "permissions-api",
      },
    ]);
    expect(await state(ctx)).toEqual(before);
    results.push({ failedOverride, events: failedOverrideEvents });
    await control(ctx, "mode", { mode: "normal" });
    const retry = await owner.apiKey.create({
      configId: "generated",
      name: "retry",
    });
    expect(retry.error).toBeNull();
    expect(retry.data!.referenceId).toBe(ownerId);
    expect(retry.data!.key).toMatch(/^app_generated-owned-secret-\d+$/);
    expect((await foreign.getSession()).data!.user.id).toBe(foreignId);
    const retryEvents = await events(ctx);
    generatedEvents(retryEvents, object(retry.data), true);
    const after = await state(ctx);
    expect(after).toHaveLength(1);
    expect(row(after, object(retry.data)).referenceId).toBe(ownerId);
    return ctx.snapshot({
      before,
      results,
      unauthenticated,
      retry,
      retryEvents,
      after,
    });
  },
  ["POST /api-key/create"],
);

compatScenario(
  "api-key forced expiration cleanup crosses owners and configurations without exposing a public cleanup route",
  async (ctx) => {
    const { owner, foreign, ownerId, foreignId } = await setup(ctx);
    const keys = [];
    for (const [userId, configId, name, expiresIn] of [
      [ownerId, "generated", "a-expired", 60],
      [foreignId, "plaintext", "b-expired", 60],
      [ownerId, "generated", "c-live", 3600],
      [foreignId, "plaintext", "d-unlimited", null],
    ] as const) {
      const key = object(
        await control(ctx, "create", {
          userId,
          configId,
          name,
          expiresIn,
          remaining: 5,
        }),
      );
      expect(key.referenceId).toBe(userId);
      expect(key.configId).toBe(configId);
      keys.push(key);
    }
    const callbackEvents = await events(ctx);
    const initial = await state(ctx);
    expect(initial).toHaveLength(4);
    for (const key of keys.slice(0, 2)) await control(ctx, "expire", { keyId: key.id });
    const expired = await state(ctx);
    expect(row(expired, keys[0]!).expiresAt).toBe("1970-01-01T00:00:00.000Z");
    expect(row(expired, keys[1]!).expiresAt).toBe("1970-01-01T00:00:00.000Z");
    const cleanupStarted = Date.now();
    const firstCleanup = await control(ctx, "cleanup", {});
    expect(firstCleanup).toEqual({ success: true, error: null });
    expect(callbackEvents).toHaveLength(8);
    const cleaned = await state(ctx);
    expect(cleaned).toHaveLength(2);
    expect(cleaned.map((row) => row.id)).toEqual(keys.slice(2).map((key) => key.id));
    expect(row(cleaned, keys[2]!)).toEqual(row(expired, keys[2]!));
    expect(row(cleaned, keys[3]!)).toEqual(row(expired, keys[3]!));
    const missing = await owner.apiKey.get({
      query: { id: keys[0]!.id, configId: "generated" },
    });
    expect(missing.error?.code).toBe("KEY_NOT_FOUND");
    const foreignMissing = await foreign.apiKey.get({
      query: { id: keys[1]!.id, configId: "plaintext" },
    });
    expect(foreignMissing.error?.code).toBe("KEY_NOT_FOUND");
    const invalid = object(
      await control(ctx, "verify", {
        key: keys[0]!.key,
        configId: "generated",
      }),
    );
    expect(invalid.valid).toBe(false);
    expect(invalid.error.code).toBe("INVALID_API_KEY");
    await control(ctx, "expire", { keyId: keys[2]!.id });
    const beforeSecond = await state(ctx);
    expect(beforeSecond).toHaveLength(2);
    const started = Date.now();
    const secondCleanup = await control(ctx, "cleanup", {});
    expect(Date.now() - started).toBeLessThan(10000);
    expect(Date.now() - cleanupStarted).toBeLessThan(10000);
    expect(secondCleanup).toEqual({ success: true, error: null });
    const final = await state(ctx);
    expect(final).toHaveLength(1);
    expect(final[0]).toEqual(row(cleaned, keys[3]!));
    expect(await events(ctx)).toEqual([]);
    const publicCleanup = await ctx.rawRequest({
      actor: "owner",
      path: `${authProfilePath("api-key-generation")}/api-key/delete-all-expired-api-keys`,
      method: "POST",
      json: {},
    });
    expect(publicCleanup.status).toBe(404);
    expect(await state(ctx)).toEqual(final);
    return ctx.snapshot({
      keys,
      callbackEvents,
      initial,
      expired,
      firstCleanup,
      cleaned,
      missing,
      foreignMissing,
      invalid,
      beforeSecond,
      secondCleanup,
      final,
      publicCleanup,
    });
  },
);
