import { expect } from "bun:test";
import { apiKeyClient } from "@better-auth/api-key/client";
import { createAuthClient } from "better-auth/client";
import { compatScenario, type ScenarioContext } from "../../support/scenario";

type RecordValue = Record<string, any>;
function object(value: unknown): RecordValue {
  expect(value).toBeObject();
  return value as RecordValue;
}
function client(ctx: ScenarioContext, name: string) {
  return createAuthClient({
    baseURL: `${ctx.baseURL}/api/auth`,
    plugins: [apiKeyClient()],
    fetchOptions: { customFetchImpl: ctx.actor(name, "api-key-hooks").fetch },
  });
}
async function setup(ctx: ScenarioContext) {
  const owner = client(ctx, "owner");
  const outsider = client(ctx, "outsider");
  const users = [];
  for (const [name, auth] of [
    ["owner", owner],
    ["outsider", outsider],
  ] as const) {
    const signup = await auth.signUp.email({
      email: ctx.uniqueEmail(`key-hooks-${name}`),
      password: "password123",
      name,
    });
    expect(signup.error).toBeNull();
    users.push(signup.data!.user);
  }
  return { owner, outsider, ownerId: users[0]!.id, outsiderId: users[1]!.id };
}
async function control(ctx: ScenarioContext, path: string, json?: unknown, headers?: HeadersInit) {
  const response = await ctx.rawRequest({
    path: `/__test/api-key-hook/${path}`,
    method: json === undefined ? "GET" : "POST",
    json,
    headers,
  });
  expect(response.status).toBe(200);
  return response.body;
}
async function create(
  ctx: ScenarioContext,
  ownerId: string,
  name: string,
  options: RecordValue = {},
) {
  const key = object(
    await control(ctx, "create", {
      userId: ownerId,
      configId: "hooks",
      prefix: "red_",
      name,
      remaining: 10,
      rateLimitEnabled: false,
      ...options,
    }),
  );
  expect(key.referenceId).toBe(ownerId);
  expect(key.key).toBeString();
  expect(key.remaining).toBe(10);
  return key;
}
async function events(ctx: ScenarioContext) {
  const value = await control(ctx, "events");
  expect(value).toBeArray();
  return value as RecordValue[];
}
async function state(ctx: ScenarioContext, ownerId: string) {
  return object(await control(ctx, `state?userId=${ownerId}`));
}
function stored(state: RecordValue, key: RecordValue) {
  const row = state.keys.find((row: RecordValue) => row.id === key.id);
  expect(row).toBeDefined();
  expect(row.referenceId).toBe(key.referenceId);
  expect(row.configId).toBe(key.configId);
  return row;
}
function getter(provided: boolean) {
  return { kind: "getter", configurationId: "hooks", provided };
}
function validator(key: RecordValue, policy: string) {
  return {
    kind: "validator",
    configurationId: "hooks",
    policy,
    keyLength: key.key.length,
    prefix: key.key.startsWith("red_") ? "red_" : "other",
  };
}

compatScenario(
  "api-key custom getter replaces headers and validator binds the request owner before usage",
  async (ctx) => {
    const { outsider, ownerId, outsiderId } = await setup(ctx);
    const red = await create(ctx, ownerId, "red");
    const blue = await create(ctx, ownerId, "blue", { prefix: "blue_" });
    const other = await create(ctx, outsiderId, "other", { configId: "other" });
    const before = await state(ctx, ownerId);
    expect(before.sessions.count).toBe(1);
    expect((await state(ctx, outsiderId)).sessions.count).toBe(1);
    await events(ctx);
    const results: unknown[] = [];
    for (const headers of [
      { "x-api-key": red.key },
      { "x-api-key": red.key, "x-custom-api-key": "ApiKey " },
    ]) {
      const response = await outsider.getSession({ fetchOptions: { headers } });
      expect(response.error).toBeNull();
      expect(response.data!.user.id).toBe(outsiderId);
      const observed = await events(ctx);
      expect(observed).toEqual([getter(false)]);
      results.push({ response, events: observed });
    }
    for (const [key, policy] of [
      [red, "deny"],
      [blue, "red-only"],
    ] as const) {
      const response = await outsider.getSession({
        fetchOptions: {
          headers: {
            "x-custom-api-key": `ApiKey ${key.key}`,
            "x-key-policy": policy,
          },
        },
      });
      expect(response.error!.status).toBe(403);
      expect(response.error!.code).toBe("INVALID_API_KEY");
      const observed = await events(ctx);
      expect(observed).toEqual([getter(true), getter(true), validator(key, policy)]);
      results.push({ response, events: observed });
    }
    const short = await outsider.getSession({
      fetchOptions: { headers: { "x-custom-api-key": "ApiKey no" } },
    });
    expect(short.error!.status).toBe(403);
    expect(short.error!.code).toBe("INVALID_API_KEY");
    const shortEvents = await events(ctx);
    expect(shortEvents).toEqual([getter(true), getter(true)]);
    results.push({ response: short, events: shortEvents });
    const wrongConfig = await outsider.getSession({
      fetchOptions: { headers: { "x-custom-api-key": `ApiKey ${other.key}` } },
    });
    expect(wrongConfig.error!.status).toBe(401);
    expect(wrongConfig.error!.code).toBe("INVALID_API_KEY");
    const wrongEvents = await events(ctx);
    expect(wrongEvents).toEqual([getter(true), getter(true), validator(other, "allow")]);
    results.push({ response: wrongConfig, events: wrongEvents });
    const rejectedState = await state(ctx, ownerId);
    expect(rejectedState).toEqual(before);
    const accepted = await outsider.getSession({
      fetchOptions: {
        headers: {
          "x-custom-api-key": `ApiKey ${red.key}`,
          "x-key-policy": "red-only",
        },
      },
    });
    expect(accepted.error).toBeNull();
    expect(accepted.data!.user.id).toBe(ownerId);
    expect(accepted.data!.session.userId).toBe(ownerId);
    expect(accepted.data!.session.id).toBe(red.id);
    expect(accepted.data!.session.token).toBe(red.key);
    const acceptedEvents = await events(ctx);
    expect(acceptedEvents).toEqual([getter(true), getter(true), validator(red, "red-only")]);
    const protectedOwner = await outsider.apiKey.get({
      query: { id: red.id, configId: "hooks" },
      fetchOptions: { headers: { "x-custom-api-key": `ApiKey ${red.key}` } },
    });
    expect(protectedOwner.error).toBeNull();
    expect(protectedOwner.data!.referenceId).toBe(ownerId);
    expect(protectedOwner.data!.id).toBe(red.id);
    const protectedEvents = await events(ctx);
    expect(protectedEvents).toEqual([getter(true), getter(true), validator(red, "allow")]);
    const forbidden = await outsider.apiKey.get({
      query: { id: red.id, configId: "hooks" },
    });
    expect(forbidden.error!.status).toBe(404);
    expect(forbidden.error!.code).toBe("KEY_NOT_FOUND");
    const forbiddenEvents = await events(ctx);
    expect(forbiddenEvents).toEqual([]);
    const cookieOwner = await outsider.getSession();
    expect(cookieOwner.data!.user.id).toBe(outsiderId);
    expect(await events(ctx)).toEqual([getter(false)]);
    const after = await state(ctx, ownerId);
    expect(after.sessions.count).toBe(before.sessions.count);
    expect((await state(ctx, outsiderId)).sessions.count).toBe(1);
    expect(stored(after, red).remaining).toBe(8);
    expect(stored(after, blue).remaining).toBe(10);
    expect(stored(after, other).remaining).toBe(10);
    expect(stored(after, red).requestCount).toBe(0);
    return {
      keys: [red, blue, other],
      before,
      rejectedState,
      results,
      accepted,
      acceptedEvents,
      protectedOwner,
      protectedEvents,
      forbidden,
      forbiddenEvents,
      cookieOwner,
      after,
    };
  },
  ["GET /get-session", "GET /api-key/get"],
);

compatScenario(
  "api-key server validators resolve issuing configuration and preserve explicit rejection errors",
  async (ctx) => {
    const { ownerId, outsiderId } = await setup(ctx);
    const key = await create(ctx, ownerId, "hook");
    const other = await create(ctx, outsiderId, "other", { configId: "other" });
    const disabled = await create(ctx, ownerId, "disabled");
    const updated = await control(ctx, "update", {
      userId: ownerId,
      keyId: disabled.id,
      configId: "hooks",
      enabled: false,
    });
    const before = await state(ctx, ownerId);
    await events(ctx);
    const attempts: unknown[] = [];
    async function verify(keyValue: RecordValue, policy: string, explicit?: string) {
      const body = object(
        await control(
          ctx,
          "verify",
          {
            key: keyValue.key,
            ...(explicit === undefined ? {} : { configId: explicit }),
          },
          { "x-key-policy": policy },
        ),
      );
      const observed = await events(ctx);
      attempts.push({ body, events: observed });
      return { body, observed };
    }
    const explicit = await verify(key, "deny", "hooks");
    expect(explicit.body).toEqual({
      valid: false,
      error: {
        code: "KEY_NOT_FOUND",
        message: { code: "INVALID_API_KEY", message: "Invalid API key." },
      },
      key: null,
    });
    expect(explicit.observed).toEqual([validator(key, "deny")]);
    const implicit = await verify(key, "deny");
    expect(implicit.body).toEqual({
      valid: false,
      error: { code: "KEY_NOT_FOUND", message: "API Key not found" },
      key: null,
    });
    expect(implicit.observed).toEqual([validator(key, "deny")]);
    const unknown = { key: "red_unknown-key-with-enough-characters" };
    const unknownImplicit = await verify(unknown, "deny");
    expect(unknownImplicit.body.error.code).toBe("INVALID_API_KEY");
    expect(unknownImplicit.observed).toEqual([]);
    const unknownExplicit = await verify(unknown, "deny", "hooks");
    expect(unknownExplicit.body).toEqual(explicit.body);
    expect(unknownExplicit.observed).toEqual([validator(unknown, "deny")]);
    const wrong = await verify(key, "allow", "other");
    expect(wrong.body.error.code).toBe("INVALID_API_KEY");
    expect(wrong.observed).toEqual([]);
    const disabledDenied = await verify(disabled, "deny");
    expect(disabledDenied.body).toEqual(implicit.body);
    expect(disabledDenied.observed).toEqual([validator(disabled, "deny")]);
    const disabledAllowed = await verify(disabled, "allow");
    expect(disabledAllowed.body.error.code).toBe("KEY_DISABLED");
    expect(disabledAllowed.observed).toEqual([validator(disabled, "allow")]);
    const rejectedState = await state(ctx, ownerId);
    expect(rejectedState).toEqual(before);
    const otherAccepted = await verify(other, "deny");
    expect(otherAccepted.body.valid).toBe(true);
    expect(otherAccepted.body.key.referenceId).toBe(outsiderId);
    expect(otherAccepted.observed).toEqual([]);
    for (const configId of ["hooks", undefined]) {
      const accepted = await verify(key, "red-only", configId);
      expect(accepted.body.valid).toBe(true);
      expect(accepted.body.key.referenceId).toBe(ownerId);
      expect(accepted.body.key.id).toBe(key.id);
      expect(accepted.body.key.key).toBeUndefined();
      expect(accepted.observed).toEqual([validator(key, "red-only")]);
    }
    const after = await state(ctx, ownerId);
    expect(stored(after, key).remaining).toBe(8);
    expect(stored(after, key).requestCount).toBe(0);
    expect(stored(after, other).remaining).toBe(9);
    expect(stored(after, other).requestCount).toBe(0);
    expect(stored(after, disabled).remaining).toBe(10);
    expect(stored(after, disabled).enabled).toBe(false);
    expect(after.sessions.count).toBe(before.sessions.count);
    return {
      keys: [key, other, disabled],
      updated,
      before,
      rejectedState,
      attempts,
      after,
    };
  },
);
