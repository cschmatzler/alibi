import { expect } from "bun:test";
import { createHash } from "node:crypto";

import { apiKeyClient } from "@better-auth/api-key/client";
import { createAuthClient } from "better-auth/client";

import { authProfilePath } from "../../../support/profiles";
import { compatScenario, type ScenarioContext } from "../../../support/scenario";

type Data = Record<string, any>;

function object(value: unknown): Data {
  expect(value).toBeObject();
  return value as Data;
}

function client(ctx: ScenarioContext, actor: string, responses: Data[]) {
  return createAuthClient({
    baseURL: `${ctx.baseURL}${authProfilePath("api-key-options")}`,
    plugins: [apiKeyClient()],
    fetchOptions: {
      customFetchImpl: async (input, init) => {
        const response = await ctx.actor(actor, "api-key-options").fetch(input, init);
        const text = await response.clone().text();
        let body: unknown = text || null;

        try {
          body = text ? JSON.parse(text) : null;
        } catch {}

        responses.push({ status: response.status, body });
        return response;
      },
    },
  });
}

async function control(
  ctx: ScenarioContext,
  action: string,
  json?: unknown,
  headers?: Record<string, string>,
) {
  const response = await ctx.rawRequest({
    path: `/__test/api-key-options/${action}`,
    method: json === undefined ? "GET" : "POST",
    json,
    headers,
  });
  expect(response.status).toBe(200);
  return response.body;
}

async function events(ctx: ScenarioContext) {
  return (await control(ctx, "events")) as Data[];
}

async function state(ctx: ScenarioContext) {
  return object(await control(ctx, "state"));
}

function row(snapshot: Data, key: Data) {
  const stored = snapshot.keys.find((entry: Data) => entry.id === key.id);
  expect(stored).toBeDefined();
  return stored as Data;
}

function hash(key: string) {
  return createHash("sha256").update(key).digest("base64url");
}

async function setup(ctx: ScenarioContext) {
  await control(ctx, "mode", { mode: "normal", reset: true });
  const ownerResponses: Data[] = [];
  const foreignResponses: Data[] = [];
  const owner = client(ctx, "owner", ownerResponses);
  const foreign = client(ctx, "foreign", foreignResponses);
  const signup = await owner.signUp.email({
    email: ctx.uniqueEmail("options-owner"),
    password: "password123",
    name: "Options Owner",
  });
  const other = await foreign.signUp.email({
    email: ctx.uniqueEmail("options-foreign"),
    password: "password123",
    name: "Options Foreign",
  });
  expect(signup.error).toBeNull();
  expect(other.error).toBeNull();

  const guard = await foreign.apiKey.create({
    configId: "default",
    name: "foreign-guard",
    metadata: { authority: "foreign" },
  });
  expect(guard.error).toBeNull();

  const foreignKey = object(guard.data);
  const initial = await state(ctx);
  const ownerState = await ctx.readUserState({ userId: signup.data!.user.id });
  const foreignState = await ctx.readUserState({ userId: other.data!.user.id });
  expect(await events(ctx)).toEqual([]);

  return {
    owner,
    foreign,
    ownerResponses,
    foreignResponses,
    ownerId: signup.data!.user.id,
    foreignId: other.data!.user.id,
    foreignKey,
    initial,
    ownerState,
    foreignState,
    signup: ctx.snapshot(signup),
    other: ctx.snapshot(other),
    guard: ctx.snapshot(guard),
  };
}

async function authority(ctx: ScenarioContext, ownerSetup: Awaited<ReturnType<typeof setup>>) {
  const after = await state(ctx);
  expect(row(after, ownerSetup.foreignKey)).toEqual(row(ownerSetup.initial, ownerSetup.foreignKey));
  expect(await ctx.readUserState({ userId: ownerSetup.ownerId })).toEqual(ownerSetup.ownerState);
  expect(await ctx.readUserState({ userId: ownerSetup.foreignId })).toEqual(
    ownerSetup.foreignState,
  );

  return {
    after,
    ownerResponses: ownerSetup.ownerResponses,
    foreignResponses: ownerSetup.foreignResponses,
    owner: await ctx.readUserState({ userId: ownerSetup.ownerId }),
    foreign: await ctx.readUserState({ userId: ownerSetup.foreignId }),
  };
}

async function trustedCreate(ctx: ScenarioContext, input: Data) {
  const result = object(await control(ctx, "create", input));
  expect(result.error).toBeNull();
  return { result, key: object(result.value) };
}

async function verify(ctx: ScenarioContext, input: Data, request = false) {
  return object(
    await control(
      ctx,
      "verify",
      { input, request },
      request ? { "x-options-marker": "actual-request" } : undefined,
    ),
  );
}

compatScenario(
  "api-key raw numeric generation options preserve safe fractional nonfinite and rejected write phases",
  async (ctx) => {
    const s = await setup(ctx);
    const observations: Data[] = [];

    for (const [configId, length] of [
      ["length-half", 1],
      ["length-fraction", 3],
      ["length-zero", 64],
      ["length-nan", 64],
      ["length-large-fraction", 32769],
    ] as const) {
      const issued = await s.owner.apiKey.create({
        configId,
        name: configId,
        metadata: { numeric: configId },
      });
      expect(issued.error).toBeNull();

      const key = object(issued.data);
      expect(key.key).toMatch(/^optKEY_[A-Za-z]+$/);
      expect(key.key.substring(7).length).toBe(length);
      expect(key.referenceId).toBe(s.ownerId);
      expect(key.configId).toBe(configId);

      const persisted = await state(ctx);
      expect(row(persisted, key).key).toBe(hash(key.key));
      expect(row(persisted, key).prefix).toBe("optKEY_");
      expect(row(persisted, key).startHex).toBe("6F70744B4559");
      expect(row(persisted, key).startType).toBe("text");

      const callback = await events(ctx);
      expect(callback).toEqual([]);

      observations.push({ configId, issued: ctx.snapshot(issued), persisted, callback });
    }

    for (const configId of ["length-negative", "length-negative-inf"]) {
      const before = await state(ctx);
      const denied = await s.owner.apiKey.create({ configId, name: configId });
      expect(s.ownerResponses.at(-1)).toEqual({ status: 500, body: null });

      const after = await state(ctx);
      expect(after).toEqual(before);

      const callback = await events(ctx);
      expect(callback).toEqual([]);

      observations.push({ configId, before, denied: ctx.snapshot(denied), after, callback });
    }

    for (const [configId, value, text] of [
      ["custom-quarter", 0.25, "0.25"],
      ["custom-inf", null, "Infinity"],
      ["custom-negative-inf", null, "-Infinity"],
      ["custom-nan", 64, "64"],
    ] as const) {
      const issued = await s.owner.apiKey.create({ configId, name: configId });
      expect(issued.error).toBeNull();

      const key = object(issued.data);
      const callback = await events(ctx);
      const persisted = await state(ctx);
      expect(callback).toEqual([
        { kind: "generator", configId, length: { value, text }, prefix: "optKEY_", mode: "normal" },
      ]);
      expect(key.key).toMatch(/^optKEY_application-owned-secret-\d{6}$/);
      expect(row(persisted, key).key).toBe(hash(key.key));

      observations.push({ configId, issued: ctx.snapshot(issued), callback, persisted });
    }

    return {
      signup: s.signup,
      other: s.other,
      guard: s.guard,
      initial: s.initial,
      ownerState: s.ownerState,
      foreignState: s.foreignState,
      observations,
      authority: await authority(ctx, s),
    };
  },
  ["POST /api-key/create"],
);

compatScenario(
  "api-key numeric default expiry and fractional policy retain callback input and complete failure state",
  async (ctx) => {
    const s = await setup(ctx);
    const observations: Data[] = [];

    for (const configId of [
      "expiration-fraction",
      "expiration-zero",
      "expiration-nan",
      "empty-prefix",
    ]) {
      const created = await s.owner.apiKey.create({ configId, name: configId });
      expect(created.error).toBeNull();

      const key = object(created.data);
      const persisted = await state(ctx);
      const callback = await events(ctx);

      if (configId === "expiration-fraction") {
        expect(new Date(key.expiresAt).getTime() - new Date(key.createdAt).getTime()).toBeWithin(
          60100,
          60175,
        );
      } else {
        expect(key.expiresAt).toBeNull();
      }

      const prefix = configId === "empty-prefix" ? "" : "optKEY_";
      expect(callback).toEqual([
        { kind: "generator", configId, length: { value: 16, text: "16" }, prefix, mode: "normal" },
      ]);
      expect(row(persisted, key).key).toBe(hash(key.key));
      expect(row(persisted, key).prefix).toBe(prefix);

      observations.push({ configId, created: ctx.snapshot(created), persisted, callback });
    }

    for (const configId of ["expiration-inf", "expiration-negative-inf"]) {
      const before = await state(ctx);
      const denied = await s.owner.apiKey.create({ configId, name: configId });
      expect(s.ownerResponses.at(-1)).toEqual({ status: 500, body: null });

      const after = await state(ctx);
      const callback = await events(ctx);
      expect(after).toEqual(before);
      expect(callback).toEqual([
        {
          kind: "generator",
          configId,
          length: { value: 16, text: "16" },
          prefix: "optKEY_",
          mode: "normal",
        },
      ]);

      observations.push({ configId, before, denied: ctx.snapshot(denied), after, callback });
    }

    const rejected = [
      { configId: "policy-fraction", prefix: "a", name: "ab", expiresIn: 2 },
      { configId: "policy-fraction", prefix: "abc", name: "ab", expiresIn: 2 },
      { configId: "policy-fraction", prefix: "ab", name: "a", expiresIn: 2 },
      { configId: "policy-fraction", prefix: "ab", name: "abcd", expiresIn: 2 },
      { configId: "policy-fraction", prefix: "ab", name: "ab", expiresIn: 1 },
      { configId: "policy-fraction", prefix: "ab", name: "ab", expiresIn: 4 },
      { configId: "policy-inf", prefix: "ab", name: "ab" },
      { configId: "policy-fraction", prefix: "😀", name: "ab", expiresIn: 2 },
    ];

    for (const input of rejected) {
      const before = await state(ctx);
      const denied = await s.owner.apiKey.create(input);
      expect(denied.error?.status).toBe(400);

      const after = await state(ctx);
      const callback = await events(ctx);
      expect(after).toEqual(before);
      expect(callback).toEqual([]);

      observations.push({ input, before, denied: ctx.snapshot(denied), after, callback });
    }

    for (const input of [
      { configId: "policy-fraction", prefix: "ab", name: "😀", expiresIn: 2 },
      { configId: "policy-nan", prefix: "long_".repeat(8), name: "long".repeat(10), expiresIn: 60 },
    ]) {
      const created = await s.owner.apiKey.create(input);
      expect(created.error).toBeNull();

      const key = object(created.data);
      const persisted = await state(ctx);
      const callback = await events(ctx);
      expect(key.name).toBe(input.name);
      expect(key.prefix).toBe(input.prefix);
      expect(row(persisted, key).key).toBe(hash(key.key));
      expect(callback).toEqual([
        {
          kind: "generator",
          configId: input.configId,
          length: { value: 16, text: "16" },
          prefix: input.prefix,
          mode: "normal",
        },
      ]);

      observations.push({ input, created: ctx.snapshot(created), persisted, callback });
    }

    const negative = await s.owner.apiKey.create({
      configId: "expiration-negative",
      name: "expired",
    });
    expect(negative.error).toBeNull();

    const expired = object(negative.data);
    const negativeState = await state(ctx);
    const negativeEvents = await events(ctx);
    expect(
      new Date(expired.expiresAt).getTime() - new Date(expired.createdAt).getTime(),
    ).toBeWithin(-3600150, -3600100);
    expect(row(negativeState, expired).key).toBe(hash(expired.key));

    const deniedExpired = await verify(ctx, { key: expired.key, configId: "expiration-negative" });
    expect(deniedExpired.value.valid).toBe(false);
    expect(deniedExpired.value.error.code).toBe("KEY_EXPIRED");

    const afterExpiry = await state(ctx);
    observations.push({
      negative: ctx.snapshot(negative),
      negativeState,
      negativeEvents,
      deniedExpired,
      afterExpiry,
    });
    return {
      signup: s.signup,
      other: s.other,
      guard: s.guard,
      initial: s.initial,
      observations,
      authority: await authority(ctx, s),
    };
  },
  ["POST /api-key/create"],
);

compatScenario(
  "api-key UTF16 starting characters preserve actual SQLite TEXT bytes across public reads updates and verification",
  async (ctx) => {
    const s = await setup(ctx);
    const observations: Data[] = [];

    for (const configId of [
      "start-half",
      "start-one",
      "start-fraction",
      "start-all",
      "start-negative",
      "start-nan",
      "start-negative-inf",
      "start-disabled",
      "plaintext",
    ]) {
      const created = await s.owner.apiKey.create({
        configId,
        name: configId,
        metadata: { start: configId },
      });
      expect(created.error).toBeNull();

      const key = object(created.data);
      const initial = await state(ctx);
      const stored = row(initial, key);
      const callback = await events(ctx);
      const split = ["start-one", "start-fraction", "plaintext"].includes(configId);
      const all = configId === "start-all";
      const disabled = configId === "start-disabled";
      const start = split ? "���" : all ? key.key : disabled ? null : "";
      expect(key.start).toBe(start);
      expect(stored.start).toBe(start);
      expect(stored.startHex).toBe(
        split ? "EDA0BD" : all ? Buffer.from(key.key).toString("hex").toUpperCase() : "",
      );
      expect(stored.startType).toBe(disabled ? "null" : "text");
      expect(stored.key).toBe(configId === "plaintext" ? key.key : hash(key.key));
      expect(stored.referenceId).toBe(s.ownerId);
      expect(stored.configId).toBe(configId);

      const read = await s.owner.apiKey.get({ query: { id: key.id, configId } });
      expect(read.error).toBeNull();
      expect(read.data!.start).toBe(start);

      const list = await s.owner.apiKey.list({ query: { configId } });
      expect(list.error).toBeNull();
      expect(
        (list.data as any).apiKeys.find((candidate: Data) => candidate.id === key.id).start,
      ).toBe(start);

      const foreignRead = await s.foreign.apiKey.get({ query: { id: key.id, configId } });
      expect(foreignRead.error?.code).toBe("KEY_NOT_FOUND");
      expect(foreignRead.error?.status).toBe(404);

      const foreignUpdate = await s.foreign.apiKey.update({
        keyId: key.id,
        configId,
        name: "stolen",
      });
      expect(foreignUpdate.error?.code).toBe("KEY_NOT_FOUND");
      expect(foreignUpdate.error?.status).toBe(404);
      expect(await state(ctx)).toEqual(initial);

      const changed = await s.owner.apiKey.update({
        keyId: key.id,
        configId,
        name: `${configId}-updated`,
      });
      expect(changed.error).toBeNull();
      expect(changed.data!.start).toBe(start);

      const afterUpdate = await state(ctx);
      expect(row(afterUpdate, key).startHex).toBe(stored.startHex);
      expect(row(afterUpdate, key).startType).toBe(stored.startType);

      const verified = await verify(ctx, { key: key.key, configId });
      expect(verified.error).toBeNull();
      expect(verified.value.valid).toBe(true);
      expect(verified.value.key.start).toBe(start);

      const afterVerify = await state(ctx);
      expect(row(afterVerify, key).startHex).toBe(stored.startHex);
      expect(row(afterVerify, key).startType).toBe(stored.startType);

      const wrongConfig = await verify(ctx, { key: key.key, configId: "default" });
      expect(wrongConfig.value.valid).toBe(false);
      expect(wrongConfig.value.error.code).toBe("INVALID_API_KEY");
      expect(await state(ctx)).toEqual(afterVerify);

      observations.push({
        configId,
        created: ctx.snapshot(created),
        initial,
        callback,
        read: ctx.snapshot(read),
        list: ctx.snapshot(list),
        foreignRead: ctx.snapshot(foreignRead),
        foreignUpdate: ctx.snapshot(foreignUpdate),
        changed: ctx.snapshot(changed),
        afterUpdate,
        verified,
        afterVerify,
        wrongConfig,
      });
    }

    return {
      signup: s.signup,
      other: s.other,
      guard: s.guard,
      initial: s.initial,
      observations,
      authority: await authority(ctx, s),
    };
  },
  ["POST /api-key/create", "POST /api-key/update"],
);

compatScenario(
  "api-key installed permission shapes retain Source authorization decisions exact quota phases and foreign authority",
  async (ctx) => {
    const s = await setup(ctx);
    const issued = await trustedCreate(ctx, {
      userId: s.ownerId,
      configId: "default",
      name: "installed-permissions",
      remaining: 30,
      permissions: { vault: ["read"] },
      metadata: { installed: "original" },
    });
    const observations: Data[] = [];
    const cases: [unknown, boolean, string][] = [
      [null, false, "KEY_NOT_FOUND"],
      ["", false, "KEY_NOT_FOUND"],
      ["garbage", false, "KEY_NOT_FOUND"],
      ["null", false, "KEY_NOT_FOUND"],
      ["false", false, "KEY_NOT_FOUND"],
      ["{}", false, "KEY_NOT_FOUND"],
      ["[]", false, "KEY_NOT_FOUND"],
      ['{"vault":[]}', false, "KEY_NOT_FOUND"],
      ['{"vault":["read",null]}', true, ""],
      ['{"vault":"breadth"}', true, ""],
      ['{"vault":true}', false, "INVALID_API_KEY"],
      ['{"vault":1}', false, "INVALID_API_KEY"],
      ['{"vault":{"includes":"read"}}', false, "INVALID_API_KEY"],
      ['{"vault":["2025-01-02T03:04:05.000Z"]}', false, "KEY_NOT_FOUND"],
    ];

    for (const [permissions, valid, code] of cases) {
      const installed = await control(ctx, "install", {
        keyId: issued.key.id,
        patch: { permissions },
      });
      const before = await state(ctx);
      const checked = await verify(ctx, {
        key: issued.key.key,
        configId: "default",
        permissions: {
          vault: [
            permissions === '{"vault":["2025-01-02T03:04:05.000Z"]}'
              ? "2025-01-02T03:04:05.000Z"
              : "read",
          ],
        },
      });
      expect(checked.error).toBeNull();
      expect(checked.value.valid).toBe(valid);

      if (!valid) {
        expect(checked.value.error.code).toBe(code);
      }

      if (code === "INVALID_API_KEY") {
        expect(checked.value.error.message).toEqual({
          code: "INVALID_API_KEY",
          message: "Invalid API key.",
        });
      }

      const after = await state(ctx);

      if (valid) {
        expect(row(after, issued.key).remaining).toBe(row(before, issued.key).remaining - 1);
        expect(checked.value.key.permissions).toEqual(JSON.parse(permissions as string));
      } else {
        expect(after).toEqual(before);
      }

      expect(row(after, issued.key).key).toBe(hash(issued.key.key));
      expect(row(after, issued.key).metadata).toBe('{"installed":"original"}');

      observations.push({
        permissions,
        installed,
        before,
        checked,
        after,
        callback: await events(ctx),
      });
    }

    for (const [action, canonical] of [
      ["2025-02-30T03:04:05Z", "2025-03-02T03:04:05.000Z"],
      ["2025-01-02T24:00:00Z", "2025-01-03T00:00:00.000Z"],
      ["2025-01-02T03:04:05.1234567890123456789Z", "2025-01-02T03:04:05.123Z"],
      ["9999-12-31T24:00:00Z", "+010000-01-01T00:00:00.000Z"],
      ["0000-01-01T00:00:00Z", "0000-01-01T00:00:00.000Z"],
      ["2025-13-02T03:04:05Z", null],
      ["2025-01-02T24:00:00.0001Z", null],
    ] as const) {
      const permissions = JSON.stringify({ vault: [action], literal: { [action]: "retained" } });
      const installed = await control(ctx, "install", {
        keyId: issued.key.id,
        patch: { permissions },
      });
      const before = await state(ctx);
      const checked = await verify(ctx, {
        key: issued.key.key,
        configId: "default",
        permissions: { vault: [action] },
      });
      expect(checked.error).toBeNull();
      expect(checked.value.valid).toBe(canonical === null);

      if (canonical !== null) {
        expect(checked.value.error.code).toBe("KEY_NOT_FOUND");
      }

      const after = await state(ctx);

      if (canonical === null) {
        expect(row(after, issued.key).remaining).toBe(row(before, issued.key).remaining - 1);
      } else {
        expect(after).toEqual(before);
      }

      const unfiltered = await verify(ctx, { key: issued.key.key, configId: "default" });
      expect(unfiltered.error).toBeNull();
      expect(unfiltered.value.valid).toBe(true);
      expect(unfiltered.value.key.permissions).toEqual({
        vault: [canonical ?? action],
        literal: { [action]: "retained" },
      });

      const afterUnfiltered = await state(ctx);
      expect(row(afterUnfiltered, issued.key).remaining).toBe(row(after, issued.key).remaining - 1);
      expect(row(afterUnfiltered, issued.key).permissions).toBe(permissions);
      expect(row(afterUnfiltered, issued.key).key).toBe(hash(issued.key.key));

      observations.push({
        action,
        canonical,
        permissions,
        installed,
        before,
        checked,
        after,
        unfiltered,
        afterUnfiltered,
        callback: await events(ctx),
      });
    }

    const installed = await control(ctx, "install", {
      keyId: issued.key.id,
      patch: { permissions: '{"vault":["read"]}' },
    });
    const beforeEmpty = await state(ctx);
    const empty = await verify(ctx, { key: issued.key.key, configId: "default", permissions: {} });
    expect(empty.value.valid).toBe(false);
    expect(empty.value.error.code).toBe("KEY_NOT_FOUND");
    expect(await state(ctx)).toEqual(beforeEmpty);

    const foreignUpdate = await s.foreign.apiKey.update({
      keyId: issued.key.id,
      configId: "default",
      permissions: { vault: ["write"] },
    });
    expect(foreignUpdate.error?.code).toBe("SERVER_ONLY_PROPERTY");
    expect(foreignUpdate.error?.status).toBe(400);
    expect(await state(ctx)).toEqual(beforeEmpty);

    const forged = await s.owner.apiKey.create({
      configId: "default",
      name: "forged-owner",
      userId: s.foreignId,
    } as any);
    expect(forged.error?.code).toBe("UNAUTHORIZED_SESSION");
    expect(forged.error?.status).toBe(401);
    expect(await state(ctx)).toEqual(beforeEmpty);

    return {
      signup: s.signup,
      other: s.other,
      guard: s.guard,
      initial: s.initial,
      issued: issued.result,
      observations,
      installed,
      beforeEmpty,
      empty,
      foreignUpdate: ctx.snapshot(foreignUpdate),
      forged: ctx.snapshot(forged),
      authority: await authority(ctx, s),
    };
  },
);

compatScenario(
  "api-key installed configuration and references resolve the actual principal after admitted usage without changing foreign keys",
  async (ctx) => {
    const s = await setup(ctx);
    const observations: Data[] = [];
    const issued = await trustedCreate(ctx, {
      userId: s.ownerId,
      configId: "default",
      name: "installed-reference",
      remaining: 8,
      permissions: { vault: ["read"] },
    });
    const original = await state(ctx);

    for (const referenceId of [s.foreignId, "installed-missing-user"]) {
      const installed = await control(ctx, "install", {
        keyId: issued.key.id,
        patch: { referenceId },
      });
      const before = await state(ctx);
      const checked = await verify(ctx, { key: issued.key.key, configId: "default" });
      expect(checked.value.valid).toBe(true);
      expect(checked.value.key.referenceId).toBe(referenceId);

      const afterTrusted = await state(ctx);
      expect(row(afterTrusted, issued.key).remaining).toBe(row(before, issued.key).remaining - 1);

      const session = await s.owner.getSession({
        fetchOptions: { headers: { "x-options-default": issued.key.key } },
      });
      const afterSession = await state(ctx);
      expect(row(afterSession, issued.key).remaining).toBe(
        row(afterTrusted, issued.key).remaining - 1,
      );

      if (referenceId === s.foreignId) {
        expect(session.error).toBeNull();
        expect(session.data!.user.id).toBe(s.foreignId);
        expect(session.data!.session.userId).toBe(s.foreignId);
        expect(session.data!.session.id).toBe(issued.key.id);
        expect(session.data!.session.token).toBe(issued.key.key);
      } else {
        expect(session.error?.status).toBe(401);
        expect(session.error?.code).toBe("INVALID_REFERENCE_ID_FROM_API_KEY");
      }

      observations.push({
        installed,
        before,
        checked,
        afterTrusted,
        session: ctx.snapshot(session),
        afterSession,
      });
    }

    const malformed = await control(ctx, "install", {
      keyId: issued.key.id,
      patch: { referenceId: s.ownerId, configId: "installed-unknown" },
    });
    const beforeMismatch = await state(ctx);
    const mismatch = await verify(ctx, { key: issued.key.key, configId: "default" });
    expect(mismatch.value.valid).toBe(false);
    expect(mismatch.value.error.code).toBe("INVALID_API_KEY");
    expect(await state(ctx)).toEqual(beforeMismatch);

    return {
      signup: s.signup,
      other: s.other,
      guard: s.guard,
      initial: s.initial,
      issued: issued.result,
      original,
      observations,
      malformed,
      beforeMismatch,
      mismatch,
      authority: await authority(ctx, s),
    };
  },
  ["GET /get-session"],
);

compatScenario(
  "api-key application callback errors preserve real request inputs and each explicit implicit and HTTP catch boundary",
  async (ctx) => {
    const s = await setup(ctx);
    const observations: Data[] = [];

    for (const mode of ["generator-ordinary", "generator-api", "generator-public-500"]) {
      await control(ctx, "mode", { mode });
      const before = await state(ctx);
      const denied = await s.owner.apiKey.create({
        configId: "custom-quarter",
        name: "generator-error",
      });
      expect(s.ownerResponses.at(-1)!.status).toBe(mode === "generator-api" ? 403 : 500);

      if (mode !== "generator-ordinary") {
        expect(denied.error?.code).toBe(
          mode === "generator-api"
            ? "APPLICATION_GENERATOR_DENIED"
            : "APPLICATION_GENERATOR_FAILED",
        );
      }

      const after = await state(ctx);
      const callback = await events(ctx);
      expect(after).toEqual(before);
      expect(callback).toEqual([
        {
          kind: "generator",
          configId: "custom-quarter",
          length: { value: 0.25, text: "0.25" },
          prefix: "optKEY_",
          mode,
        },
      ]);

      observations.push({ mode, before, denied: ctx.snapshot(denied), after, callback });
    }

    await control(ctx, "mode", { mode: "normal" });
    const validator = await trustedCreate(ctx, {
      userId: s.ownerId,
      configId: "validator-session",
      name: "validator",
      remaining: 8,
      permissions: { vault: ["read"] },
    });
    const getter = await trustedCreate(ctx, {
      userId: s.ownerId,
      configId: "getter-session",
      name: "getter",
      remaining: 8,
    });
    const issuingEvents = await events(ctx);
    const initial = await state(ctx);
    const input = {
      key: validator.key.key,
      configId: "validator-session",
      permissions: { vault: ["read"] },
    };
    const absent = await verify(ctx, input);
    expect(absent.value.valid).toBe(true);

    const absentEvents = await events(ctx);
    expect(absentEvents).toEqual([
      {
        kind: "validator",
        configId: "validator-session",
        key: validator.key.key,
        mode: "normal",
        requestPresent: false,
        method: null,
        marker: null,
        body: input,
      },
    ]);

    const present = await verify(ctx, input, true);
    expect(present.value.valid).toBe(true);

    const presentEvents = await events(ctx);
    expect(presentEvents).toEqual([
      {
        kind: "validator",
        configId: "validator-session",
        key: validator.key.key,
        mode: "normal",
        requestPresent: true,
        method: "POST",
        marker: "actual-request",
        body: input,
      },
    ]);

    for (const mode of [
      "validator-deny",
      "validator-ordinary",
      "validator-api",
      "validator-public-500",
    ]) {
      await control(ctx, "mode", { mode });
      const before = await state(ctx);
      const explicit = await verify(ctx, input);
      const explicitEvents = await events(ctx);
      expect(explicitEvents).toEqual([
        {
          kind: "validator",
          configId: "validator-session",
          key: validator.key.key,
          mode,
          requestPresent: false,
          method: null,
          marker: null,
          body: input,
        },
      ]);

      if (mode === "validator-deny") {
        expect(explicit.error).toBeNull();
        expect(explicit.value.error.code).toBe("KEY_NOT_FOUND");
      } else {
        expect(explicit.value).toBeNull();
        expect(explicit.error.api).toBe(mode !== "validator-ordinary");
        expect(explicit.error.message).toBe(
          mode === "validator-ordinary"
            ? "Private validator failure"
            : mode === "validator-api"
              ? "Application validator denied"
              : "Application validator failed",
        );
      }

      const implicitInput = { key: validator.key.key, permissions: { vault: ["read"] } };
      const implicit = await verify(ctx, implicitInput);
      const implicitEvents = await events(ctx);
      expect(implicit.error).toBeNull();
      expect(implicit.value.valid).toBe(false);
      expect(implicit.value.error.code).toBe(
        mode === "validator-deny"
          ? "KEY_NOT_FOUND"
          : mode === "validator-ordinary"
            ? "INVALID_API_KEY"
            : mode === "validator-api"
              ? "APPLICATION_VALIDATOR_DENIED"
              : "APPLICATION_VALIDATOR_FAILED",
      );
      expect(implicitEvents).toEqual([
        {
          kind: "validator",
          configId: "validator-session",
          key: validator.key.key,
          mode,
          requestPresent: false,
          method: null,
          marker: null,
          body: implicitInput,
        },
      ]);

      const http = await s.foreign.getSession({
        fetchOptions: {
          headers: {
            "x-options-validator-session": validator.key.key,
            "x-options-marker": "http-request",
          },
        },
      });
      const httpEvents = await events(ctx);
      expect(http.error?.status).toBe(
        mode === "validator-deny" || mode === "validator-api" ? 403 : 500,
      );
      expect(httpEvents).toEqual([
        {
          kind: "validator",
          configId: "validator-session",
          key: validator.key.key,
          mode,
          requestPresent: true,
          method: "GET",
          marker: "http-request",
          body: null,
        },
      ]);

      const after = await state(ctx);
      expect(after).toEqual(before);

      observations.push({
        mode,
        before,
        explicit,
        explicitEvents,
        implicit,
        implicitEvents,
        http: ctx.snapshot(http),
        httpEvents,
        after,
      });
    }

    await control(ctx, "mode", { mode: "normal" });
    const beforeGetter = await state(ctx);
    const getterSession = await s.foreign.getSession({
      fetchOptions: {
        headers: { "x-options-getter-session": getter.key.key, "x-options-marker": "http-request" },
      },
    });
    expect(getterSession.error).toBeNull();
    expect(getterSession.data!.user.id).toBe(s.ownerId);

    const afterGetter = await state(ctx);
    expect(row(afterGetter, getter.key).remaining).toBe(
      row(beforeGetter, getter.key).remaining - 1,
    );

    const getterEvents = await events(ctx);
    expect(getterEvents).toEqual(
      [1, 2].map(() => ({
        kind: "getter",
        configId: "getter-session",
        key: getter.key.key,
        mode: "normal",
        requestPresent: true,
        method: "GET",
        marker: "http-request",
        body: null,
      })),
    );

    for (const mode of ["getter-ordinary", "getter-api", "getter-public-500"]) {
      await control(ctx, "mode", { mode });
      const before = await state(ctx);
      const http = await s.foreign.getSession({
        fetchOptions: {
          headers: {
            "x-options-getter-session": getter.key.key,
            "x-options-marker": "http-request",
          },
        },
      });
      const callback = await events(ctx);
      expect(http.error?.status).toBe(500);
      expect(http.error?.message).toBe(
        "An error occurred during hook matcher execution. Check the logs for more details.",
      );
      expect(callback).toEqual([
        {
          kind: "getter",
          configId: "getter-session",
          key: getter.key.key,
          mode,
          requestPresent: true,
          method: "GET",
          marker: "http-request",
          body: null,
        },
      ]);

      const after = await state(ctx);
      expect(after).toEqual(before);

      observations.push({ mode, before, http: ctx.snapshot(http), callback, after });
    }

    for (const mode of [
      "getter-handler-ordinary",
      "getter-handler-api",
      "getter-handler-public-500",
    ]) {
      await control(ctx, "mode", { mode });
      const before = await state(ctx);
      const http = await s.foreign.getSession({
        fetchOptions: {
          headers: {
            "x-options-getter-session": getter.key.key,
            "x-options-marker": "http-request",
          },
        },
      });
      const callback = await events(ctx);
      expect(http.error?.status).toBe(mode === "getter-handler-api" ? 403 : 500);

      if (mode === "getter-handler-ordinary") {
        expect(s.foreignResponses.at(-1)).toEqual({ status: 500, body: null });
      } else {
        expect(http.error).toMatchObject({
          code:
            mode === "getter-handler-api"
              ? "APPLICATION_GETTER_DENIED"
              : "APPLICATION_GETTER_FAILED",
          message:
            mode === "getter-handler-api"
              ? "Application getter denied"
              : "Application getter failed",
        });
      }

      expect(callback).toEqual(
        [1, 2].map(() => ({
          kind: "getter",
          configId: "getter-session",
          key: getter.key.key,
          mode,
          requestPresent: true,
          method: "GET",
          marker: "http-request",
          body: null,
        })),
      );

      const after = await state(ctx);
      expect(after).toEqual(before);

      observations.push({ mode, before, http: ctx.snapshot(http), callback, after });
    }

    return {
      signup: s.signup,
      other: s.other,
      guard: s.guard,
      initial,
      validator: validator.result,
      getter: getter.result,
      issuingEvents,
      absent,
      absentEvents,
      present,
      presentEvents,
      observations,
      beforeGetter,
      getterSession: ctx.snapshot(getterSession),
      afterGetter,
      getterEvents,
      authority: await authority(ctx, s),
    };
  },
  ["POST /api-key/create", "GET /get-session"],
);
