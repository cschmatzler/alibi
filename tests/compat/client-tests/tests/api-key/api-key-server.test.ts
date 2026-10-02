import { expect } from "bun:test";

import { apiKeyClient } from "@better-auth/api-key/client";
import { createAuthClient } from "better-auth/client";

import { compatScenario } from "../../support/scenario";

type Context = Parameters<Parameters<typeof compatScenario>[1]>[0];

function record(value: unknown): Record<string, any> {
  expect(value).toBeObject();
  return value as Record<string, any>;
}

async function signUp(ctx: Context, actor = "primary") {
  const result = await ctx.actor(actor).client.signUp.email({
    email: ctx.uniqueEmail(`api-key-server-${actor}`),
    password: "password123",
    name: "API Key Owner",
  });
  expect(result.error).toBeNull();
  return result.data!.user.id;
}

async function serverKey(ctx: Context, options: Record<string, unknown> = {}) {
  const userId = await signUp(ctx);
  const result = await ctx.rawRequest({
    path: "/__test/api-key/create",
    method: "POST",
    json: { userId, ...options },
  });
  expect(result.status).toBe(200);

  return record(result.body);
}

async function verify(ctx: Context, key: string, options: Record<string, unknown> = {}) {
  const response = await ctx.rawRequest({
    path: "/__test/api-key/verify",
    method: "POST",
    json: { key, ...options },
  });
  expect(response.status).toBe(200);

  const body = record(response.body);
  expect(body.key?.key).toBeUndefined();

  return body;
}

function verificationResult(body: Record<string, any>) {
  return {
    valid: body.valid,
    error: body.error,
    key: body.key && {
      config: body.key.configId,
      permissions: body.key.permissions,
      remaining: body.key.remaining,
      requestCount: body.key.requestCount,
      metadata: body.key.metadata,
    },
  };
}

compatScenario("api-key SDK uses the standalone 1.7 client plugin", async (ctx) => {
  await signUp(ctx);
  const client = createAuthClient({
    baseURL: ctx.baseURL,
    plugins: [apiKeyClient()],
    fetchOptions: { customFetchImpl: ctx.actor().fetch },
  });
  const created = await client.apiKey.create({ name: "sdk-key" });
  expect(created.error).toBeNull();
  expect(created.data!.key).toBeString();

  const listed = await client.apiKey.list();
  expect(listed.error).toBeNull();
  expect(listed.data!.total).toBe(1);

  const deleted = await client.apiKey.delete({ keyId: created.data!.id });
  return {
    name: created.data!.name,
    config: created.data!.configId,
    referenceMatchesOwner: created.data!.referenceId === listed.data!.apiKeys[0]!.referenceId,
    listedNames: listed.data!.apiKeys.map((key) => key.name),
    deleted,
  };
});

compatScenario("api-key server methods are not public HTTP routes", async (ctx) => {
  const responses = [];
  for (const route of ["verify", "delete-all-expired-api-keys"]) {
    const response = await ctx.rawRequest({
      path: `/api/auth/api-key/${route}`,
      method: "POST",
      json: { key: "invalid" },
    });
    expect(response.status).toBe(404);
    responses.push(response);
  }
  return responses;
});

compatScenario("api-key HTTP requests cannot select a different owner", async (ctx) => {
  const key = await serverKey(ctx);
  const otherUserId = await signUp(ctx, "other");
  const create = await ctx.rawRequest({
    path: "/api/auth/api-key/create",
    method: "POST",
    json: { userId: key.referenceId },
  });
  const update = await ctx.rawRequest({
    path: "/api/auth/api-key/update",
    method: "POST",
    json: { userId: otherUserId, keyId: key.id, name: "unauthorized" },
  });
  expect(create.status).toBe(401);
  expect(update.status).toBe(401);

  return { create, update };
});

compatScenario("api-key list validates pagination and sort direction", async (ctx) => {
  await signUp(ctx);
  const responses = [];

  for (const query of [
    "limit=-1",
    "limit=1.5",
    "limit=NaN",
    "offset=-1",
    "offset=1.5",
    "sortDirection=other",
  ]) {
    const response = await ctx.rawRequest({ path: `/api/auth/api-key/list?${query}` });
    expect(response.status).toBe(400);
    expect(record(response.body).code).toBe("VALIDATION_ERROR");

    responses.push(response);
  }

  return responses;
});

compatScenario("api-key create validates prefix expiration and null fields", async (ctx) => {
  await signUp(ctx);
  const responses = [];

  for (const json of [{ prefix: "invalid prefix" }, { expiresIn: 0 }, { name: null }]) {
    const response = await ctx.rawRequest({
      path: "/api/auth/api-key/create",
      method: "POST",
      json,
    });
    expect(response.status).toBe(400);
    expect(record(response.body).code).toBe("VALIDATION_ERROR");

    responses.push(response);
  }

  return responses;
});

compatScenario(
  "api-key verification scopes configuration and checks permissions before usage",
  async (ctx) => {
    const key = await serverKey(ctx, {
      configId: "secondary",
      permissions: { node: ["read", "heartbeat"] },
      metadata: { purpose: "compat" },
    });
    const wrongConfig = await verify(ctx, key.key, { configId: "default" });
    const denied = await verify(ctx, key.key, { permissions: { node: ["delete"] } });
    const valid = await verify(ctx, key.key, { permissions: { node: ["heartbeat"] } });
    const scoped = await verify(ctx, key.key, { configId: "secondary" });
    expect(wrongConfig.error.code).toBe("INVALID_API_KEY");
    expect(denied.error.code).toBe("KEY_NOT_FOUND");
    expect(valid.valid).toBe(true);
    expect(valid.key.requestCount).toBe(1);
    expect(scoped.key.requestCount).toBe(2);

    return [wrongConfig, denied, valid, scoped].map(verificationResult);
  },
);

compatScenario("api-key usage exhaustion deletes the exhausted key", async (ctx) => {
  const key = await serverKey(ctx, { remaining: 2 });
  const first = await verify(ctx, key.key);
  const second = await verify(ctx, key.key);
  const exhausted = await verify(ctx, key.key);
  const deleted = await verify(ctx, key.key);
  expect(first.key.remaining).toBe(1);
  expect(second.key.remaining).toBe(0);
  expect(exhausted.error.code).toBe("USAGE_EXCEEDED");
  expect(deleted.error.code).toBe("INVALID_API_KEY");

  return [first, second, exhausted, deleted].map(verificationResult);
});

compatScenario("api-key concurrent verification cannot overdraw quota", async (ctx) => {
  const key = await serverKey(ctx, { remaining: 2, refillAmount: 2, refillInterval: 60_000 });
  // Concurrent response order varies. Compare accepted requests and persisted counters.
  const results = await Promise.all(
    Array.from({ length: 8 }, async () => {
      const response = await fetch(`${ctx.baseURL}/__test/api-key/verify`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ key: key.key }),
      });
      expect(response.status).toBe(200);
      return record(await response.json());
    }),
  );
  const accepted = results.filter((result) => result.valid).length;
  const rejected = results.filter((result) => !result.valid).map((result) => result.error.code);
  expect(accepted).toBe(2);
  expect(rejected).toEqual(Array(6).fill("USAGE_EXCEEDED"));

  const stored = await ctx.rawRequest({ path: `/api/auth/api-key/get?id=${key.id}` });
  expect(record(stored.body).remaining).toBe(0);
  expect(record(stored.body).requestCount).toBe(2);

  return {
    accepted,
    rejected,
    remaining: record(stored.body).remaining,
    requestCount: record(stored.body).requestCount,
  };
});

compatScenario("api-key rate limit rejection consumes remaining quota", async (ctx) => {
  const key = await serverKey(ctx, {
    remaining: 5,
    rateLimitMax: 2,
    rateLimitTimeWindow: 60_000,
  });
  const first = await verify(ctx, key.key);
  const second = await verify(ctx, key.key);
  const limited = await verify(ctx, key.key);
  expect(limited.valid).toBe(false);
  expect(limited.error.code).toBe("RATE_LIMITED");
  expect(limited.error.details.tryAgainIn).toBeGreaterThan(0);
  expect(limited.error.details.tryAgainIn).toBeLessThanOrEqual(60_000);

  const stored = await ctx.rawRequest({ path: `/api/auth/api-key/get?id=${key.id}` });
  expect(record(stored.body).remaining).toBe(2);
  expect(record(stored.body).requestCount).toBe(2);

  return {
    allowed: [first, second].map(verificationResult),
    denied: { ...limited.error, details: { tryAgainIn: "<positive milliseconds>" } },
    remaining: record(stored.body).remaining,
  };
});

compatScenario("api-key server update revokes a machine credential", async (ctx) => {
  const key = await serverKey(ctx, { permissions: { node: ["read"] } });
  const updated = await ctx.rawRequest({
    path: "/__test/api-key/update",
    method: "POST",
    json: { userId: key.referenceId, keyId: key.id, enabled: false },
  });
  expect(updated.status).toBe(200);

  const result = await verify(ctx, key.key);
  expect(result.error.code).toBe("KEY_DISABLED");

  return verificationResult(result);
});

compatScenario("api-key session accepts configured headers for GET and POST", async (ctx) => {
  const key = await serverKey(ctx, { configId: "session" });
  const sessions = [];

  for (const [method, header] of [
    ["GET", "x-api-key"],
    ["POST", "x-api-key"],
    ["GET", "x-machine-key"],
  ]) {
    const response = await ctx.rawRequest({
      actor: "machine",
      path: "/api/auth/get-session",
      method,
      headers: { [header!]: key.key },
    });
    expect(response.status).toBe(200);

    const body = record(response.body);
    expect(body.session.token).toBe(key.key);
    expect(body.session.id).toBe(key.id);
    expect(body.user.id).toBe(key.referenceId);

    sessions.push({
      status: response.status,
      ownerMatches: body.session.userId === key.referenceId,
    });
  }

  const listed = await ctx.rawRequest({
    actor: "machine",
    path: "/api/auth/api-key/list",
    headers: { "x-machine-key": key.key },
  });
  expect(listed.status).toBe(200);
  expect(record(listed.body).total).toBe(1);

  return { sessions, listedTotal: record(listed.body).total };
});

compatScenario("api-key server numeric fields retain fractional values", async (ctx) => {
  const numbers = {
    remaining: 2.5,
    refillAmount: 1.5,
    refillInterval: 60_000.5,
    rateLimitMax: 2.5,
    rateLimitTimeWindow: 60_000.5,
  };
  const key = await serverKey(ctx, numbers);

  for (const [field, value] of Object.entries(numbers)) {
    expect(key[field]).toBe(value);
  }

  const verified = await verify(ctx, key.key);
  expect(verified.valid).toBe(true);
  expect(verified.key.remaining).toBe(1.5);
  expect(verified.key.requestCount).toBe(1);

  const second = await verify(ctx, key.key);
  const third = await verify(ctx, key.key);
  const exhausted = await verify(ctx, key.key);
  expect(second.key.remaining).toBe(0.5);
  // TS consumes a full request while a positive fractional balance remains.
  expect(third.key.remaining).toBe(-0.5);
  expect(third.key.requestCount).toBe(3);
  expect(exhausted.error.code).toBe("USAGE_EXCEEDED");

  return {
    numbers: Object.fromEntries(Object.keys(numbers).map((field) => [field, key[field]])),
    verified: [verified, second, third, exhausted].map(verificationResult),
  };
});

compatScenario("api-key shared headers select the first configured session", async (ctx) => {
  const userId = await signUp(ctx);
  const results = [];

  for (const configId of ["shared-first", "shared-second"]) {
    const created = await ctx.rawRequest({
      path: "/__test/api-key/create",
      method: "POST",
      json: { userId, configId },
    });
    expect(created.status).toBe(200);

    const response = await ctx.rawRequest({
      actor: "machine",
      path: "/api/auth/get-session",
      headers: { "x-shared-key": record(created.body).key },
    });
    expect(response.status).toBe(configId === "shared-first" ? 200 : 401);

    results.push({ config: configId, status: response.status, error: record(response.body).code });
  }

  return results;
});

compatScenario(
  "api-key CRUD isolates configurations and preserves all-config listing",
  async (ctx) => {
    await signUp(ctx);
    const keys = [];

    for (const configId of ["default", "secondary"]) {
      const response = await ctx.rawRequest({
        path: "/api/auth/api-key/create",
        method: "POST",
        json: { configId, name: `${configId}-key` },
      });
      expect(response.status).toBe(200);
      keys.push(record(response.body));
    }

    const key = keys[1]!;
    const getWrong = await ctx.rawRequest({ path: `/api/auth/api-key/get?id=${key.id}` });
    const updateWrong = await ctx.rawRequest({
      path: "/api/auth/api-key/update",
      method: "POST",
      json: { keyId: key.id, name: "wrong" },
    });
    const deleteWrong = await ctx.rawRequest({
      path: "/api/auth/api-key/delete",
      method: "POST",
      json: { keyId: key.id },
    });

    for (const response of [getWrong, updateWrong, deleteWrong]) {
      expect(response.status).toBe(404);
    }

    const all = record((await ctx.rawRequest({ path: "/api/auth/api-key/list" })).body);
    const scoped = record(
      (await ctx.rawRequest({ path: "/api/auth/api-key/list?configId=secondary" })).body,
    );
    expect(all.total).toBe(2);
    expect(scoped.total).toBe(1);

    return {
      errors: [getWrong, updateWrong, deleteWrong],
      allNames: all.apiKeys.map((value: any) => value.name),
      scopedNames: scoped.apiKeys.map((value: any) => value.name),
    };
  },
);

compatScenario("api-key organization ownership rejects unrelated users", async (ctx) => {
  const ownerId = await signUp(ctx);
  const organization = await ctx.rawRequest({
    path: "/api/auth/organization/create",
    method: "POST",
    json: { name: "Fleet", slug: ctx.uniqueToken("fleet") },
  });
  expect(organization.status).toBe(200);

  const organizationId = record(organization.body).id;
  const created = await ctx.rawRequest({
    path: "/api/auth/api-key/create",
    method: "POST",
    json: { configId: "organization", organizationId, name: "org-key" },
  });
  expect(created.status).toBe(200);

  const key = record(created.body);
  expect(key.referenceId).toBe(organizationId);

  await signUp(ctx, "outsider");
  const unrelated = await ctx.rawRequest({
    actor: "outsider",
    path: `/api/auth/api-key/get?configId=organization&id=${key.id}`,
  });
  expect(unrelated.status).toBe(403);

  const verified = await verify(ctx, key.key, { configId: "organization" });
  expect(verified.valid).toBe(true);

  const listed = await ctx.rawRequest({
    path: `/api/auth/api-key/list?organizationId=${organizationId}`,
  });
  expect(record(listed.body).total).toBe(1);

  const memberErrors = [];

  for (const role of ["member", "admin"]) {
    await signUp(ctx, role);
    const invited = await ctx.rawRequest({
      path: "/api/auth/organization/invite-member",
      method: "POST",
      json: { organizationId, email: ctx.uniqueEmail(`api-key-server-${role}`), role },
    });
    expect(invited.status).toBe(200);

    const accepted = await ctx.rawRequest({
      actor: role,
      path: "/api/auth/organization/accept-invitation",
      method: "POST",
      json: { invitationId: record(invited.body).id },
    });
    expect(accepted.status).toBe(200);

    const denied = await ctx.rawRequest({
      actor: role,
      path: `/api/auth/api-key/get?configId=organization&id=${key.id}`,
    });
    expect(denied.status).toBe(403);
    expect(record(denied.body).code).toBe("INSUFFICIENT_API_KEY_PERMISSIONS");

    memberErrors.push(denied);
  }

  const serverCreated = await ctx.rawRequest({
    path: "/__test/api-key/create",
    method: "POST",
    json: { configId: "organization", organizationId, userId: ownerId, name: "server-org-key" },
  });
  expect(serverCreated.status).toBe(200);
  expect(record(serverCreated.body).referenceId).toBe(organizationId);

  return {
    unrelated,
    memberErrors,
    verified: verificationResult(verified),
    ownerMatchesOrganization: key.referenceId === organizationId,
    serverCreatedStatus: serverCreated.status,
  };
});
