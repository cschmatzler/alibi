import { Database } from "bun:sqlite";
import { expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { apiKey } from "@better-auth/api-key";
import { betterAuth } from "better-auth";
import { APIError, createAuthMiddleware } from "better-auth/api";
import { getMigrations } from "better-auth/db/migration";
import { organization } from "better-auth/plugins";
import { compareValues } from "../support/compare";
import { normalizeClientValue } from "../support/normalize";

type Data = Record<string, any>;
async function capture(baseURL: string) {
  const database = new Database(":memory:"),
    events: Data[] = [];
  let serial = 0;
  const snapshot = (stage: string, ctx: Data) =>
    events.push({
      stage,
      pathPresent: Object.hasOwn(ctx, "path"),
      path: ctx.path ?? null,
      methodPresent: Object.hasOwn(ctx, "method"),
      method: ctx.method ?? null,
      bodyPresent: Object.hasOwn(ctx, "body"),
      body: ctx.body ?? null,
      queryPresent: Object.hasOwn(ctx, "query"),
      query: ctx.query ?? null,
      headers: ctx.headers ? Object.fromEntries(ctx.headers) : null,
      request: ctx.request
        ? {
            url: ctx.request.url,
            method: ctx.request.method,
            headers: Object.fromEntries(ctx.request.headers),
          }
        : null,
      session: ctx.context.session ?? null,
      returned:
        ctx.context.returned instanceof APIError
          ? { status: ctx.context.returned.statusCode, body: ctx.context.returned.body }
          : (ctx.context.returned ?? null),
    });
  const auth = betterAuth({
    baseURL,
    secret: "selector-harness-application-secret32",
    database,
    emailAndPassword: { enabled: true },
    rateLimit: { enabled: false },
    hooks: {
      before: createAuthMiddleware(async (ctx) => {
        snapshot("before", ctx);
      }),
      after: createAuthMiddleware(async (ctx) => {
        snapshot("after", ctx);
      }),
    },
    plugins: [
      apiKey({
        configId: "selectors",
        enableSessionForAPIKeys: true,
        defaultKeyLength: 16,
        rateLimit: { enabled: false },
        customKeyGenerator: () => `observed-selector-actual-${String(++serial).padStart(6, "0")}`,
      }),
      organization(),
    ],
  });
  const startedAt = Date.now();
  try {
    await (await getMigrations(auth.options)).runMigrations();
    const owner = await auth.api.signUpEmail({
      body: { email: "owner@selector.local", name: "Owner", password: "password123" },
    });
    const target = await auth.api.signUpEmail({
      body: { email: "target@selector.local", name: "Target", password: "password123" },
    });
    const foreign = await auth.api.signUpEmail({
      body: { email: "foreign@selector.local", name: "Foreign", password: "password123" },
    });
    const run = async (operation: string, args: Data) => {
      events.length = 0;
      const api = auth.api as unknown as Record<string, (args: Data) => Promise<unknown>>;
      const result = await api[operation]!({
        ...args,
        asResponse: false,
        returnHeaders: true,
      }).then(
        (result) => ({ ok: true as const, value: result as Data }),
        (error) => ({
          ok: false as const,
          error: { status: error.statusCode, body: error.body, message: error.message },
        }),
      );
      if (result.ok) result.value.headers = Object.fromEntries(result.value.headers);
      return normalizeClientValue({ result, events: [...events] }) as Data;
    };
    const key = await run("createApiKey", {
      body: { configId: "selectors", userId: owner.user.id, name: "owner", remaining: 40 },
    });
    const otherKey = await run("createApiKey", {
      body: { configId: "selectors", userId: foreign.user.id, name: "foreign", remaining: 40 },
    });
    const revokedKey = await run("createApiKey", {
      body: { configId: "selectors", userId: owner.user.id, name: "revoked", remaining: 40 },
    });
    const revoked = await run("updateApiKey", {
      body: {
        configId: "selectors",
        userId: owner.user.id,
        keyId: revokedKey.result.value.response.id,
        enabled: false,
      },
    });
    expect(revoked.result.ok).toBe(true);
    expect(revoked.result.value.response.enabled).toBe(false);
    const created = await run("createOrganization", {
      body: { userId: owner.user.id, name: "Observed", slug: "observed" },
    });
    const headers = new Headers({ "x-api-key": key.result.value.response.key });
    const added = await run("addMember", {
      body: {
        organizationId: created.result.value.response.id,
        userId: target.user.id,
        role: "member",
      },
      headers,
    });
    const otherMember = await run("addMember", {
      body: {
        organizationId: created.result.value.response.id,
        userId: foreign.user.id,
        role: "member",
      },
      headers,
    });
    const memberRows = database
      .query("SELECT * FROM member ORDER BY role,createdAt,id")
      .all()
      .map((raw) => {
        const row = { ...(raw as Data) };
        row.createdAt = new Date(row.createdAt).toISOString();
        return row;
      });
    expect(memberRows).toHaveLength(3);
    expect(memberRows.find((row) => row.id === added.result.value.response.id)!.userId).toBe(
      target.user.id,
    );
    expect(memberRows.find((row) => row.id === otherMember.result.value.response.id)!.userId).toBe(
      foreign.user.id,
    );
    const removed = await run("removeMember", {
      body: {
        organizationId: created.result.value.response.id,
        memberIdOrEmail: added.result.value.response.id,
      },
      headers,
    });
    expect(removed.result.ok).toBe(true);
    expect(removed.result.value.response.member.id).toBe(added.result.value.response.id);
    const emailRemoved = await run("removeMember", {
      body: {
        organizationId: created.result.value.response.id,
        memberIdOrEmail: foreign.user.email,
      },
      headers,
    });
    expect(emailRemoved.result.ok).toBe(true);
    expect(emailRemoved.result.value.response.member.id).toBe(otherMember.result.value.response.id);
    expect(database.query("SELECT * FROM member").all()).toHaveLength(1);
    const revokedDenied = await run("removeMember", {
      body: {
        organizationId: created.result.value.response.id,
        memberIdOrEmail: "unknown-real-selector",
      },
      headers: new Headers({ "x-api-key": revokedKey.result.value.response.key }),
    });
    expect(revokedDenied.result.ok).toBe(false);
    expect(revokedDenied.result.error.body.code).toBe("KEY_DISABLED");
    const keyRows = database
      .query(
        "SELECT *,hex(CAST(start AS BLOB)) AS startHex,typeof(start) AS startType FROM apikey ORDER BY name,id",
      )
      .all()
      .map((raw) => {
        const row = { ...(raw as Data) };
        row.enabled = !!row.enabled;
        row.rateLimitEnabled = !!row.rateLimitEnabled;
        for (const field of ["createdAt", "updatedAt", "expiresAt", "lastRequest", "lastRefillAt"])
          if (row[field] !== null) row[field] = new Date(row[field]).toISOString();
        return row;
      });
    for (const issued of [key, otherKey, revokedKey]) {
      const output = issued.result.value.response,
        stored = keyRows.find((row) => row.id === output.id)!;
      expect(stored.referenceId).toBe(output.referenceId);
      expect(stored.key).toBe(createHash("sha256").update(output.key).digest("base64url"));
      expect(stored.startType).toBe("text");
      expect(stored.startHex).toBe(Buffer.from(output.start).toString("hex").toUpperCase());
    }
    expect(keyRows.find((row) => row.id === key.result.value.response.id)!.remaining).toBe(36);
    expect(keyRows.find((row) => row.id === revokedKey.result.value.response.id)!.remaining).toBe(
      40,
    );
    return {
      value: normalizeClientValue({
        observation: {
          owner,
          target,
          foreign,
          key,
          otherKey,
          revokedKey,
          revoked,
          created,
          added,
          otherMember,
          removed,
          emailRemoved,
          revokedDenied,
          memberRows,
          keyRows,
        },
      }) as Data,
      baseURL,
      startedAt,
      finishedAt: Date.now(),
    };
  } finally {
    database.close();
  }
}

test("actual Source server selectors retain issued key and member ownership relationships with literal emails", async () => {
  const left = await capture("http://localhost:3100"),
    right = await capture("http://localhost:3200");
  const context = {
    leftBaseURL: left.baseURL,
    rightBaseURL: right.baseURL,
    leftStartedAt: left.startedAt,
    leftFinishedAt: left.finishedAt,
    rightStartedAt: right.startedAt,
    rightFinishedAt: right.finishedAt,
  };
  if (Bun.env.COMPAT_SERVER_SELECTOR_CAPTURE)
    await Bun.write(
      Bun.env.COMPAT_SERVER_SELECTOR_CAPTURE,
      JSON.stringify({ left: left.value, right: right.value, context }, null, 2),
    );
  expect(compareValues(left.value, right.value, context)).toEqual([]);
  const keyPath = "observation.revoked.events.0.body.keyId",
    memberPath = "observation.removed.events.0.body.memberIdOrEmail";
  const keyRowIndex = right.value.observation.keyRows.findIndex(
    (row: Data) => row.id === right.value.observation.revokedKey.result.value.response.id,
  );
  const memberRowIndex = right.value.observation.memberRows.findIndex(
    (row: Data) => row.id === right.value.observation.added.result.value.response.id,
  );
  const mutations: { mutate: (value: Data) => void; path: string; reason: string }[] = [
    {
      mutate: (value) => {
        value.observation.revoked.events[0].body.keyId =
          value.observation.otherKey.result.value.response.id;
      },
      path: keyPath,
      reason: "identity relationship or token rotation differs",
    },
    {
      mutate: (value) => {
        value.observation.removed.events[0].body.memberIdOrEmail =
          value.observation.otherMember.result.value.response.id;
      },
      path: memberPath,
      reason: "identity relationship or token rotation differs",
    },
    {
      mutate: (value) => {
        value.observation.revoked.events[0].body.keyId = "unobserved-key-id";
      },
      path: keyPath,
      reason: "server selector lacks its observed entity on both sides",
    },
    {
      mutate: (value) => {
        value.observation.removed.events[0].body.memberIdOrEmail = "unobserved-member-id";
      },
      path: memberPath,
      reason: "server selector lacks its observed entity on both sides",
    },
    {
      mutate: (value) => {
        value.observation.revoked.events[0].body.keyId =
          value.observation.otherMember.result.value.response.id;
      },
      path: keyPath,
      reason: "server selector lacks its observed entity on both sides",
    },
    {
      mutate: (value) => {
        value.observation.removed.events[0].body.memberIdOrEmail =
          value.observation.otherKey.result.value.response.id;
      },
      path: memberPath,
      reason: "server selector lacks its observed entity on both sides",
    },
    {
      mutate: (value) => {
        value.observation.emailRemoved.events[0].body.memberIdOrEmail =
          value.observation.owner.user.email;
      },
      path: "observation.emailRemoved.events.0.body.memberIdOrEmail",
      reason: "value or type differs",
    },
    {
      mutate: (value) => {
        value.observation.removed.events[0].body.memberIdOrEmail = 42;
      },
      path: memberPath,
      reason: "value or type differs",
    },
    {
      mutate: (value) => {
        value.observation.memberRows[memberRowIndex].userId = value.observation.foreign.user.id;
      },
      path: `observation.memberRows.${memberRowIndex}.userId`,
      reason: "identity relationship or token rotation differs",
    },
    {
      mutate: (value) => {
        value.observation.memberRows[memberRowIndex].organizationId = "unobserved-organization";
      },
      path: `observation.memberRows.${memberRowIndex}.organizationId`,
      reason: "identity relationship or token rotation differs",
    },
    {
      mutate: (value) => {
        value.observation.keyRows[keyRowIndex].referenceId = value.observation.foreign.user.id;
      },
      path: `observation.keyRows.${keyRowIndex}.referenceId`,
      reason: "identity relationship or token rotation differs",
    },
    {
      mutate: (value) => {
        value.observation.keyRows[keyRowIndex].key = value.observation.keyRows.find(
          (row: Data) => row.id === value.observation.otherKey.result.value.response.id,
        ).key;
      },
      path: keyPath,
      reason: "server selector lacks its observed entity on both sides",
    },
  ];
  for (const mutation of mutations) {
    const changed = structuredClone(right.value);
    mutation.mutate(changed);
    expect(compareValues(left.value, changed, context)).toContainEqual({
      path: mutation.path,
      reason: mutation.reason,
    });
  }
  for (const field of ["metadata", "additionalFields", "custom", "applicationData"]) {
    const appLeft = {
      ...left.value,
      [field]: {
        keyId: left.value.observation.revokedKey.result.value.response.id,
        memberIdOrEmail: left.value.observation.added.result.value.response.id,
      },
    };
    const appRight = {
      ...right.value,
      [field]: {
        keyId: right.value.observation.revokedKey.result.value.response.id,
        memberIdOrEmail: right.value.observation.added.result.value.response.id,
      },
    };
    const diffs = compareValues(appLeft, appRight, context);
    expect(diffs).toContainEqual({ path: `${field}.keyId`, reason: "value or type differs" });
    expect(diffs).toContainEqual({
      path: `${field}.memberIdOrEmail`,
      reason: "value or type differs",
    });
  }
  const literalLeft = {
    ...left.value,
    unknown: { keyId: "literal-left", memberIdOrEmail: "literal-left" },
  };
  const literalRight = {
    ...right.value,
    unknown: { keyId: "literal-right", memberIdOrEmail: "literal-right" },
  };
  expect(compareValues(literalLeft, literalRight, context)).toContainEqual({
    path: "unknown.keyId",
    reason: "value or type differs",
  });
  expect(compareValues(literalLeft, literalRight, context)).toContainEqual({
    path: "unknown.memberIdOrEmail",
    reason: "value or type differs",
  });
  const claimLeft = {
    ...left.value,
    claims: {
      iat: 100,
      exp: 200,
      iss: "application-issuer",
      aud: "application-audience",
      keyId: left.value.observation.revokedKey.result.value.response.id,
      memberIdOrEmail: left.value.observation.added.result.value.response.id,
    },
  };
  const claimRight = {
    ...right.value,
    claims: {
      iat: 100,
      exp: 200,
      iss: "application-issuer",
      aud: "application-audience",
      keyId: right.value.observation.revokedKey.result.value.response.id,
      memberIdOrEmail: right.value.observation.added.result.value.response.id,
    },
  };
  expect(compareValues(claimLeft, claimRight, context)).toContainEqual({
    path: "claims.keyId",
    reason: "value or type differs",
  });
  expect(compareValues(claimLeft, claimRight, context)).toContainEqual({
    path: "claims.memberIdOrEmail",
    reason: "value or type differs",
  });
  const missingReceipts = structuredClone(right.value);
  const removeMemberReceipts = (value: unknown) => {
    if (Array.isArray(value)) value.forEach(removeMemberReceipts);
    else if (value && typeof value === "object") {
      const row = value as Data;
      if (
        typeof row.id === "string" &&
        typeof row.userId === "string" &&
        typeof row.organizationId === "string" &&
        "createdAt" in row
      )
        delete row.role;
      Object.values(row).forEach(removeMemberReceipts);
    }
  };
  removeMemberReceipts(missingReceipts);
  expect(compareValues(left.value, missingReceipts, context)).toContainEqual({
    path: memberPath,
    reason: "server selector lacks its observed entity on both sides",
  });
});
