import { expect } from "bun:test";
import { apiKeyClient } from "@better-auth/api-key/client";
import { createAuthClient } from "better-auth/client";
import { z } from "zod";
import { compatScenario } from "../../support/scenario";

const metadataText =
  '{"rounded":9007199254740993,"scientific":1e21,"fixed":1e20,"preciseTiny":3.8730639354761726e-71,"negativeZero":-0.0,"overflow":1e400,"nested":[-1e400,229069639655724.625,{"2":1e400,"1":-0.0}],"tiny":1e-7,"private":[{"$serde_json::private::Number":"7"},{"$serde_json::private::Number":"1e400"},{"$serde_json::private::Number":"hello"},{"$serde_json::private::RawValue":"7"},{"$serde_json::private::RawValue":"hello"}],"unicode":"\\ud83d\\ude00","duplicate":1,"duplicate":2}';
const expectedMetadata = {
  rounded: 9007199254740992,
  scientific: 1e21,
  fixed: 1e20,
  preciseTiny: 3.8730639354761726e-71,
  negativeZero: 0,
  overflow: null,
  nested: [null, 229069639655724.62, { "1": 0, "2": null }],
  tiny: 1e-7,
  private: [
    { "$serde_json::private::Number": "7" },
    { "$serde_json::private::Number": "1e400" },
    { "$serde_json::private::Number": "hello" },
    { "$serde_json::private::RawValue": "7" },
    { "$serde_json::private::RawValue": "hello" },
  ],
  unicode: "😀",
  duplicate: 2,
};

compatScenario(
  "arbitrary JSON delivery emits JavaScript rounded numbers and nullable overflow",
  async (ctx) => {
    const actor = ctx.actor();
    const email = ctx.uniqueEmail("json-delivery");
    const issued = await actor.fetch(new URL("/api/auth/sign-in/magic-link", ctx.baseURL), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: `{"email":${JSON.stringify(email)},"metadata":${metadataText}}`,
    });
    expect(issued.status).toBe(200);
    const deliveryResponse = await fetch(
      new URL(`/__test/magic-link?email=${encodeURIComponent(email)}`, ctx.baseURL),
    );
    expect(deliveryResponse.status).toBe(200);
    const delivery = z
      .object({ url: z.string(), token: z.string(), metadata: z.record(z.string(), z.unknown()) })
      .parse(await deliveryResponse.json());
    expect(delivery.metadata).toEqual(expectedMetadata);
    const verified = await actor.client.magicLink.verify({ query: { token: delivery.token } });
    expect(verified.error).toBeNull();
    const user = z.object({ id: z.string(), email: z.string() }).parse(verified.data?.user);
    expect(user.email).toBe(email);
    const current = await actor.client.getSession();
    expect(current.data?.user.id).toBe(user.id);
    expect(current.data?.session.token).toBe(verified.data?.token);
    return { delivery, verified, current };
  },
);

compatScenario(
  "arbitrary JSON key metadata persists JavaScript rounded numbers through create and update",
  async (ctx) => {
    const actor = ctx.actor();
    const signup = await actor.client.signUp.email({
      email: ctx.uniqueEmail("json-key-owner"),
      password: "password123",
      name: "JSON Key Owner",
    });
    expect(signup.error).toBeNull();
    const owner = z.object({ id: z.string() }).parse(signup.data?.user);
    const raw = await actor.fetch(new URL("/api/auth/api-key/create", ctx.baseURL), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: `{"name":"json-numbers","metadata":${metadataText}}`,
    });
    expect(raw.status).toBe(200);
    const created = z
      .object({
        id: z.string(),
        referenceId: z.string(),
        key: z.string(),
        metadata: z.record(z.string(), z.unknown()),
      })
      .passthrough()
      .parse(await raw.json());
    expect(created.referenceId).toBe(owner.id);
    expect(created.metadata).toEqual(expectedMetadata);
    const client = createAuthClient({
      baseURL: ctx.baseURL,
      plugins: [apiKeyClient()],
      fetchOptions: { customFetchImpl: actor.fetch },
    });
    const fetched = await client.apiKey.get({ query: { id: created.id } });
    expect(fetched.error).toBeNull();
    expect(fetched.data?.metadata).toEqual(expectedMetadata);
    const replacement = '{"replacement":[1e400,-0.0,9007199254740993]}';
    const updateResponse = await actor.fetch(new URL("/api/auth/api-key/update", ctx.baseURL), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: `{"keyId":${JSON.stringify(created.id)},"metadata":${replacement}}`,
    });
    expect(updateResponse.status).toBe(200);
    const updated = z
      .object({
        id: z.string(),
        referenceId: z.string(),
        metadata: z.record(z.string(), z.unknown()),
      })
      .parse(await updateResponse.json());
    expect(updated.id).toBe(created.id);
    expect(updated.referenceId).toBe(owner.id);
    expect(updated.metadata).toEqual({ replacement: [null, 0, 9007199254740992] });
    const persisted = await client.apiKey.get({ query: { id: created.id } });
    expect(persisted.error).toBeNull();
    expect(persisted.data?.metadata).toEqual(updated.metadata);
    const verify = await ctx.rawRequest({
      path: "/__test/api-key/verify",
      method: "POST",
      json: { key: created.key },
    });
    expect(verify.status).toBe(200);
    const validated = z
      .object({
        valid: z.literal(true),
        key: z.object({
          id: z.string(),
          referenceId: z.string(),
          metadata: z.record(z.string(), z.unknown()),
        }),
      })
      .parse(verify.body);
    expect(validated.key.id).toBe(created.id);
    expect(validated.key.referenceId).toBe(owner.id);
    expect(validated.key.metadata).toEqual(updated.metadata);
    const invalidNumbers = [];
    for (const [field, literal, message] of [
      ["expiresIn", "1e400", "[body.expiresIn] Invalid input: expected number, received Infinity"],
      [
        "expiresIn",
        "-1e400",
        "[body.expiresIn] Invalid input: expected number, received -Infinity",
      ],
      ["name", "1e400", "[body.name] Invalid input: expected string, received Infinity"],
    ]) {
      const rejected = await actor.fetch(new URL("/api/auth/api-key/create", ctx.baseURL), {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: `{${JSON.stringify(field)}:${literal}}`,
      });
      expect(rejected.status).toBe(400);
      const body: unknown = await rejected.json();
      expect(body).toEqual({ code: "VALIDATION_ERROR", message });
      invalidNumbers.push({ status: rejected.status, body });
    }
    const foreign = ctx.actor("foreign");
    await foreign.client.signUp.email({
      email: ctx.uniqueEmail("json-key-foreign"),
      password: "password123",
      name: "Foreign JSON Owner",
    });
    const denied = await foreign.fetch(new URL("/api/auth/api-key/update", ctx.baseURL), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: `{"keyId":${JSON.stringify(created.id)},"metadata":${metadataText}}`,
    });
    expect(denied.status).toBe(404);
    expect((await client.apiKey.get({ query: { id: created.id } })).data?.metadata).toEqual(
      updated.metadata,
    );
    return {
      created,
      fetched,
      updated,
      persisted,
      validated,
      invalidNumbers,
      denied: { status: denied.status, body: (await denied.json()) as unknown },
    };
  },
  ["POST /api-key/create", "POST /api-key/update"],
);

compatScenario(
  "organization metadata stores rounded JavaScript numbers before readback",
  async (ctx) => {
    const actor = ctx.actor();
    const signup = await actor.client.signUp.email({
      email: ctx.uniqueEmail("json-organization-owner"),
      password: "password123",
      name: "JSON Organization Owner",
    });
    expect(signup.error).toBeNull();
    const createdResponse = await actor.fetch(
      new URL("/api/auth/organization/create", ctx.baseURL),
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: `{"name":"JSON Organization","slug":${JSON.stringify(ctx.uniqueToken("json-organization"))},"metadata":${metadataText}}`,
      },
    );
    expect(createdResponse.status).toBe(200);
    const created = z
      .object({ id: z.string(), metadata: z.record(z.string(), z.unknown()) })
      .passthrough()
      .parse(await createdResponse.json());
    expect(created.metadata).toEqual(expectedMetadata);
    const read = async () => {
      // The adapter returns parsed persisted metadata for name-only updates.
      // get-full-organization exposes raw stored text in the pinned runtime and
      // has a separate organization response contract.
      const response = await actor.fetch(new URL("/api/auth/organization/update", ctx.baseURL), {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          organizationId: created.id,
          data: { name: "JSON Organization Readback" },
        }),
      });
      expect(response.status).toBe(200);
      return z
        .object({ id: z.string(), metadata: z.record(z.string(), z.unknown()) })
        .passthrough()
        .parse(await response.json());
    };
    const before = await read();
    expect(before.id).toBe(created.id);
    expect(before.metadata).toEqual(expectedMetadata);
    const updatedResponse = await actor.fetch(
      new URL("/api/auth/organization/update", ctx.baseURL),
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: `{"organizationId":${JSON.stringify(created.id)},"data":{"metadata":{"replacement":[-1e400,-0.0,9007199254740993]}}}`,
      },
    );
    expect(updatedResponse.status).toBe(200);
    const updated = z
      .object({ id: z.string(), metadata: z.record(z.string(), z.unknown()) })
      .passthrough()
      .parse(await updatedResponse.json());
    expect(updated.id).toBe(created.id);
    expect(updated.metadata).toEqual({ replacement: [null, 0, 9007199254740992] });
    const after = await read();
    expect(after.id).toBe(created.id);
    expect(after.metadata).toEqual(updated.metadata);
    return { created, before, updated, after };
  },
  ["POST /organization/create", "POST /organization/update"],
);

compatScenario(
  "JSON request grammar rejects malformed numbers structures and escapes before delivery",
  async (ctx) => {
    const actor = ctx.actor();
    const email = ctx.uniqueEmail("json-grammar");
    const rejected = [];
    for (const literal of [
      "01",
      "-01",
      "+1",
      ".1",
      "1.",
      "1e",
      "1e+",
      "NaN",
      "Infinity",
      "[1,]",
      '{"x":1,}',
      '"\\x00"',
      '"\\uZZZZ"',
      "true false",
    ]) {
      const response = await actor.fetch(new URL("/api/auth/sign-in/magic-link", ctx.baseURL), {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: `{"email":${JSON.stringify(email)},"metadata":${literal}}`,
      });
      expect(response.status).toBe(400);
      rejected.push({ status: response.status, body: (await response.json()) as unknown });
    }
    const delivery = await fetch(
      new URL(`/__test/magic-link?email=${encodeURIComponent(email)}`, ctx.baseURL),
    );
    expect(delivery.status).toBe(200);
    expect(await delivery.json()).toBeNull();
    expect((await actor.client.getSession()).data).toBeNull();
    return { rejected };
  },
);

compatScenario(
  "raw team member ID coercion selects infinity owners before JSON normalization",
  async (ctx) => {
    const { data, state, signUp, serverOperation } = await import(
      "../organization-extensions/helpers"
    );
    const owner = await signUp(ctx, "numeric-coercion-owner");
    const actor = ctx.actor("numeric-coercion-owner", "org-teams");
    const org = data(
      await owner.client.organization.create({
        name: "Numeric ID Org",
        slug: ctx.uniqueToken("numeric-id-org"),
      }),
    );
    const team = data(
      await owner.client.organization.createTeam({
        name: "Numeric ID Team",
        organizationId: org.id,
      }),
    );
    const ids = ["Infinity", "-Infinity", "Infinity,-Infinity,", "null", ",,", "[object Object]"];
    const seeded = [];
    for (const [index, id] of ids.entries()) {
      const seed = await serverOperation(ctx, {
        operation: "seed-member",
        organizationId: org.id,
        id,
        email: ctx.uniqueEmail(`numeric-member-${index}`),
        name: id,
      });
      expect(seed.status).toBe(200);
      expect(seed.body).toMatchObject({ userId: id });
      seeded.push(seed);
    }
    const results = [];
    for (const [literal, expected] of [
      ["1e400", "Infinity"],
      ["-1e400", "-Infinity"],
      ["[1e400,-1e400,null]", "Infinity,-Infinity,"],
      ['{"$serde_json::private::RawValue":"hello"}', "[object Object]"],
      ['{"$serde_json::private::Number":"1e400"}', "[object Object]"],
    ] as const) {
      const response = await actor.fetch(
        new URL("/api/auth/organization/add-team-member", ctx.baseURL),
        {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: `{"teamId":${JSON.stringify(team.id)},"organizationId":${JSON.stringify(org.id)},"userId":${literal}}`,
        },
      );
      expect(response.status).toBe(200);
      const added = z
        .object({ id: z.string(), teamId: z.string(), userId: z.string() })
        .passthrough()
        .parse(await response.json());
      expect(added.userId).toBe(expected);
      expect(added.teamId).toBe(team.id);
      const stored = await state(ctx, org.id);
      const selected = stored.parsed.teamMembers.filter((member) => member.teamId === team.id);
      expect(selected).toHaveLength(1);
      expect(selected[0]?.userId).toBe(expected);
      expect(selected.some((member) => member.userId === "null" || member.userId === ",,")).toBe(
        false,
      );
      const removedResponse = await actor.fetch(
        new URL("/api/auth/organization/remove-team-member", ctx.baseURL),
        {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: `{"teamId":${JSON.stringify(team.id)},"organizationId":${JSON.stringify(org.id)},"userId":${literal}}`,
        },
      );
      expect(removedResponse.status).toBe(200);
      const removed: unknown = await removedResponse.json();
      const after = await state(ctx, org.id);
      expect(after.parsed.teamMembers.filter((member) => member.teamId === team.id)).toHaveLength(
        0,
      );
      results.push({ added, stored: stored.raw, removed, after: after.raw });
    }
    return { seeded, results };
  },
  ["POST /organization/add-team-member", "POST /organization/remove-team-member"],
);
