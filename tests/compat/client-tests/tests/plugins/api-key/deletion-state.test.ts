import { expect } from "bun:test";

import { apiKeyClient } from "@better-auth/api-key/client";
import { createAuthClient } from "better-auth/client";
import { z } from "zod";

import { compatScenario, type ScenarioContext } from "../../../support/scenario";

async function state(ctx: ScenarioContext) {
  const result = await ctx.rawRequest({ path: "/__test/api-key-options/state" });
  expect(result.status).toBe(200);
  return z
    .object({
      keys: z.array(
        z.object({
          id: z.string(),
          referenceId: z.string(),
          name: z.string().nullable(),
          enabled: z.boolean(),
          key: z.string(),
          metadata: z.string().nullable(),
          createdAt: z.string(),
          updatedAt: z.string(),
        }),
      ),
    })
    .parse(result.body);
}

compatScenario(
  "api-key explicit deletion removes only the selected stored key and cannot be replayed",
  async (ctx) => {
    const make = (name: string) =>
      createAuthClient({
        baseURL: ctx.baseURL,
        plugins: [apiKeyClient()],
        fetchOptions: { customFetchImpl: ctx.actor(name).fetch },
      });
    const owner = make("delete-owner");
    const foreign = make("delete-foreign");
    for (const [name, client] of [
      ["delete-owner", owner],
      ["delete-foreign", foreign],
    ] as const) {
      expect(
        (await client.signUp.email({ email: ctx.uniqueEmail(name), name, password: "password123" }))
          .error,
      ).toBeNull();
    }
    const target = await owner.apiKey.create({ name: "delete-target" });
    const sibling = await owner.apiKey.create({ name: "delete-sibling" });
    const guard = await foreign.apiKey.create({ name: "delete-foreign" });
    expect(target.error).toBeNull();
    expect(sibling.error).toBeNull();
    expect(guard.error).toBeNull();
    if (!target.data || !sibling.data || !guard.data) throw new Error("persisted keys required");
    const before = await state(ctx);
    expect(before.keys.map((row) => row.id).sort()).toEqual(
      [target.data.id, sibling.data.id, guard.data.id].sort(),
    );
    const denied = await foreign.apiKey.delete({ keyId: target.data.id });
    expect(denied.error).not.toBeNull();
    expect(await state(ctx)).toEqual(before);
    const deleted = await owner.apiKey.delete({ keyId: target.data.id });
    expect(deleted.error).toBeNull();
    const after = await state(ctx);
    expect(after.keys).toEqual(before.keys.filter((row) => row.id !== target.data!.id));
    const fetched = await owner.apiKey.get({ query: { id: target.data.id } });
    const repeated = await owner.apiKey.delete({ keyId: target.data.id });
    expect(fetched.error).not.toBeNull();
    expect(repeated.error).not.toBeNull();
    expect(await state(ctx)).toEqual(after);
    const replacement = await owner.apiKey.create({ name: "delete-target" });
    expect(replacement.error).toBeNull();
    expect(replacement.data?.id).not.toBe(target.data.id);
    const regenerated = await state(ctx);
    expect(regenerated.keys.some((row) => row.id === target.data!.id)).toBe(false);
    expect(regenerated.keys).toHaveLength(3);
    for (const retained of after.keys) expect(regenerated.keys).toContainEqual(retained);
    return ctx.snapshot({
      target,
      sibling,
      guard,
      before,
      denied,
      deleted,
      after,
      fetched,
      repeated,
      replacement,
      regenerated,
    });
  },
  ["POST /api-key/delete"],
);
