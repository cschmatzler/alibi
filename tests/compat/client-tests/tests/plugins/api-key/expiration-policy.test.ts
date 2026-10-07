import { expect } from "bun:test";

import { apiKeyClient } from "@better-auth/api-key/client";
import { createAuthClient } from "better-auth/client";
import { z } from "zod";

import { authProfilePath } from "../../../support/profiles";
import { compatScenario } from "../../../support/scenario";

compatScenario(
  "api-key disabled custom expiration rejects create and update overrides while preserving its default lifetime",
  async (ctx) => {
    const configId = "expiration-disabled";
    const client = createAuthClient({
      baseURL: `${ctx.baseURL}${authProfilePath("api-key-options")}`,
      plugins: [apiKeyClient()],
      fetchOptions: { customFetchImpl: ctx.actor("expiry-owner", "api-key-options").fetch },
    });
    const signup = await client.signUp.email({
      email: ctx.uniqueEmail("expiry-owner"),
      name: "Expiry owner",
      password: "password123",
    });
    expect(signup.error).toBeNull();
    const read = async () => {
      const result = await ctx.rawRequest({ path: "/__test/api-key-options/state" });
      expect(result.status).toBe(200);
      return z
        .object({
          keys: z.array(
            z.object({
              id: z.string(),
              name: z.string().nullable(),
              configId: z.string(),
              expiresAt: z.string().nullable(),
              createdAt: z.string(),
              updatedAt: z.string(),
            }),
          ),
        })
        .parse(result.body);
    };
    const before = await read();
    const rejected = await client.apiKey.create({ configId, name: "rejected", expiresIn: 60 });
    expect(rejected.error).toMatchObject({ status: 400, code: "KEY_DISABLED_EXPIRATION" });
    expect(await read()).toEqual(before);
    const started = Date.now();
    const issued = await client.apiKey.create({ configId, name: "default-expiration" });
    expect(issued.error).toBeNull();
    const completed = Date.now();
    const stored = await read();
    expect(stored.keys).toHaveLength(1);
    expect(stored.keys[0]!.id).toBe(issued.data!.id);
    const expiry = Date.parse(stored.keys[0]!.expiresAt!);
    expect(expiry).toBeGreaterThanOrEqual(started + 120000);
    expect(expiry).toBeLessThanOrEqual(completed + 120000);
    const updated = await client.apiKey.update({ configId, keyId: issued.data!.id, expiresIn: 60 });
    expect(updated.error).toMatchObject({ status: 400, code: "KEY_DISABLED_EXPIRATION" });
    expect(await read()).toEqual(stored);
    const renamed = await client.apiKey.update({
      configId,
      keyId: issued.data!.id,
      name: "renamed",
    });
    expect(renamed.error).toBeNull();
    expect(renamed.data?.expiresAt).toEqual(issued.data?.expiresAt);
    const after = await read();
    expect(after.keys[0]!.expiresAt).toBe(stored.keys[0]!.expiresAt);
    return ctx.snapshot({ signup, before, rejected, issued, stored, updated, renamed, after });
  },
  ["POST /api-key/create", "POST /api-key/update"],
);
