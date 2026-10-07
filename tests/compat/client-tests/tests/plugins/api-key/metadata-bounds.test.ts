import { expect } from "bun:test";

import { apiKeyClient } from "@better-auth/api-key/client";
import { createAuthClient } from "better-auth/client";
import { z } from "zod";

import { authProfilePath } from "../../../support/profiles";
import { compatScenario } from "../../../support/scenario";

compatScenario(
  "api-key metadata and prefix name bounds reject without creating keys and permit valid retries",
  async (ctx) => {
    const profile = "api-key-options" as const;
    const actor = ctx.actor("metadata-owner", profile);
    const client = createAuthClient({
      baseURL: `${ctx.baseURL}${authProfilePath(profile)}`,
      plugins: [apiKeyClient()],
      fetchOptions: { customFetchImpl: actor.fetch },
    });
    const signup = await client.signUp.email({
      email: ctx.uniqueEmail("metadata-owner"),
      name: "Metadata owner",
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
              configId: z.string(),
              name: z.string().nullable(),
              metadata: z.string().nullable(),
            }),
          ),
        })
        .parse(result.body);
    };
    const before = await read();
    const observations = [];
    for (const [body, code] of [
      [
        { configId: "metadata-disabled", name: "metadata", metadata: { purpose: "forbidden" } },
        "METADATA_DISABLED",
      ],
      [{ configId: "default", metadata: "invalid" }, "INVALID_METADATA_TYPE"],
      [{ configId: "policy-fraction", name: "ok", prefix: "x" }, "INVALID_PREFIX_LENGTH"],
      [{ configId: "policy-fraction", name: "ok", prefix: "xxx" }, "INVALID_PREFIX_LENGTH"],
      [{ configId: "policy-fraction", name: "x" }, "INVALID_NAME_LENGTH"],
      [{ configId: "policy-fraction", name: "xxxx" }, "INVALID_NAME_LENGTH"],
    ] as const) {
      const response = await actor.fetch(
        `${ctx.baseURL}${authProfilePath(profile)}/api-key/create`,
        {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(body),
        },
      );
      const result = { status: response.status, body: await response.json() };
      expect(result.status).toBe(400);
      expect(result.body).toMatchObject({ code });
      expect(await read()).toEqual(before);
      observations.push(result);
    }
    const valid = await client.apiKey.create({
      configId: "default",
      name: "metadata",
      metadata: { purpose: "valid" },
    });
    expect(valid.error).toBeNull();
    const after = await read();
    expect(after.keys).toEqual([
      {
        id: valid.data!.id,
        configId: "default",
        name: "metadata",
        metadata: JSON.stringify({ purpose: "valid" }),
      },
    ]);
    return ctx.snapshot({ signup, before, observations, valid, after });
  },
  ["POST /api-key/create"],
);
