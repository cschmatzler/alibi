import { expect } from "bun:test";

import { apiKeyClient } from "@better-auth/api-key/client";
import { createAuthClient } from "better-auth/client";
import { z } from "zod";

import { authProfilePath } from "../../../support/profiles";
import { compatScenario } from "../../../support/scenario";

compatScenario(
  "api-key required and optional name policies persist null names and project them through get and list",
  async (ctx) => {
    const client = createAuthClient({
      baseURL: `${ctx.baseURL}${authProfilePath("api-key-options")}`,
      plugins: [apiKeyClient()],
      fetchOptions: { customFetchImpl: ctx.actor("name-owner", "api-key-options").fetch },
    });
    const signup = await client.signUp.email({
      email: ctx.uniqueEmail("name-owner"),
      name: "Name owner",
      password: "password123",
    });
    expect(signup.error).toBeNull();
    const read = async () => {
      const response = await ctx.rawRequest({ path: "/__test/api-key-options/state" });
      expect(response.status).toBe(200);
      const parsed = z
        .object({
          keys: z.array(
            z.object({
              id: z.string(),
              configId: z.string(),
              name: z.string().nullable(),
              referenceId: z.string(),
            }),
          ),
        })
        .parse(response.body);
      parsed.keys.sort(
        (a, b) =>
          a.configId.localeCompare(b.configId) || (a.name ?? "").localeCompare(b.name ?? ""),
      );
      return parsed;
    };
    const observations = [];
    for (const configId of ["name-optional", "name-required"]) {
      const before = await read();
      const absent = await client.apiKey.create({ configId });
      if (configId === "name-required") {
        expect(absent.error).toMatchObject({ status: 400, code: "NAME_REQUIRED" });
        expect(await read()).toEqual(before);
      } else {
        expect(absent.error).toBeNull();
        expect(absent.data?.name).toBeNull();
        const stored = await read();
        expect(stored.keys).toContainEqual({
          id: absent.data!.id,
          configId,
          name: null,
          referenceId: signup.data!.user.id,
        });
        const fetched = await client.apiKey.get({ query: { id: absent.data!.id, configId } });
        const listed = await client.apiKey.list({ query: { configId } });
        expect(fetched.error).toBeNull();
        expect(fetched.data?.name).toBeNull();
        expect(listed.error).toBeNull();
        expect(listed.data?.apiKeys).toContainEqual(
          expect.objectContaining({ id: absent.data!.id, name: null }),
        );
        observations.push({ stored, fetched, listed });
      }
      const named = await client.apiKey.create({ configId, name: "Named key" });
      expect(named.error).toBeNull();
      expect(named.data?.name).toBe("Named key");
      observations.push({ configId, absent, named, after: await read() });
    }
    return ctx.snapshot({ signup, observations });
  },
  ["POST /api-key/create", "GET /api-key/get", "GET /api-key/list"],
);
