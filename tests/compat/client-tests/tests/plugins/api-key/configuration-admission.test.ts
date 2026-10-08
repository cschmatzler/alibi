import { expect } from "bun:test";

import { apiKeyClient } from "@better-auth/api-key/client";
import { createAuthClient } from "better-auth/client";

import { authProfilePath } from "../../../support/profiles";
import { compatScenario } from "../../../support/scenario";
// Getter runtime type violations cannot cross Rust's AuthResult<Option<String>>
// callback boundary. Existing options-installed-state owns invalid identity refs;
// generation-cleanup owns client server-only fields (they are server denials).
compatScenario(
  "API-key named-only configuration rejects absent and unknown selectors without persistence",
  async (ctx) => {
    const profile = "api-key-no-default";
    const client = createAuthClient({
      baseURL: ctx.baseURL + authProfilePath(profile),
      plugins: [apiKeyClient()],
      fetchOptions: { customFetchImpl: ctx.actor("owner", profile).fetch },
    });
    const signup = await client.signUp.email({
      email: ctx.uniqueEmail("no-default-owner"),
      name: "Owner",
      password: "password123",
    });
    expect(signup.error).toBeNull();
    const read = async () => (await ctx.rawRequest({ path: "/__test/api-key-options/state" })).body;
    const before = await read();
    const denied = [];
    for (const configId of [undefined, "unknown", "default"]) {
      const result = await client.apiKey.create({
        ...(configId === undefined ? {} : { configId }),
        name: "Rejected key",
      });
      expect(result.error).toMatchObject({
        status: 400,
        code: "NO_DEFAULT_API_KEY_CONFIGURATION_FOUND",
      });
      expect(await read()).toEqual(before);
      denied.push({ configId: configId ?? null, result });
    }
    const accepted = await client.apiKey.create({ configId: "other", name: "Named key" });
    expect(accepted.error).toBeNull();
    expect(accepted.data!.configId).toBe("other");
    const fetched = await client.apiKey.get({
      query: { id: accepted.data!.id, configId: "other" },
    });
    expect(fetched.error).toBeNull();
    expect(fetched.data!.referenceId).toBe(signup.data!.user.id);
    return ctx.snapshot({ signup, before, denied, accepted, fetched });
  },
  ["POST /api-key/create", "GET /api-key/get"],
);
