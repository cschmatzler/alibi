import { expect } from "bun:test";

import { apiKeyClient } from "@better-auth/api-key/client";
import { createAuthClient } from "better-auth/client";
import { z } from "zod";

import { authProfilePath } from "../../../support/profiles";
import { compatScenario } from "../../../support/scenario";

compatScenario(
  "api-key configured maximum allows two uses and refuses the third without consuming another request",
  async (ctx) => {
    const profile = "api-key-options" as const;
    const client = createAuthClient({
      baseURL: `${ctx.baseURL}${authProfilePath(profile)}`,
      plugins: [apiKeyClient()],
      fetchOptions: { customFetchImpl: ctx.actor("rate-owner", profile).fetch },
    });
    const signup = await client.signUp.email({
      email: ctx.uniqueEmail("rate-owner"),
      name: "Rate owner",
      password: "password123",
    });
    expect(signup.error).toBeNull();
    const issued = await client.apiKey.create({ configId: "rate-max", name: "rate-key" });
    expect(issued.error).toBeNull();
    expect(issued.data?.rateLimitMax).toBe(2);
    expect(issued.data?.rateLimitTimeWindow).toBe(86400000);
    const read = async () => {
      const result = await ctx.rawRequest({ path: "/__test/api-key-options/state" });
      expect(result.status).toBe(200);
      return z
        .object({
          keys: z.array(
            z.object({
              id: z.string(),
              rateLimitMax: z.number(),
              rateLimitTimeWindow: z.number(),
              requestCount: z.number(),
              remaining: z.number().nullable(),
              lastRequest: z.string().nullable(),
            }),
          ),
        })
        .parse(result.body);
    };
    const before = await read();
    expect(before.keys[0]).toMatchObject({
      id: issued.data!.id,
      rateLimitMax: 2,
      requestCount: 0,
      remaining: null,
    });
    const uses = [];
    for (let count = 1; count <= 2; count++) {
      const result = await client.getSession({
        fetchOptions: { headers: { "x-options-rate-max": issued.data!.key } },
      });
      expect(result.error).toBeNull();
      expect(result.data?.user.id).toBe(signup.data!.user.id);
      const stored = await read();
      expect(stored.keys[0]?.requestCount).toBe(count);
      uses.push({ result, stored });
    }
    const exhausted = await read();
    const denialStarted = Date.now();
    const deniedResponse = await fetch(`${ctx.baseURL}${authProfilePath(profile)}/get-session`, {
      headers: { "x-options-rate-max": issued.data!.key },
    });
    const denied = {
      error: { ...(await deniedResponse.json()), status: deniedResponse.status },
      cookies: deniedResponse.headers.getSetCookie(),
    };
    expect(denied.error).toMatchObject({ status: 429, code: "RATE_LIMITED" });
    const denialCompleted = Date.now();
    const retry = z.object({ details: z.object({ tryAgainIn: z.number() }) }).parse(denied.error)
      .details.tryAgainIn;
    const deadline = Date.parse(exhausted.keys[0]!.lastRequest!) + 86400000;
    expect(retry).toBeGreaterThanOrEqual(Math.max(0, deadline - denialCompleted));
    expect(retry).toBeLessThanOrEqual(deadline - denialStarted);
    const observedDenial = {
      ...denied,
      error: { ...denied.error, details: { tryAgainIn: "<positive milliseconds>" } },
    };
    const after = await read();
    expect(after).toEqual(exhausted);
    return ctx.snapshot({ signup, issued, before, uses, denied: observedDenial, after });
  },
  ["POST /api-key/create", "GET /get-session"],
);
