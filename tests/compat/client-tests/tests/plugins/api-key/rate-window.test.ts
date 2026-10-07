import { expect } from "bun:test";

import { apiKeyClient } from "@better-auth/api-key/client";
import { createAuthClient } from "better-auth/client";
import { z } from "zod";

import { authProfilePath } from "../../../support/profiles";
import { compatScenario } from "../../../support/scenario";

compatScenario(
  "api-key configured window expires its per-key throttle and resets request count",
  async (ctx) => {
    const profile = "api-key-options" as const;
    const client = createAuthClient({
      baseURL: `${ctx.baseURL}${authProfilePath(profile)}`,
      plugins: [apiKeyClient()],
      fetchOptions: { customFetchImpl: ctx.actor("window-owner", profile).fetch },
    });
    const signup = await client.signUp.email({
      email: ctx.uniqueEmail("window-owner"),
      name: "Window owner",
      password: "password123",
    });
    expect(signup.error).toBeNull();
    const issued = await ctx.rawRequest({
      path: "/__test/api-key-options/create",
      method: "POST",
      json: {
        configId: "rate-window",
        userId: signup.data!.user.id,
        name: "window-key",
        rateLimitMax: 1,
      },
    });
    const key = z
      .object({
        value: z.object({
          id: z.string(),
          key: z.string(),
          rateLimitTimeWindow: z.number(),
          rateLimitMax: z.number(),
        }),
        error: z.null(),
      })
      .parse(issued.body).value;
    expect(key.rateLimitTimeWindow).toBe(600);
    expect(key.rateLimitMax).toBe(1);
    const read = async () => {
      const result = await ctx.rawRequest({ path: "/__test/api-key-options/state" });
      expect(result.status).toBe(200);
      return z
        .object({
          keys: z.array(
            z.object({
              id: z.string(),
              rateLimitTimeWindow: z.number(),
              requestCount: z.number(),
              lastRequest: z.string().nullable(),
            }),
          ),
        })
        .parse(result.body);
    };
    const before = await read();
    expect(before.keys[0]).toMatchObject({ id: key.id, rateLimitTimeWindow: 600, requestCount: 0 });
    const use = () =>
      client.getSession({ fetchOptions: { headers: { "x-options-rate-window": key.key } } });
    const first = await use();
    expect(first.error).toBeNull();
    const used = await read();
    expect(used.keys[0]?.requestCount).toBe(1);
    const denialStarted = Date.now();
    const deniedResponse = await fetch(`${ctx.baseURL}${authProfilePath(profile)}/get-session`, {
      headers: { "x-options-rate-window": key.key },
    });
    const denied = {
      error: { ...(await deniedResponse.json()), status: deniedResponse.status },
      cookies: deniedResponse.headers.getSetCookie(),
    };
    expect(denied.error).toMatchObject({ status: 429, code: "RATE_LIMITED" });
    const denialCompleted = Date.now();
    const retry = z.object({ details: z.object({ tryAgainIn: z.number() }) }).parse(denied.error)
      .details.tryAgainIn;
    const deadline = Date.parse(used.keys[0]!.lastRequest!) + 600;
    expect(retry).toBeGreaterThanOrEqual(Math.max(0, deadline - denialCompleted));
    expect(retry).toBeLessThanOrEqual(deadline - denialStarted);
    const observedDenial = {
      ...denied,
      error: { ...denied.error, details: { tryAgainIn: "<positive milliseconds>" } },
    };
    expect(await read()).toEqual(used);
    await Bun.sleep(Math.max(0, Date.parse(used.keys[0]!.lastRequest!) + 600 - Date.now()) + 100);
    const renewed = await use();
    expect(renewed.error).toBeNull();
    expect(renewed.data?.user.id).toBe(signup.data!.user.id);
    const after = await read();
    expect(after.keys[0]?.requestCount).toBe(1);
    expect(Date.parse(after.keys[0]!.lastRequest!)).toBeGreaterThan(
      Date.parse(used.keys[0]!.lastRequest!),
    );
    return ctx.snapshot({
      signup,
      issued,
      before,
      first,
      used,
      denied: observedDenial,
      renewed,
      after,
    });
  },
  ["POST /api-key/create", "GET /get-session"],
);
