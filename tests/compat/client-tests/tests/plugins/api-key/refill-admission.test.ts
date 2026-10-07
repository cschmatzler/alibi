import { expect } from "bun:test";

import { compatScenario } from "../../../support/scenario";

compatScenario(
  "api-key server rejects half refill policies without persisting keys and decays usage",
  async (ctx) => {
    const actor = ctx.actor("owner", "api-key-options");
    const signup = await actor.client.signUp.email({
      email: ctx.uniqueEmail("refill-guards"),
      name: "Refill Owner",
      password: "password123",
    });
    expect(signup.error).toBeNull();
    const state = async () =>
      (await ctx.rawRequest({ path: "/__test/api-key-options/state" })).body;
    const before = await state();
    const denials = [];
    for (const [fields, code] of [
      [{ refillAmount: 2 }, "REFILL_AMOUNT_AND_INTERVAL_REQUIRED"],
      [{ refillInterval: 60000 }, "REFILL_INTERVAL_AND_AMOUNT_REQUIRED"],
    ] as const) {
      const response = await ctx.rawRequest({
        path: "/__test/api-key-options/create",
        method: "POST",
        json: {
          userId: signup.data!.user.id,
          configId: "default",
          name: "invalid-refill",
          ...fields,
        },
      });
      expect(response.status).toBe(200);
      expect(response.body).toMatchObject({
        value: null,
        error: { api: true, status: 400, body: { code } },
      });
      expect(await state()).toEqual(before);
      denials.push(response);
    }
    const issued = await ctx.rawRequest({
      path: "/__test/api-key-options/create",
      method: "POST",
      json: {
        userId: signup.data!.user.id,
        configId: "default",
        name: "usage-key",
        remaining: 1,
        refillAmount: 2,
        refillInterval: 60000,
      },
    });
    const key = (issued.body as any).value;
    expect(key.remaining).toBe(1);
    expect(key.requestCount).toBe(0);
    const first = await ctx.rawRequest({
      path: "/__test/api-key-options/verify",
      method: "POST",
      json: { input: { key: key.key, configId: "default" } },
    });
    expect(first.body).toMatchObject({
      value: { valid: true, key: { remaining: 0, requestCount: 0 } },
      error: null,
    });
    const exhausted = await ctx.rawRequest({
      path: "/__test/api-key-options/verify",
      method: "POST",
      json: { input: { key: key.key, configId: "default" } },
    });
    expect(exhausted.body).toMatchObject({
      value: { valid: false, error: { code: "USAGE_EXCEEDED" } },
      error: null,
    });
    const readback = await actor.fetch(
      `${ctx.baseURL}/__test/profiles/api-key-options/api/auth/api-key/get?id=${key.id}`,
    );
    expect(readback.status).toBe(200);
    const stored = await readback.json();
    expect(stored.remaining).toBe(0);
    expect(stored.requestCount).toBe(0);
    return ctx.snapshot({ denials, issued, first, exhausted, stored });
  },
  ["POST /api-key/create", "GET /api-key/get"],
);
