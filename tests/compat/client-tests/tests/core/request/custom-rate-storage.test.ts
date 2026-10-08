import { expect } from "bun:test";

import { authProfilePath } from "../../../support/profiles";
import { compatScenario } from "../../../support/scenario";
compatScenario(
  "custom rate storage overrides secondary selection and preserves quota across storage rejection recovery",
  async (ctx) => {
    const actor = ctx.actor("limiter", "rate-limit-custom");
    const request = async (
      profile: "rate-limit-custom" | "rate-limit-custom-memory" = "rate-limit-custom",
    ) => {
      const r = await actor.fetch(ctx.baseURL + authProfilePath(profile) + "/get-session", {
        headers: { "x-forwarded-for": "198.51.100.241" },
      });
      return {
        status: r.status,
        body: await r.text().then((text) => {
          try {
            return JSON.parse(text);
          } catch {
            return text;
          }
        }),
        headers: {
          "content-type": r.headers.get("content-type"),
          "x-retry-after": r.headers.get("x-retry-after"),
          "set-cookie": r.headers.getSetCookie(),
        },
      };
    };
    const control = async (failure?: boolean) =>
      (
        await ctx.rawRequest({
          path: "/__test/rate-limit-custom/control",
          ...(failure === undefined ? {} : { method: "POST", json: { failure } }),
        })
      ).body as any;
    expect((await control(false)).rows).toEqual([]);
    const first = await request();
    expect(first.status).toBe(200);
    const saved = await control();
    expect(saved.rows).toHaveLength(1);
    expect(saved.rows[0]).toMatchObject({ key: "198.51.100.241|/get-session", count: 1 });
    await control(true);
    const rejected = await request();
    expect(rejected.status).toBe(500);
    expect(rejected.body).toEqual({ message: "Internal server error" });
    expect(rejected.headers["content-type"]).toBe("application/json;charset=utf-8");
    expect(rejected.headers["set-cookie"]).toEqual([]);
    expect((await control()).rows).toEqual(saved.rows);
    const memory = await request("rate-limit-custom-memory");
    expect(memory.status).toBe(200);
    await control(false);
    const second = await request();
    expect(second.status).toBe(200);
    const blocked = await request();
    expect(blocked.status).toBe(429);
    expect(blocked.body).toEqual({ message: "Too many requests. Please try again later." });
    expect(blocked.headers["x-retry-after"]).toBe("1");
    const limited = await control();
    expect(limited.rows[0].count).toBe(2);
    await Bun.sleep(1300);
    const recovered = await request();
    expect(recovered.status).toBe(200);
    const after = await control();
    expect(after.rows[0].count).toBe(1);
    expect(recovered.headers["set-cookie"]).toEqual([]);
    return ctx.snapshot({
      first,
      saved,
      rejected,
      memory,
      second,
      blocked,
      limited,
      recovered,
      after,
    });
  },
  ["GET /get-session"],
  30_000,
  {
    oracle: {
      collapsedFixtureErrors:
        "The scenario deliberately makes the configured atomic consume callback throw, then verifies unchanged stored quota, masked body and headers, unaffected memory storage and successful recovery.",
    },
  },
);
