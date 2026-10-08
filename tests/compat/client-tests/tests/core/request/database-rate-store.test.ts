import { expect } from "bun:test";

import { authProfilePath } from "../../../support/profiles";
import { compatScenario } from "../../../support/scenario";

compatScenario(
  "database limiter shares quota across auth instances and resets persisted bucket",
  async (ctx) => {
    const ip = "198.51.100.232";
    const request = async (
      profile: "rate-limit-database-first" | "rate-limit-database-second",
      clientIp = ip,
    ) => {
      const response = await ctx
        .actor(profile, profile)
        .fetch(ctx.baseURL + authProfilePath(profile) + "/get-session", {
          headers: { "x-forwarded-for": clientIp },
        });
      return {
        status: response.status,
        body: await response.json(),
        retry: response.headers.get("x-retry-after"),
        cookies: response.headers.getSetCookie(),
      };
    };
    const read = async () =>
      (await ctx.rawRequest({ path: "/__test/rate-database-state" })).body as any[];
    const initial = Date.now();
    const first = await request("rate-limit-database-first");
    const second = await request("rate-limit-database-second");
    expect(first).toEqual({ status: 200, body: null, retry: null, cookies: [] });
    expect(second).toEqual(first);
    const before = await read();
    const bucket = before.find((row) => row.key.includes(ip));
    expect(bucket).toBeDefined();
    expect(bucket.count).toBe(2);
    expect(bucket.lastRequest).toBeGreaterThanOrEqual(initial);
    expect(bucket.lastRequest).toBeLessThanOrEqual(Date.now());
    const denied = await request("rate-limit-database-first");
    expect(denied).toEqual({
      status: 429,
      body: { message: "Too many requests. Please try again later." },
      retry: "1",
      cookies: [],
    });
    expect(await read()).toEqual(before);
    const independent = await request("rate-limit-database-second", "198.51.100.233");
    expect(independent).toEqual(first);
    await Bun.sleep(1200);
    const resumed = await request("rate-limit-database-second");
    expect(resumed).toEqual(first);
    const after = await read();
    const renewed = after.find((row) => row.key === bucket.key);
    expect(renewed.count).toBe(1);
    expect(renewed.lastRequest).toBeGreaterThan(bucket.lastRequest);
    const outage = await ctx.rawRequest({
      path: "/__test/rate-database-control",
      method: "POST",
      json: { action: "disable" },
    });
    expect(outage.body).toEqual({ status: true });
    let failure;
    try {
      const response = await ctx
        .actor("outage", "rate-limit-database-first")
        .fetch(ctx.baseURL + authProfilePath("rate-limit-database-first") + "/get-session", {
          headers: { "x-forwarded-for": "198.51.100.234" },
        });
      expect(response.status).toBe(500);
      expect(response.headers.getSetCookie()).toEqual([]);
      failure = {
        status: response.status,
        body: await response.text(),
        contentType: response.headers.get("content-type"),
        cookies: response.headers.getSetCookie(),
      };
    } finally {
      expect(
        (
          await ctx.rawRequest({
            path: "/__test/rate-database-control",
            method: "POST",
            json: { action: "restore" },
          })
        ).body,
      ).toEqual({ status: true });
    }
    expect(await read()).toEqual(after);
    const recovered = await request("rate-limit-database-first", "198.51.100.234");
    expect(recovered).toEqual(first);
    const project = (rows: any[]) =>
      rows.map(({ key, count, lastRequest }) => ({
        key,
        count,
        lastRequest: new Date(lastRequest).toISOString(),
      }));
    return {
      first,
      second,
      denied,
      independent,
      resumed,
      failure,
      recovered,
      before: project(before),
      after: project(after),
    };
  },
  ["GET /get-session"],
  30_000,
  {
    oracle: {
      collapsedFixtureErrors:
        "The scenario deliberately retires the backing rate_limit table, then verifies unchanged quota after restoration, masked body and headers, and successful recovery.",
    },
  },
);
