import { expect } from "bun:test";

import { authProfilePath } from "../../../support/profiles";
import { compatScenario } from "../../../support/scenario";
compatScenario(
  "secondary rate storage shares exact client path quotas across runtimes and expires independently of disabled rules",
  async (ctx) => {
    const request = async (
      profile: "rate-limit-secondary-a" | "rate-limit-secondary-b",
      ip = "198.51.100.231",
      endpoint = "/get-session",
    ) => {
      const response = await ctx
        .actor(profile, profile)
        .fetch(ctx.baseURL + authProfilePath(profile) + endpoint, {
          headers: { "x-forwarded-for": ip },
        });
      return {
        status: response.status,
        body: await response.json(),
        headers: {
          "content-type": response.headers.get("content-type"),
          "x-retry-after": response.headers.get("x-retry-after"),
          "set-cookie": response.headers.getSetCookie(),
        },
      };
    };
    const value = async (key: string) =>
      (
        await ctx.rawRequest({
          path: `/__test/rate-limit-secondary/control?key=${encodeURIComponent(key)}`,
        })
      ).body;
    const key = "198.51.100.231|/get-session";
    expect(await value(key)).toEqual({ value: null });
    const first = await request("rate-limit-secondary-a");
    const second = await request("rate-limit-secondary-b");
    const blocked = await request("rate-limit-secondary-a");
    expect(first.status).toBe(200);
    expect(first.body).toBeNull();
    expect(second.status).toBe(200);
    expect(second.body).toBeNull();
    expect(blocked.status).toBe(429);
    expect(blocked.body).toEqual({ message: "Too many requests. Please try again later." });
    expect(blocked.headers["x-retry-after"]).toBe("1");
    expect(blocked.headers["set-cookie"]).toEqual([]);
    expect(await value(key)).toEqual({ value: "3" });
    const foreign = await request("rate-limit-secondary-b", "198.51.100.232");
    expect(foreign.status).toBe(200);
    expect(await value("198.51.100.232|/get-session")).toEqual({ value: "1" });
    const disabled = [];
    for (let i = 0; i < 3; i++) {
      const r = await request("rate-limit-secondary-a", "198.51.100.231", "/list-sessions");
      expect(r.status).toBe(401);
      disabled.push(r);
    }
    expect(await value("198.51.100.231|/list-sessions")).toEqual({ value: null });
    await Bun.sleep(1300);
    expect(await value(key)).toEqual({ value: null });
    const recovered = await request("rate-limit-secondary-b");
    expect(recovered.status).toBe(200);
    expect(await value(key)).toEqual({ value: "1" });
    return ctx.snapshot({ first, second, blocked, foreign, disabled, recovered });
  },
  ["GET /get-session", "GET /list-sessions"],
);
