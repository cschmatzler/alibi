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

compatScenario(
  "secondary rate storage rejects missing and failing atomic increments without signup mutation or fallback",
  async (ctx) => {
    const profile = "rate-limit-secondary-failure";
    const control = async (mode?: string) => {
      const response = await fetch(
        `${ctx.baseURL}/__test/rate-limit-secondary/failure`,
        mode
          ? {
              method: "POST",
              headers: { "content-type": "application/json" },
              body: JSON.stringify({ mode }),
            }
          : undefined,
      );
      expect(response.status).toBe(200);
      return (await response.json()) as { events: string[] };
    };
    const physical = async () => {
      const response = await fetch(`${ctx.baseURL}/__test/provider-batch/sql-state`);
      expect(response.status).toBe(200);
      return response.json();
    };
    const wire: { status: number; cookies: string[] }[] = [];
    const signUp = (name: string, ip: string, bypass = false) =>
      ctx.actor(name, profile).client.signUp.email({
        email: ctx.uniqueEmail(name),
        password: "password123",
        name,
        fetchOptions: {
          headers: { "x-forwarded-for": ip, ...(bypass ? { "x-rate-bypass": "yes" } : {}) },
          onResponse: ({ response }) => {
            wire.push({ status: response.status, cookies: response.headers.getSetCookie() });
          },
        },
      });
    const observations = [];
    const mismatches = [];
    for (const [index, mode] of ["missing", "throws"].entries()) {
      const ip = `198.51.100.${240 + index}`;
      await control(mode);
      const before = await physical();
      const failed = await signUp(`atomic-${mode}-blocked`, ip);
      expect(failed.data).toBeNull();
      expect(failed.error?.status).toBe(500);
      expect(wire.at(-1)).toEqual({ status: 500, cookies: [] });
      expect(await physical()).toEqual(before);
      const failedCalls = await control();
      expect(failedCalls.events).toEqual(mode === "missing" ? [] : ["increment"]);
      // The reference exposes an empty 500 body through the SDK. Keep failure
      // comparison last so recovery and physical invariants run on both engines.
      if (
        JSON.stringify(failed.error) !==
        JSON.stringify({ status: 500, statusText: "Internal Server Error" })
      )
        mismatches.push({ mode, error: failed.error });
      const disabled = await signUp(`atomic-${mode}-disabled`, ip, true);
      expect(disabled.error).toBeNull();
      expect(disabled.data?.user.email).toBe(ctx.uniqueEmail(`atomic-${mode}-disabled`));
      expect((await control()).events).not.toContain("increment");
      await control("normal");
      const owner = await ctx.actor(`atomic-${mode}-disabled`, profile).client.getSession();
      expect(owner.data?.user.id).toBe(disabled.data!.user.id);
      const first = await signUp(`atomic-${mode}-first`, ip);
      const second = await signUp(`atomic-${mode}-second`, ip);
      expect(first.error).toBeNull();
      expect(second.error).toBeNull();
      const quotaBefore = await physical();
      const rejected = await signUp(`atomic-${mode}-over-quota`, ip);
      expect(rejected.error).toMatchObject({
        status: 429,
        message: "Too many requests. Please try again later.",
      });
      expect(rejected.data).toBeNull();
      expect(wire.at(-1)).toEqual({ status: 429, cookies: [] });
      expect(await physical()).toEqual(quotaBefore);
      observations.push({
        mode,
        failed,
        failedCalls,
        disabled,
        owner,
        first,
        second,
        rejected,
      });
    }
    expect(mismatches).toEqual([]);
    return ctx.snapshot({ observations, wire });
  },
  ["POST /sign-up/email"],
);
