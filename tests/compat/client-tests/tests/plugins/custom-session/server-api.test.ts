import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "custom session overrides server getSession with genuine callback context",
  async (ctx) => {
    const actor = ctx.actor();
    const control = (input: unknown) =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/custom-session`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(input),
      });
    const email = ctx.uniqueEmail("custom-session-sdk");
    const signup = await actor.fetch(
      `${ctx.baseURL}/__test/profiles/custom-session-server/api/auth/sign-up/email`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ email, password: "a-native-password-123", name: "Owner" }),
      },
    );
    expect(signup.status).toBe(200);
    const owner = (await signup.json()) as any;
    const cookie = signup.headers
      .getSetCookie()
      .map((value) => value.split(";")[0])
      .join("; ");
    const missing = await control({ headers: { "x-custom-session": "error" } });
    expect(missing.status).toBe(200);
    expect(await missing.json()).toBeNull();
    expect(missing.headers.get("cache-control")).toBeNull();
    const response = await control({ headers: { cookie, "x-custom-marker": "sdk" } });
    expect(response.status).toBe(200);
    const value = (await response.json()) as any;
    expect(value.application).toEqual({
      userId: owner.user.id,
      label: "Owner",
      path: "/get-session",
      hasRequest: false,
      marker: "sdk",
    });
    expect(response.headers.get("cache-control")).toBe("no-store");
    const request = await control({
      headers: { cookie, "x-custom-marker": "explicit" },
      requestHeaders: { "x-custom-marker": "original" },
    });
    expect(request.status).toBe(200);
    expect(((await request.json()) as any).application).toMatchObject({
      hasRequest: true,
      marker: "explicit",
    });
    const filtered = await control({ headers: { cookie, "x-custom-session": "filtered" } });
    expect(filtered.status).toBe(200);
    expect(await filtered.json()).toEqual({ userId: owner.user.id, label: "Owner" });
    const nil = await control({ headers: { cookie, "x-custom-session": "null" } });
    expect(nil.status).toBe(200);
    expect(await nil.json()).toBeNull();
    expect(nil.headers.get("cache-control")).toBe("no-store");
    const coded = await control({ headers: { cookie, "x-custom-session": "error" } });
    expect(coded.status).toBe(403);
    expect(await coded.json()).toMatchObject({
      code: "CUSTOM_SESSION_DENIED",
      message: "Application session denied",
    });
    const absent = await control({ requestHeaders: { cookie } });
    expect(absent.status).toBe(400);
    const http = await actor.fetch(
      `${ctx.baseURL}/__test/profiles/custom-session-server/api/auth/get-session`,
      { headers: { cookie, "x-custom-marker": "http" } },
    );
    expect(http.status).toBe(200);
    expect(((await http.json()) as any).application).toMatchObject({
      hasRequest: true,
      marker: "http",
    });
    return { overridden: true, context: true, filtered: true };
  },
);
