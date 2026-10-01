import { expect } from "bun:test";
import { compatScenario, type ScenarioContext } from "../../support/scenario";
import { authProfilePath, type FixtureProfile } from "../../support/profiles";

async function events(ctx: ScenarioContext) {
  const response = await ctx.rawRequest({ path: "/__test/dispatch-events" });
  expect(response.status).toBe(200);
  return response.body as { path: string; method: string }[];
}

for (const mode of ["default", "csrf-off", "origin-off", "origin-off-explicit-csrf", "origin-path"] as const) {
  compatScenario(`dispatch ${mode} origin and CSRF configuration preserves writes only after admission`, async ctx => {
    const profile = `dispatch-${mode}` as FixtureProfile;
    const owner = ctx.actor("owner", profile), foreign = ctx.actor("foreign", profile);
    const signup = await owner.client.signUp.email({ email: ctx.uniqueEmail("dispatch-owner"), password: "password123", name: "Owner" });
    const other = await foreign.client.signUp.email({ email: ctx.uniqueEmail("dispatch-foreign"), password: "password123", name: "Foreign" });
    expect(signup.error).toBeNull(); expect(other.error).toBeNull();
    const foreignBefore = await ctx.readUserState({ userId: other.data!.user.id });
    await events(ctx);
    const observations = [];
    for (const input of [
      { name: "foreign-cookie-origin", headers: { origin: "https://foreign.fixture.test" }, callbackURL: "/owned" },
      { name: "foreign-callback", headers: {}, callbackURL: "https://foreign.fixture.test/owned" },
    ]) {
      const before = await ctx.readUserState({ userId: signup.data!.user.id });
      const result = await owner.client.signIn.email({ email: signup.data!.user.email, password: "password123", callbackURL: input.callbackURL }, { headers: input.headers });
      const allowed = input.name === "foreign-cookie-origin" ? mode !== "default" : ["origin-off", "origin-off-explicit-csrf", "origin-path"].includes(mode);
      const after = await ctx.readUserState({ userId: signup.data!.user.id });
      const callbacks = await events(ctx);
      if (allowed) {
        expect(result.error).toBeNull();
        expect(result.data?.user.id).toBe(signup.data!.user.id);
        expect(callbacks).toEqual([{ path: "/sign-in/email", method: "POST" }]);
      } else {
        expect(result.error?.code).toBe(input.name === "foreign-cookie-origin" ? "INVALID_ORIGIN" : "INVALID_CALLBACK_URL");
        expect(after).toEqual(before); expect(callbacks).toEqual([]);
      }
      expect(await ctx.readUserState({ userId: other.data!.user.id })).toEqual(foreignBefore);
      observations.push({ input, before, result: ctx.snapshot(result), after, callbacks });
    }
    const guest = ctx.actor("cross-site", profile);
    const before = await ctx.readUserState({ userId: signup.data!.user.id });
    const navigation = await guest.client.signIn.email({ email: signup.data!.user.email, password: "password123" }, { headers: { "sec-fetch-site": "cross-site", "sec-fetch-mode": "navigate", origin: "https://foreign.fixture.test" } });
    const callbacks = await events(ctx), after = await ctx.readUserState({ userId: signup.data!.user.id });
    if (mode === "csrf-off" || mode === "origin-off") expect(navigation.error).toBeNull();
    else { expect(navigation.error?.code).toBe("CROSS_SITE_NAVIGATION_LOGIN_BLOCKED"); expect(after).toEqual(before); expect(callbacks).toEqual([{ path: "/sign-in/email", method: "POST" }]); }
    expect(await ctx.readUserState({ userId: other.data!.user.id })).toEqual(foreignBefore);
    return { signup: ctx.snapshot(signup), other: ctx.snapshot(other), observations, navigation: ctx.snapshot(navigation), callbacks, before, after, foreignBefore, foreignAfter: await ctx.readUserState({ userId: other.data!.user.id }) };
  }, ["POST /sign-up/email", "POST /sign-in/email"]);
}

for (const mode of ["default", "trailing", "disabled-email", "disabled-template", "disabled-literal"] as const) {
  compatScenario(`dispatch ${mode} literal paths and unknown methods preserve router rejection before application hooks`, async ctx => {
    const path = authProfilePath(`dispatch-${mode}` as FixtureProfile);
    await events(ctx);
    const results = [];
    for (const [route, method, expected] of [
      ["/ok/", "GET", mode === "trailing" ? 200 : 404],
      ["/ok", "POST", 404], ["/ok", "HEAD", 404],
      ["/unregistered", "POST", 404],
      ["/owned/item", "GET", mode === "disabled-literal" ? 404 : 200],
      ["/owned/item/", "GET", mode === "trailing" ? 200 : 404],
    ] as const) {
      const result = await ctx.rawRequest({ path: path + route, method });
      expect(result.status).toBe(expected);
      const callbacks = await events(ctx);
      expect(callbacks).toEqual(expected === 200 ? [{ path: route, method }] : []);
      results.push({ route, method, result, callbacks });
    }
    if (mode === "disabled-email") {
      const result = await ctx.rawRequest({ path: path + "/sign-in/email/", method: "POST", body: "{", headers: { "content-type": "application/json", origin: "https://foreign.fixture.test" } });
      expect(result).toEqual({ status: 404, location: null, body: "Not Found" });
      expect(await events(ctx)).toEqual([]); results.push({ route: "/sign-in/email/", method: "POST", result, callbacks: [] });
    }
    return results;
  }, ["GET /ok", "POST /sign-in/email"]);
}

compatScenario("dispatch media and JSON syntax validation precede origin rejection and preserve physical principals", async ctx => {
  const profile: FixtureProfile = "dispatch-default", path = authProfilePath(profile);
  const owner = ctx.actor("owner", profile), foreign = ctx.actor("foreign", profile);
  const signup = await owner.client.signUp.email({ email: ctx.uniqueEmail("media-owner"), name: "Owner", password: "password123" });
  const other = await foreign.client.signUp.email({ email: ctx.uniqueEmail("media-foreign"), name: "Foreign", password: "password123" });
  expect(signup.error).toBeNull(); expect(other.error).toBeNull();
  await events(ctx);
  const foreignBefore = await ctx.readUserState({ userId: other.data!.user.id });
  const results = [];
  for (const [name, contentType, body, status, code] of [
    ["text", "text/plain", JSON.stringify({ email: signup.data!.user.email, password: "password123" }), 415, "UNSUPPORTED_MEDIA_TYPE"],
    ["missing", "", JSON.stringify({ email: signup.data!.user.email, password: "password123" }), 415, "UNSUPPORTED_MEDIA_TYPE"],
    ["malformed", "application/json", "{", 400, "BAD_REQUEST"],
    ["form", "application/x-www-form-urlencoded", new URLSearchParams({ email: signup.data!.user.email, password: "password123" }).toString(), 200, null],
    ["json-parameter", "Application/JSON; charset=UTF-8", JSON.stringify({ email: signup.data!.user.email, password: "password123" }), 200, null],
  ] as const) {
    const before = await ctx.readUserState({ userId: signup.data!.user.id });
    const result = await ctx.rawRequest({ actor: `media-${name}`, path: path + "/sign-in/email", method: "POST", body, headers: { "content-type": contentType, ...(status !== 200 ? { origin: "https://foreign.fixture.test" } : {}) } });
    expect(result.status).toBe(status);
    const after = await ctx.readUserState({ userId: signup.data!.user.id }), callbacks = await events(ctx);
    if (status !== 200) { expect(result.body).toMatchObject({ code }); expect(after).toEqual(before); expect(callbacks).toEqual([]); }
    else { expect(callbacks).toEqual([{ path: "/sign-in/email", method: "POST" }]); expect(result.body).toMatchObject({ user: { id: signup.data!.user.id } }); }
    expect(await ctx.readUserState({ userId: other.data!.user.id })).toEqual(foreignBefore);
    results.push({ name, contentType, body, before, result, after, callbacks });
  }
  return { signup: ctx.snapshot(signup), other: ctx.snapshot(other), results, foreignBefore, foreignAfter: await ctx.readUserState({ userId: other.data!.user.id }) };
}, ["POST /sign-up/email", "POST /sign-in/email"]);
