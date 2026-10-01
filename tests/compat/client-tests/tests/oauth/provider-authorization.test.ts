import { expect } from "bun:test";
import { compatScenario, type ScenarioContext } from "../../support/scenario";
import { authProfilePath, type FixtureProfile } from "../../support/profiles";

type ProviderState = {
  users: { id: string; email: string; name: string; image: string | null }[];
  accounts: { id: string; userId: string; providerId: string; accountId: string; scope: string | null; accessToken: string | null }[];
  sessions: { id: string; userId: string; token: string }[];
  receipts: { path: string; method: string; authorization: string | null; contentType: string | null; body: Record<string, string> | null }[];
};
async function state(ctx: ScenarioContext) {
  const response = await ctx.rawRequest({ path: "/__test/social-provider/state" });
  expect(response.status).toBe(200);
  return response.body as ProviderState;
}
const expectedOrigins = { google: "https://accounts.google.com/o/oauth2/v2/auth", github: "https://github.com/login/oauth/authorize", discord: "https://discord.com/api/oauth2/authorize" };

compatScenario("builtin social authorization retains ordered default configured and requested scopes", async ctx => {
  const before = await state(ctx);
  const requested = [undefined, [], ["request-scope", "email", "email"], [""]] as const;
  const table = [
    ["google", "default", ["email profile openid", "email profile openid", "email profile openid request-scope email email", "email profile openid "]],
    ["google", "configured", ["email profile openid configured-scope", "email profile openid configured-scope", "email profile openid configured-scope request-scope email email", "email profile openid configured-scope "]],
    ["google", "disabled", [null, null, "request-scope email email", ""]],
    ["google", "disabled-configured", ["configured-scope", "configured-scope", "configured-scope request-scope email email", "configured-scope "]],
    ["github", "default", ["read:user user:email", "read:user user:email", "read:user user:email request-scope email email", "read:user user:email "]],
    ["github", "configured", ["read:user user:email configured-scope", "read:user user:email configured-scope", "read:user user:email configured-scope request-scope email email", "read:user user:email configured-scope "]],
    ["github", "disabled", [null, null, "request-scope email email", ""]],
    ["github", "disabled-configured", ["configured-scope", "configured-scope", "configured-scope request-scope email email", "configured-scope "]],
    ["discord", "default", ["identify email", "identify email", "identify email request-scope email email", "identify email "]],
    ["discord", "configured", ["identify email configured-scope", "identify email configured-scope", "identify email request-scope email email configured-scope", "identify email  configured-scope"]],
    ["discord", "disabled", [null, null, "request-scope email email", ""]],
    ["discord", "disabled-configured", ["configured-scope", "configured-scope", "request-scope email email configured-scope", " configured-scope"]],
  ] as const;
  const results = [];
  for (const [provider, mode, expected] of table) {
    const profile = `social-${provider}-${mode}` as FixtureProfile;
    const actor = ctx.actor(profile, profile);
    for (const [index, scopes] of requested.entries()) {
      const result = await actor.client.signIn.social({ provider, callbackURL: "/social-done", disableRedirect: true, ...(scopes === undefined ? {} : { scopes: [...scopes] }) });
      expect(result.error).toBeNull();
      const url = new URL(result.data!.url!);
      expect(`${url.origin}${url.pathname}`).toBe(expectedOrigins[provider]);
      expect(url.searchParams.getAll("scope")).toEqual(expected[index] === null ? [] : [expected[index]!]);
      expect(url.searchParams.get("prompt")).toBe(provider === "discord" ? "none" : null);
      expect(url.searchParams.has("code_challenge")).toBe(provider !== "discord");
      expect(url.searchParams.get("code_challenge_method")).toBe(provider === "discord" ? null : "S256");
      expect(url.searchParams.get("redirect_uri")).toBe(`${ctx.baseURL}${authProfilePath(profile)}/callback/${provider}`);
      results.push({ provider, mode, scopes: scopes ?? null, result: ctx.snapshot(result) });
    }
  }
  const after = await state(ctx);
  expect(after).toEqual(before);
  return { before, results, after };
}, ["POST /sign-in/social"]);

compatScenario("Discord authorization conditions JS permissions on effective bot scope and defaults prompt", async ctx => {
  const before = await state(ctx);
  const cases = [
    ["permissions", undefined, null, "none"], ["permissions", ["bot"], "8", "none"],
    ["bot", [], "8", "none"], ["bot", ["request-scope"], "8", "none"],
    ["zero", ["bot"], "0", "none"], ["fractional", ["bot"], "1.5", "none"],
    ["infinite", ["bot"], "Infinity", "none"], ["prompt", [], null, "consent"],
    ["empty-prompt", [], null, "none"],
  ] as const;
  const results = [];
  for (const [mode, scopes, permissions, prompt] of cases) {
    const profile = `social-discord-${mode}` as FixtureProfile;
    const result = await ctx.actor(profile, profile).client.signIn.social({ provider: "discord", callbackURL: "/social-done", disableRedirect: true, ...(scopes === undefined ? {} : { scopes: [...scopes] }) });
    expect(result.error).toBeNull();
    const url = new URL(result.data!.url!);
    expect(`${url.origin}${url.pathname}`).toBe(expectedOrigins.discord);
    expect(url.searchParams.getAll("permissions")).toEqual(permissions === null ? [] : [permissions]);
    expect(url.searchParams.getAll("prompt")).toEqual([prompt]);
    expect(url.searchParams.has("code_challenge")).toBe(false);
    results.push({ mode, scopes: scopes ?? null, result: ctx.snapshot(result) });
  }
  const after = await state(ctx);
  expect(after).toEqual(before);
  return { before, results, after };
}, ["POST /sign-in/social"]);

compatScenario("builtin social link authorization requires a session and retains configured scope additions", async ctx => {
  const results = [];
  for (const provider of ["google", "github", "discord"] as const) {
    const profile = `social-${provider}-configured` as FixtureProfile;
    const owner = ctx.actor(`owner-${provider}`, profile);
    const signup = await owner.client.signUp.email({ email: ctx.uniqueEmail(`social-link-${provider}`), password: "password123", name: "Link Owner" });
    expect(signup.error).toBeNull();
    const before = await state(ctx);
    const guest = await ctx.actor(`guest-${provider}`, profile).client.linkSocial({ provider, callbackURL: "/social-done", disableRedirect: true, scopes: ["request-scope"] });
    expect(guest.error?.status).toBe(401);
    expect(await state(ctx)).toEqual(before);
    const link = await owner.client.linkSocial({ provider, callbackURL: "/social-done", disableRedirect: true, scopes: ["request-scope", "request-scope"] });
    expect(link.error).toBeNull();
    const url = new URL(link.data!.url!);
    expect(`${url.origin}${url.pathname}`).toBe(expectedOrigins[provider]);
    expect(url.searchParams.get("scope")).toBe(provider === "google" ? "email profile openid configured-scope request-scope request-scope" : provider === "github" ? "read:user user:email configured-scope request-scope request-scope" : "identify email request-scope request-scope configured-scope");
    expect(url.searchParams.has("code_challenge")).toBe(provider !== "discord");
    const current = await owner.client.getSession();
    expect(current.data!.user.id).toBe(signup.data!.user.id);
    const after = await state(ctx);
    expect(after).toEqual(before);
    results.push({ provider, signup: ctx.snapshot(signup), before, guest: ctx.snapshot(guest), link: ctx.snapshot(link), current: ctx.snapshot(current), after });
  }
  return { results };
}, ["POST /link-social"]);

compatScenario("Discord callback exchanges without PKCE and preserves current foreign and replay state", async ctx => {
  const fixture = "social-discord-default";
  const primary = ctx.actor("primary", fixture);
  const foreign = ctx.actor("foreign", fixture);
  const foreignSignup = await foreign.client.signUp.email({ email: ctx.uniqueEmail("discord-foreign"), password: "password123", name: "Foreign User" });
  expect(foreignSignup.error).toBeNull();
  const foreignBefore = await ctx.readUserState({ userId: foreignSignup.data!.user.id });
  const profile = { id: "4194304", email: ctx.uniqueEmail("discord-owner"), username: "Discord Owner", global_name: null, avatar: "fixture", discriminator: "0", verified: true };
  const control = await ctx.rawRequest({ path: "/__test/social-provider/profile", method: "POST", json: profile });
  expect(control.status).toBe(200);
  const before = await state(ctx);
  const signin = await primary.client.signIn.social({ provider: "discord", callbackURL: "/social-done", disableRedirect: true, scopes: ["requested-scope"] });
  expect(signin.error).toBeNull();
  const oauth = new URL(signin.data!.url!);
  expect(oauth.searchParams.has("code_challenge")).toBe(false);
  const path = `${authProfilePath(fixture)}/callback/discord?${new URLSearchParams({ code: "fixture-code", state: oauth.searchParams.get("state")! })}`;
  const callbackResponse = await primary.fetch(path, { redirect: "manual" });
  const callback = { status: callbackResponse.status, location: callbackResponse.headers.get("location"), body: await callbackResponse.text() };
  expect(callback.status).toBe(302);
  expect(callback.location).toBe("/social-done");
  const current = await primary.client.getSession();
  expect(current.data!.user.email).toBe(profile.email);
  const after = await state(ctx);
  expect(after.users).toHaveLength(before.users.length + 1);
  expect(after.accounts).toHaveLength(before.accounts.length + 1);
  expect(after.sessions).toHaveLength(before.sessions.length + 1);
  expect(after.receipts).toHaveLength(2);
  expect(after.receipts[0]!.body).toEqual({ grant_type: "authorization_code", code: "fixture-code", redirect_uri: `${ctx.baseURL}${authProfilePath(fixture)}/callback/discord`, client_id: "fixture-social-client", client_secret: "fixture-social-secret" });
  expect(after.receipts[1]!.authorization).toBe("Bearer fixture-discord-access");
  const account = after.accounts.find(row => row.providerId === "discord")!;
  expect(account.userId).toBe(current.data!.user.id);
  expect(account.accountId).toBe(profile.id);
  expect(account.scope).toBe("identify,email");
  expect(account.accessToken).toBe("fixture-discord-access");
  expect(current.data!.session.userId).toBe(current.data!.user.id);
  expect(current.data!.session.userId).not.toBe(foreignSignup.data!.user.id);
  const replayResponse = await primary.fetch(path, { redirect: "manual" });
  const replay = { status: replayResponse.status, location: replayResponse.headers.get("location"), body: await replayResponse.text() };
  expect(replay.status).toBe(302);
  expect(replay.location).not.toBe(callback.location);
  const afterReplay = await state(ctx);
  expect(afterReplay).toEqual(after);
  const foreignAfter = await ctx.readUserState({ userId: foreignSignup.data!.user.id });
  expect(foreignAfter).toEqual(foreignBefore);
  const foreignCurrent = await foreign.client.getSession();
  expect(foreignCurrent.data!.user.id).toBe(foreignSignup.data!.user.id);
  return { foreignSignup: ctx.snapshot(foreignSignup), foreignBefore, control, before, signin: ctx.snapshot(signin), callback, current: ctx.snapshot(current), after, replay, afterReplay, foreignAfter, foreignCurrent: ctx.snapshot(foreignCurrent) };
}, ["POST /sign-in/social", "GET /callback/{}", "GET /get-session"]);
