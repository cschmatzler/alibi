import { expect } from "bun:test";
import { compatScenario, type ScenarioContext } from "../../support/scenario";
import { authProfilePath, type FixtureProfile } from "../../support/profiles";

type Row = Record<string, unknown>;
type Stored = { users: Array<Row & { id: string }>; accounts: Array<Row & { id: string }>; sessions: Array<Row & { id: string }> };
type Receipt = { path: string; method: string; authorization: string | null; contentType: string | null; body: Record<string, string> | string };

async function state(ctx: ScenarioContext): Promise<Stored> {
  const response = await ctx.rawRequest({ path: "/__test/social-provider/state" });
  expect(response.status).toBe(200);
  return response.body as Stored;
}
async function control(ctx: ScenarioContext, value: Row) {
  const response = await ctx.rawRequest({ path: "/__test/dropbox/control", method: "POST", json: value });
  expect(response.status).toBe(200);
}
async function receipts(ctx: ScenarioContext) {
  const response = await ctx.rawRequest({ path: "/__test/dropbox/receipts" });
  expect(response.status).toBe(200);
  return (response.body as Receipt[]).map(row => ({ ...row, body: typeof row.body === "object" && row.body.code_verifier ? { ...row.body, code_verifier: { token: row.body.code_verifier, length: row.body.code_verifier.length } } : row.body }));
}
async function foreign(ctx: ScenarioContext) {
  const actor = ctx.actor("foreign"), signup = await actor.client.signUp.email({ email: ctx.uniqueEmail("foreign"), password: "Password123!", name: "Foreign" });
  expect(signup.error).toBeNull();
  return { actor, before: await state(ctx) };
}
function unchangedForeign(before: Stored, after: Stored) {
  for (const table of ["users", "accounts", "sessions"] as const) for (const row of before[table]) expect(after[table].find(candidate => candidate.id === row.id)).toEqual(row);
}
function profile(ctx: ScenarioContext): Row {
  return { account_id: ctx.uniqueToken("dropbox-subject"), name: { display_name: "Dropbox User", given_name: "Dropbox", surname: "User" }, email: ctx.uniqueEmail("dropbox"), email_verified: true, profile_photo_url: "https://images.example.invalid/dropbox.png", originalApplicationField: { retained: true } };
}
async function callback(ctx: ScenarioContext, mode: FixtureProfile = "social-dropbox-default", requestSignUp = false) {
  const actor = ctx.actor("dropbox", mode), start = await actor.client.signIn.social({ provider: "dropbox", callbackURL: "/dashboard", requestSignUp });
  expect(start.error).toBeNull();
  const url = new URL(start.data!.url!), path = authProfilePath(mode) + `/callback/dropbox?code=fixture-code&state=${encodeURIComponent(url.searchParams.get("state")!)}`;
  return { actor, start, url, path, response: await actor.fetch(ctx.baseURL + path, { redirect: "manual" }) };
}

for (const mode of ["default", "configured", "disabled-scope", "disabled-configured", "offline", "online", "legacy", "configured-endpoint"] as const) {
  compatScenario(`dropbox published ${mode} authorization retains scopes PKCE and access type`, async ctx => {
    const other = await foreign(ctx), fixture: FixtureProfile = `social-dropbox-${mode}`;
    const result = await ctx.actor("dropbox", fixture).client.signIn.social({ provider: "dropbox", callbackURL: "/dashboard", scopes: ["requested-scope", "account_info.read"], loginHint: "ignored@example.invalid", additionalParams: { custom: "value with space" } });
    expect(result.error).toBeNull();
    const url = new URL(result.data!.url!), configured = ["configured", "disabled-configured"].includes(mode);
    expect(url.origin).toBe(mode === "configured-endpoint" ? "https://alternate-dropbox.example.invalid" : "https://www.dropbox.com");
    expect(url.pathname).toBe(mode === "configured-endpoint" ? "/authorize" : "/oauth2/authorize");
    const scopes = [...(mode.startsWith("disabled-") ? [] : ["account_info.read"]), ...(configured ? ["files.metadata.read", "account_info.read", "punctuation !~*'()"] : []), "requested-scope", "account_info.read"];
    expect(url.searchParams.getAll("scope")).toEqual([scopes.join(" ")]);
    expect(result.data!.url).toContain(`scope=${new URLSearchParams({ scope: scopes.join(" ") }).toString().slice(6)}`);
    expect(url.searchParams.getAll("client_id")).toEqual(["fixture-social-client"]);
    expect(url.searchParams.get("response_type")).toBe("code");
    expect(url.searchParams.getAll("state")).toHaveLength(1);
    expect(url.searchParams.get("state")).not.toBe("stale");
    expect(url.searchParams.get("code_challenge_method")).toBe("S256");
    expect(url.searchParams.get("code_challenge")).toBeTruthy();
    expect(url.searchParams.has("login_hint")).toBeFalse();
    expect(url.searchParams.get("custom")).toBe("value with space");
    expect(url.searchParams.get("token_access_type")).toBe(["offline", "online", "legacy"].includes(mode) ? mode : null);
    expect(url.searchParams.get("redirect_uri")).toBe(mode === "configured-endpoint" ? "https://client.example.invalid/dropbox-return" : ctx.baseURL + authProfilePath(fixture) + "/callback/dropbox");
    if (mode === "configured-endpoint") expect(url.searchParams.get("retained")).toBe("value");
    expect(await state(ctx)).toEqual(other.before); expect(await receipts(ctx)).toEqual([]);
    return { result: ctx.snapshot(result), before: other.before, after: await state(ctx), receipts: await receipts(ctx) };
  }, ["POST /sign-in/social"]);
}

for (const mode of ["default", "public", "mapped", "configured-endpoint", "client-key"] as const) {
  compatScenario(`dropbox ${mode} real POST exchange refresh replay and local logout preserve foreign authority`, async ctx => {
    const other = await foreign(ctx), original = profile(ctx); await control(ctx, { profile: original });
    const fixture: FixtureProfile = `social-dropbox-${mode}`, flow = await callback(ctx, fixture);
    expect(flow.response.status).toBe(302); expect(flow.response.headers.get("location")).toBe("/dashboard");
    const session = await flow.actor.client.getSession(), after = await state(ctx); expect(session.error).toBeNull(); unchangedForeign(other.before, after);
    for (const table of ["users", "accounts", "sessions"] as const) expect(after[table]).toHaveLength(other.before[table].length + 1);
    const user = after.users.find(row => !other.before.users.some(old => old.id === row.id))!, account = after.accounts.find(row => row.userId === user.id)!;
    expect(user).toMatchObject({ name: mode === "mapped" ? "Mapped Dropbox User" : "Dropbox User", email: mode === "mapped" ? "mapped-dropbox@example.invalid" : original.email, emailVerified: mode !== "mapped", image: mode === "mapped" ? "https://images.example.invalid/mapped-dropbox.png" : original.profile_photo_url });
    expect(account).toMatchObject({ providerId: "dropbox", accountId: original.account_id, accessToken: "fixture-dropbox-access", refreshToken: "fixture-dropbox-refresh", scope: "account_info.read", idToken: null });
    expect(account.accessTokenExpiresAt).toBeTruthy(); expect(session.data?.user.id).toBe(user.id);
    const raw = (await ctx.rawRequest({ path: "/__test/dropbox/receipts" })).body as Receipt[], exchange = raw[0]!.body as Record<string, string>, verifier = exchange.code_verifier!;
    expect(verifier).toHaveLength(128); expect(flow.url.searchParams.get("code_challenge")).toBe(Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))).toString("base64url"));
    expect(exchange).toEqual({ grant_type: "authorization_code", code: "fixture-code", code_verifier: verifier, client_id: "fixture-social-client", ...(mode === "public" ? {} : { client_secret: "fixture-social-secret" }), ...(mode === "client-key" ? { client_key: "fixture-dropbox-client-key" } : {}), redirect_uri: mode === "configured-endpoint" ? "https://client.example.invalid/dropbox-return" : ctx.baseURL + authProfilePath(fixture) + "/callback/dropbox" });
    expect(raw[0]!.authorization).toBeNull(); expect(raw[1]).toEqual({ path: "/userinfo", method: "POST", authorization: "Bearer fixture-dropbox-access", contentType: null, body: "" });
    const mapper = (await ctx.rawRequest({ path: "/__test/dropbox/mapper-receipts" })).body; expect(mapper).toEqual(mode === "mapped" ? [original] : []);
    const replay = await flow.actor.fetch(ctx.baseURL + flow.path, { redirect: "manual" }); expect(replay.status).toBe(302); expect(new URL(replay.headers.get("location")!, ctx.baseURL).searchParams.get("error")).toBeTruthy(); expect(await state(ctx)).toEqual(after); expect(await receipts(ctx)).toHaveLength(2);
    await control(ctx, { tokenResponse: { access_token: "fixture-dropbox-access-rotated", refresh_token: "fixture-dropbox-refresh-rotated", expires_in: 1800, scope: "rotated-scope" } });
    const denied = await other.actor.client.refreshToken({ accountId: account.id }); expect(denied.error).not.toBeNull(); expect(await state(ctx)).toEqual(after); expect(await receipts(ctx)).toHaveLength(2);
    const refreshed = await flow.actor.client.refreshToken({ accountId: account.id }); expect(refreshed.error).toBeNull();
    const rotated = await state(ctx); expect(rotated.users).toEqual(after.users); expect(rotated.sessions).toEqual(after.sessions); unchangedForeign(other.before, rotated);
    expect(rotated.accounts.find(row => row.id === account.id)).toMatchObject({ accountId: original.account_id, userId: user.id, accessToken: "fixture-dropbox-access-rotated", refreshToken: "fixture-dropbox-refresh-rotated", scope: account.scope });
    const requests = await receipts(ctx); expect(requests[2]!.body).toEqual({ grant_type: "refresh_token", refresh_token: "fixture-dropbox-refresh", client_id: "fixture-social-client", ...(mode === "public" ? {} : { client_secret: "fixture-social-secret" }) });
    const signedOut = await flow.actor.client.signOut(); expect(signedOut.error).toBeNull(); expect((await flow.actor.client.getSession()).data).toBeNull(); const final = await state(ctx); expect(final.users).toEqual(rotated.users); expect(final.accounts).toEqual(rotated.accounts); unchangedForeign(other.before, final); expect(final.sessions).toEqual(other.before.sessions); expect(await receipts(ctx)).toEqual(requests);
    return { before: other.before, start: ctx.snapshot(flow.start), callback: { status: flow.response.status, location: flow.response.headers.get("location") }, session: ctx.snapshot(session), after, mapper, denied: ctx.snapshot(denied), refreshed: ctx.snapshot(refreshed), rotated, signedOut: ctx.snapshot(signedOut), final, receipts: requests };
  }, ["POST /sign-in/social", "GET /callback/{}", "POST /refresh-token", "POST /sign-out"]);
}

const mappings: Array<{ name: string; patch: Row; expectedName: string; expectedImage?: string | null; expectedSubject?: string; verified?: boolean }> = [
  { name: "numeric name", patch: { name: { display_name: 7 } }, expectedName: "7" },
  { name: "empty name", patch: { name: { display_name: "" } }, expectedName: "" },
  { name: "null display name", patch: { name: { display_name: null } }, expectedName: "" },
  { name: "missing name", patch: { name: undefined }, expectedName: "" },
  { name: "numeric subject", patch: { account_id: 42 }, expectedName: "Dropbox User", expectedSubject: "42" },
  { name: "missing image", patch: { profile_photo_url: undefined }, expectedName: "Dropbox User", expectedImage: null },
  { name: "null image", patch: { profile_photo_url: null }, expectedName: "Dropbox User", expectedImage: null },
  { name: "empty image", patch: { profile_photo_url: "" }, expectedName: "Dropbox User", expectedImage: "" },
  { name: "numeric image", patch: { profile_photo_url: 7 }, expectedName: "Dropbox User", expectedImage: "7" },
  { name: "missing verified", patch: { email_verified: undefined }, expectedName: "Dropbox User", verified: false },
  { name: "null verified", patch: { email_verified: null }, expectedName: "Dropbox User", verified: false },
  { name: "false verified", patch: { email_verified: false }, expectedName: "Dropbox User", verified: false },
];
for (const mapping of mappings) compatScenario(`dropbox ${mapping.name} profile retains original raw account and typed persistence`, async ctx => {
  const other = await foreign(ctx), original = { ...profile(ctx), ...mapping.patch }; await control(ctx, { profile: original }); const flow = await callback(ctx);
  expect(flow.response.headers.get("location")).toBe("/dashboard"); const stored = await state(ctx); unchangedForeign(other.before, stored);
  const user = stored.users.find(row => !other.before.users.some(old => old.id === row.id))!, account = stored.accounts.find(row => row.userId === user.id)!;
  expect(user).toMatchObject({ name: mapping.expectedName, email: original.email, emailVerified: mapping.verified ?? true, image: mapping.expectedImage === undefined ? original.profile_photo_url : mapping.expectedImage }); expect(account.accountId).toBe(mapping.expectedSubject ?? original.account_id); expect((await flow.actor.client.getSession()).data?.user.id).toBe(user.id);
  return { before: other.before, start: ctx.snapshot(flow.start), callback: { status: flow.response.status, location: flow.response.headers.get("location") }, stored, receipts: await receipts(ctx) };
}, ["POST /sign-in/social", "GET /callback/{}"]);

for (const expiry of ["absent", "zero", "fractional"] as const) compatScenario(`dropbox ${expiry} access expiry follows actual token helper`, async ctx => {
  await control(ctx, { profile: profile(ctx), tokenResponse: { access_token: "fixture-dropbox-access", refresh_token: "fixture-dropbox-refresh", ...(expiry === "zero" ? { expires_in: 0 } : expiry === "fractional" ? { expires_in: 0.5 } : {}) } }); const flow = await callback(ctx); expect(flow.response.headers.get("location")).toBe("/dashboard"); const stored = await state(ctx); expect(stored.accounts).toHaveLength(1); expect(stored.accounts[0]!.scope).toBe(""); if (expiry === "fractional") expect(stored.accounts[0]!.accessTokenExpiresAt).toBeTruthy(); else expect(stored.accounts[0]!.accessTokenExpiresAt).toBeNull();
  return { start: ctx.snapshot(flow.start), callback: { status: flow.response.status, location: flow.response.headers.get("location") }, stored, receipts: await receipts(ctx) };
}, ["POST /sign-in/social", "GET /callback/{}"]);

for (const variant of ["wrong-state", "wrong-provider", "token-http-error", "userinfo-http-error", "missing-subject", "null-subject", "blank-subject", "missing-email", "signup-disabled", "implicit-disabled"] as const) compatScenario(`dropbox browser ${variant} denies before any owned or foreign identity write`, async ctx => {
  const other = await foreign(ctx), original = profile(ctx); if (variant === "missing-subject") delete original.account_id; if (variant === "null-subject") original.account_id = null; if (variant === "blank-subject") original.account_id = " "; if (variant === "missing-email") delete original.email;
  await control(ctx, { profile: original, ...(variant === "token-http-error" ? { tokenStatus: 503 } : {}), ...(variant === "userinfo-http-error" ? { userInfoStatus: 503 } : {}) });
  const fixture: FixtureProfile = variant === "signup-disabled" ? "social-dropbox-signup-disabled" : variant === "implicit-disabled" ? "social-dropbox-implicit-disabled" : "social-dropbox-default", actor = ctx.actor("dropbox", fixture), start = await actor.client.signIn.social({ provider: "dropbox", callbackURL: "/dashboard", requestSignUp: variant === "signup-disabled" }); expect(start.error).toBeNull();
  const url = new URL(start.data!.url!), callbackState = variant === "wrong-state" ? ctx.uniqueToken("wrong-state") : url.searchParams.get("state")!, provider = variant === "wrong-provider" ? "unknown-dropbox" : "dropbox", response = await actor.fetch(ctx.baseURL + authProfilePath(fixture) + `/callback/${provider}?code=fixture-code&state=${encodeURIComponent(callbackState)}`, { redirect: "manual" });
  expect(response.status).toBe(302); const location = response.headers.get("location")!, error = new URL(location, ctx.baseURL).searchParams.get("error"); expect(error).toBe(variant === "wrong-state" ? "state_mismatch" : variant === "wrong-provider" ? "oauth_provider_not_found" : variant === "token-http-error" ? "invalid_code" : variant === "missing-email" ? "email_not_found" : variant.endsWith("disabled") ? "signup_disabled" : "unable_to_get_user_info"); expect(await state(ctx)).toEqual(other.before); expect((await actor.client.getSession()).data).toBeNull(); const requests = await receipts(ctx); expect(requests.map(row => row.path)).toEqual(["wrong-state", "wrong-provider"].includes(variant) ? [] : variant === "token-http-error" ? ["/token"] : ["/token", "/userinfo"]);
  return { before: other.before, start: ctx.snapshot(start), callback: { status: response.status, location }, after: await state(ctx), receipts: requests };
}, ["GET /callback/{}"]);

compatScenario("dropbox configured access type can be replaced by a nonreserved request parameter", async ctx => {
  const before = await state(ctx), result = await ctx.actor("dropbox", "social-dropbox-offline").client.signIn.social({ provider: "dropbox", additionalParams: { token_access_type: "online" } }); expect(result.error).toBeNull(); expect(new URL(result.data!.url!).searchParams.getAll("token_access_type")).toEqual(["online"]); expect(await state(ctx)).toEqual(before); expect(await receipts(ctx)).toEqual([]); return { result: ctx.snapshot(result), before, after: await state(ctx) };
}, ["POST /sign-in/social"]);
compatScenario("dropbox disabled default scope omits an empty scope parameter", async ctx => {
  const before = await state(ctx), result = await ctx.actor("dropbox", "social-dropbox-disabled-scope").client.signIn.social({ provider: "dropbox" }); expect(result.error).toBeNull(); expect(new URL(result.data!.url!).searchParams.has("scope")).toBeFalse(); expect(await state(ctx)).toEqual(before); expect(await receipts(ctx)).toEqual([]); return { result: ctx.snapshot(result), before, after: await state(ctx) };
}, ["POST /sign-in/social"]);
compatScenario("dropbox explicit signup overrides implicit signup policy", async ctx => {
  await control(ctx, { profile: profile(ctx) }); const flow = await callback(ctx, "social-dropbox-implicit-disabled", true); expect(flow.response.headers.get("location")).toBe("/dashboard"); const stored = await state(ctx); for (const table of ["users", "accounts", "sessions"] as const) expect(stored[table]).toHaveLength(1); expect((await flow.actor.client.getSession()).data?.user.id).toBe(stored.users[0]!.id); return { start: ctx.snapshot(flow.start), callback: { status: flow.response.status, location: flow.response.headers.get("location") }, stored, receipts: await receipts(ctx) };
}, ["POST /sign-in/social", "GET /callback/{}"]);
compatScenario("dropbox rejects direct ID-token sign-in without remote verification or identity writes", async ctx => {
  const other = await foreign(ctx), result = await ctx.actor("dropbox", "social-dropbox-default").client.signIn.social({ provider: "dropbox", idToken: { token: "unsupported-proof" } }); expect(result.error?.code).toBe("ID_TOKEN_NOT_SUPPORTED"); expect(await state(ctx)).toEqual(other.before); expect(await receipts(ctx)).toEqual([]); return { result: ctx.snapshot(result), before: other.before, after: await state(ctx) };
});
compatScenario("dropbox requires a client before creating authorization state", async ctx => {
  const other = await foreign(ctx), result = await ctx.actor("dropbox", "social-dropbox-empty-clients").client.signIn.social({ provider: "dropbox" }); expect(result.error?.status).toBe(500); expect(await state(ctx)).toEqual(other.before); expect(await receipts(ctx)).toEqual([]); return { result: ctx.snapshot(result), before: other.before, after: await state(ctx) };
});

for (const valid of [true, false]) compatScenario(`dropbox explicit browser link ${valid ? "admits raw account" : "rejects missing raw account"} while retaining the existing principal`, async ctx => {
  const other = await foreign(ctx), actor = ctx.actor("dropbox", "social-dropbox-default"), email = ctx.uniqueEmail("dropbox-link");
  const signup = await actor.client.signUp.email({ email, password: "Password123!", name: "Existing local user" }); expect(signup.error).toBeNull();
  const before = await state(ctx), original: Row = { ...profile(ctx), email }; if (!valid) delete original.account_id; await control(ctx, { profile: original });
  const start = await actor.client.linkSocial({ provider: "dropbox", callbackURL: "/linked" }); expect(start.error).toBeNull();
  const url = new URL(start.data!.url!), path = authProfilePath("social-dropbox-default") + `/callback/dropbox?code=fixture-code&state=${encodeURIComponent(url.searchParams.get("state")!)}`, response = await actor.fetch(ctx.baseURL + path, { redirect: "manual" });
  expect(response.status).toBe(302); const location = response.headers.get("location")!, after = await state(ctx); unchangedForeign(other.before, after); expect(after.users).toEqual(before.users); expect(after.sessions).toEqual(before.sessions);
  if (valid) { expect(location).toBe("/linked"); expect(after.accounts).toHaveLength(before.accounts.length + 1); expect(after.accounts.find(row => row.providerId === "dropbox")).toMatchObject({ accountId: original.account_id, userId: signup.data!.user.id }); }
  else { expect(new URL(location, ctx.baseURL).searchParams.get("error")).toBe("unable_to_get_user_info"); expect(after).toEqual(before); }
  expect((await actor.client.getSession()).data?.user.id).toBe(signup.data!.user.id); expect((await receipts(ctx)).map(row => row.path)).toEqual(["/token", "/userinfo"]);
  const replay = await actor.fetch(ctx.baseURL + path, { redirect: "manual" }); expect(replay.status).toBe(302); expect(new URL(replay.headers.get("location")!, ctx.baseURL).searchParams.get("error")).toBeTruthy(); expect(await state(ctx)).toEqual(after); expect(await receipts(ctx)).toHaveLength(2);
  return { before, start: ctx.snapshot(start), callback: { status: response.status, location }, after, receipts: await receipts(ctx) };
}, ["POST /link-social", "GET /callback/{}"]);

compatScenario("dropbox existing account info uses real POST without readmitting a changed raw account subject", async ctx => {
  const other = await foreign(ctx), original = profile(ctx); await control(ctx, { profile: original }); const flow = await callback(ctx); expect(flow.response.headers.get("location")).toBe("/dashboard");
  const before = await state(ctx), user = before.users.find(row => !other.before.users.some(old => old.id === row.id))!, account = before.accounts.find(row => row.userId === user.id)!; delete original.account_id; await control(ctx, { profile: original });
  const denied = await other.actor.client.$fetch("/account-info", { query: { accountId: account.id } }); expect(denied.error).not.toBeNull(); expect(await receipts(ctx)).toHaveLength(2); expect(await state(ctx)).toEqual(before);
  const result = await flow.actor.client.$fetch("/account-info", { query: { accountId: account.id } }); expect(result.error).toBeNull(); expect(result.data).toEqual({ user: { name: "Dropbox User", email: original.email, image: original.profile_photo_url, emailVerified: true }, data: original, account: { id: account.id, providerId: "dropbox", accountId: account.accountId } }); expect(await state(ctx)).toEqual(before); expect((await receipts(ctx))[2]).toEqual({ path: "/userinfo", method: "POST", authorization: "Bearer fixture-dropbox-access", contentType: null, body: "" });
  return { before, denied: ctx.snapshot(denied), result: ctx.snapshot(result), after: await state(ctx), receipts: await receipts(ctx) };
}, ["GET /account-info"]);
