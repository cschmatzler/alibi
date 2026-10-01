import { expect } from "bun:test";
import { createAuthClient } from "better-auth/client";
import { passkeyClient } from "@better-auth/passkey/client";
import { Authenticator } from "../../support/authenticator";
import { compatScenario, type ScenarioContext } from "../../support/scenario";
import { authProfilePath, type FixtureProfile } from "../../support/profiles";

async function setup(ctx: ScenarioContext, profile: FixtureProfile) {
  const submitted: Record<string, any>[] = [];
  const make = (name: string) => createAuthClient({ baseURL: `${ctx.baseURL}${authProfilePath(profile)}`, plugins: [passkeyClient()], fetchOptions: { customFetchImpl: async (input, init) => {
    const request = new Request(input, init);
    if (new URL(request.url).pathname.endsWith("/passkey/verify-authentication")) submitted.push(await request.clone().json());
    return ctx.actor(name, profile).fetch(request);
  } } });
  const owner = make("authentication-owner"), foreign = make("authentication-foreign");
  const signup = await owner.signUp.email({ email: ctx.uniqueEmail("authentication-owner"), name: "Owner", password: "password123" });
  let foreignCookies: string[] = [];
  const foreignSignup = await foreign.signUp.email({ email: ctx.uniqueEmail("authentication-foreign"), name: "Foreign", password: "password123" }, { onSuccess({ response }) { foreignCookies = response.headers.getSetCookie(); } });
  expect(signup.error).toBeNull(); expect(foreignSignup.error).toBeNull();
  const device = new Authenticator();
  const options = await owner.$fetch("/passkey/generate-register-options", { method: "GET" }); expect(options.error).toBeNull();
  const registered = await owner.$fetch("/passkey/verify-registration", { method: "POST", body: { response: device.register(options.data, ctx.baseURL), name: "Callback device" } }); expect(registered.error).toBeNull();
  const listed = await owner.$fetch("/passkey/list-user-passkeys", { method: "GET" }); expect(listed.error).toBeNull();
  const out = await owner.signOut(); expect(out.error).toBeNull();
  const before = await ctx.readUserState({ userId: signup.data!.user.id }); expect(before).toMatchObject({ sessions: [] });
  const foreignBefore = await ctx.readUserState({ userId: foreignSignup.data!.user.id });
  const events = async () => {
    const result = await ctx.rawRequest({ path: "/__test/passkey-authentication-events" }); expect(result.status).toBe(200);
    return result.body as Record<string, any>[];
  };
  expect(await events()).toEqual([]);
  return { owner, foreign, signup, foreignSignup, foreignCookies, device, options, registered, listed, out, before, foreignBefore, events, submitted };
}

function wrapAssertion(assertion: Record<string, any>) {
  const bytes = Buffer.from(assertion.response.clientDataJSON, "base64url").toString();
  const decoded = JSON.parse(bytes);
  expect(Buffer.from(JSON.stringify(decoded)).toString("base64url")).toBe(assertion.response.clientDataJSON);
  const generatedId = Buffer.from(assertion.response.userHandle, "base64url").toString();
  expect(Buffer.from(generatedId).toString("base64url")).toBe(assertion.response.userHandle);
  return { ...assertion, response: { ...assertion.response, clientDataJSON: { ...decoded, origin: { url: decoded.origin } }, userHandle: { id: assertion.response.userHandle, decoded: { id: generatedId } }, signature: { token: assertion.response.signature } } };
}
function submitted(fixture: Awaited<ReturnType<typeof setup>>) {
  return fixture.submitted.map(request => ({ ...request, response: wrapAssertion(request.response) }));
}
function observed(events: Record<string, any>[], assertion: ReturnType<Authenticator["authenticate"]>, fixture: Awaited<ReturnType<typeof setup>>): Record<string, any>[] {
  expect(events).toHaveLength(1);
  const event = events[0]!;
  // Retain all callback client fields. Decode one reversible transport encoding
  // only after exact issued-byte equality is proved in each actual runtime.
  expect(event.clientData).toEqual(assertion);
  expect(fixture.submitted[0]?.response).toEqual(assertion);
  expect(assertion.response.userHandle).toBe((fixture.options.data as { user: { id: string } }).user.id);
  expect(Buffer.from(assertion.response.userHandle, "base64url").toString()).toMatch(/^[a-z0-9]{32}$/);
  const bytes = Buffer.from(event.clientData.response.clientDataJSON, "base64url").toString();
  const decoded = JSON.parse(bytes);
  expect(JSON.stringify(decoded)).toBe(bytes);
  expect(event.facts).toMatchObject({ newCounter: 1, credentialID: assertion.id, userVerified: true, credentialDeviceType: "singleDevice", credentialBackedUp: false });
  expect(event.storedPasskey).toMatchObject({ credentialID: assertion.id, counter: 0, backedUp: false });
  expect(event.sessions).toEqual({ count: 0 }); expect(event.challenges).toEqual({ count: 0 });
  return events.map(current => ({ ...current, facts: { ...current.facts, origin: { url: current.facts.origin } }, clientData: wrapAssertion(current.clientData) }));
}

for (const [profile, status, code, message] of [
  ["passkey-auth-forbidden", 403, "PASSKEY_APPLICATION_DENIED", "Application denied this verified authentication"],
  ["passkey-auth-public-error", 500, "PASSKEY_APPLICATION_ERROR", "Application authentication service failed"],
  ["passkey-auth-internal-error", 400, "AUTHENTICATION_FAILED", "Authentication failed"],
] as const) compatScenario(`passkey ${profile} callback rejects after real proof and burns challenge without counter session or cookie writes`, async ctx => {
  const fixture = await setup(ctx, profile);
  const challenge = await fixture.owner.$fetch("/passkey/generate-authenticate-options", { method: "GET" }); expect(challenge.error).toBeNull();
  const assertion = fixture.device.authenticate(challenge.data, ctx.baseURL);
  let cookies: string[] = [];
  const result = await fixture.owner.$fetch("/passkey/verify-authentication", { method: "POST", body: { response: assertion }, onResponse({ response }) { cookies = response.headers.getSetCookie(); } });
  expect(result.error).toMatchObject({ status, code, message }); expect(cookies).toEqual([]);
  const callback = observed(await fixture.events(), assertion, fixture);
  const after = await ctx.readUserState({ userId: fixture.signup.data!.user.id }); expect(after).toEqual(fixture.before);
  const replay = await fixture.owner.$fetch("/passkey/verify-authentication", { method: "POST", body: { response: assertion } }); expect(replay.error).toMatchObject({ status: 400, code: "CHALLENGE_NOT_FOUND" });
  expect(await fixture.events()).toHaveLength(1);
  expect(await ctx.readUserState({ userId: fixture.foreignSignup.data!.user.id })).toEqual(fixture.foreignBefore);
  const current = await fixture.owner.getSession(); expect(current.data).toBeNull();
  const relogin = await fixture.owner.signIn.email({ email: fixture.signup.data!.user.email, password: "password123" }); expect(relogin.error).toBeNull();
  const listed = await fixture.owner.$fetch("/passkey/list-user-passkeys", { method: "GET" }); expect(listed).toEqual(fixture.listed);
  return { signup: fixture.signup, foreignSignup: fixture.foreignSignup, registration: { options: fixture.options, result: fixture.registered }, before: fixture.before, foreignBefore: fixture.foreignBefore, challenge, result, cookies, callback, after, replay, current, relogin, listed, submitted: submitted(fixture), foreignAfter: await ctx.readUserState({ userId: fixture.foreignSignup.data!.user.id }) };
}, ["POST /passkey/verify-authentication"]);

compatScenario("passkey verified callback awaits real stored reads before counter and session while body claims cannot switch credential owner", async ctx => {
  const fixture = await setup(ctx, "passkey-auth-accept");
  const challenge = await fixture.foreign.$fetch("/passkey/generate-authenticate-options", { method: "GET" }); expect(challenge.error).toBeNull();
  const assertion = { ...fixture.device.authenticate(challenge.data, ctx.baseURL), userId: fixture.foreignSignup.data!.user.id, details: { "$serde_json::private::RawValue": "literal", "$serde_json::private::Number": "literal" } };
  const result = await fixture.foreign.$fetch("/passkey/verify-authentication", { method: "POST", body: { response: assertion, userId: fixture.foreignSignup.data!.user.id } }); expect(result.error).toBeNull();
  expect(result.data).toMatchObject({ user: { id: fixture.signup.data!.user.id }, session: { userId: fixture.signup.data!.user.id } });
  const callback = observed(await fixture.events(), assertion, fixture);
  expect(callback[0]!.storedPasskey.userId).toBe(fixture.signup.data!.user.id);
  const current = await fixture.foreign.getSession(); expect(current.data?.user.id).toBe(fixture.signup.data!.user.id);
  const listed = await fixture.foreign.$fetch("/passkey/list-user-passkeys", { method: "GET" }); expect(listed.data).toMatchObject([{ userId: fixture.signup.data!.user.id, counter: 1 }]);
  const after = await ctx.readUserState({ userId: fixture.signup.data!.user.id }); expect(after).toMatchObject({ sessions: [{ userId: fixture.signup.data!.user.id }] });
  const replay = await fixture.foreign.$fetch("/passkey/verify-authentication", { method: "POST", body: { response: assertion } }); expect(replay.error).toMatchObject({ status: 400, code: "CHALLENGE_NOT_FOUND" });
  expect(await fixture.events()).toHaveLength(1);
  expect(await ctx.readUserState({ userId: fixture.foreignSignup.data!.user.id })).toEqual(fixture.foreignBefore);
  return { signup: fixture.signup, foreignSignup: fixture.foreignSignup, registered: fixture.registered, before: fixture.before, foreignBefore: fixture.foreignBefore, challenge, result, callback, current, listed, after, replay, submitted: submitted(fixture), foreignAfter: await ctx.readUserState({ userId: fixture.foreignSignup.data!.user.id }) };
}, ["POST /passkey/verify-authentication", "GET /passkey/list-user-passkeys"]);

compatScenario("passkey cryptographic challenge and signature failures never invoke application callback and cannot reuse consumed context", async ctx => {
  const fixture = await setup(ctx, "passkey-auth-accept"); const outcomes = [];
  for (const mode of ["challenge", "signature"] as const) {
    const challenge = await fixture.owner.$fetch("/passkey/generate-authenticate-options", { method: "GET" }); expect(challenge.error).toBeNull();
    const wrong = mode === "challenge" ? { ...(challenge.data as object), challenge: "wrong-signed-challenge" } : challenge.data;
    const assertion = fixture.device.authenticate(wrong, ctx.baseURL);
    if (mode === "signature") { const bytes = Buffer.from(assertion.response.signature, "base64url"); bytes[bytes.length - 1] = bytes[bytes.length - 1]! ^ 1; assertion.response.signature = bytes.toString("base64url"); }
    const result = await fixture.owner.$fetch("/passkey/verify-authentication", { method: "POST", body: { response: assertion } }); expect(result.error).toMatchObject({ status: mode === "signature" ? 401 : 400, code: "AUTHENTICATION_FAILED" });
    expect(await fixture.events()).toEqual([]);
    const replay = await fixture.owner.$fetch("/passkey/verify-authentication", { method: "POST", body: { response: assertion } }); expect(replay.error).toMatchObject({ status: 400, code: "CHALLENGE_NOT_FOUND" });
    expect(await ctx.readUserState({ userId: fixture.signup.data!.user.id })).toEqual(fixture.before);
    expect(await ctx.readUserState({ userId: fixture.foreignSignup.data!.user.id })).toEqual(fixture.foreignBefore);
    outcomes.push({ mode, challenge, result, replay });
  }
  return { signup: fixture.signup, foreignSignup: fixture.foreignSignup, registered: fixture.registered, before: fixture.before, foreignBefore: fixture.foreignBefore, outcomes, events: await fixture.events(), after: await ctx.readUserState({ userId: fixture.signup.data!.user.id }), submitted: submitted(fixture), foreignAfter: await ctx.readUserState({ userId: fixture.foreignSignup.data!.user.id }) };
}, ["POST /passkey/verify-authentication"]);


compatScenario("passkey callback may change persisted credential ownership and metadata without changing the verified session owner", async ctx => {
  const fixture = await setup(ctx, "passkey-auth-mutation");
  const challenge = await fixture.foreign.$fetch("/passkey/generate-authenticate-options", { method: "GET" }); expect(challenge.error).toBeNull();
  const assertion = fixture.device.authenticate(challenge.data, ctx.baseURL);
  const result = await fixture.foreign.$fetch("/passkey/verify-authentication", { method: "POST", body: { response: assertion } }); expect(result.error).toBeNull();
  expect(result.data).toMatchObject({ user: { id: fixture.signup.data!.user.id }, session: { userId: fixture.signup.data!.user.id } });
  const callback = observed(await fixture.events(), assertion, fixture);
  const current = await fixture.foreign.getSession(); expect(current.data?.user.id).toBe(fixture.signup.data!.user.id);
  const ownerRows = await fixture.foreign.$fetch("/passkey/list-user-passkeys", { method: "GET" }); expect(ownerRows.data).toEqual([]);
  const foreignRows = await fixture.foreign.$fetch("/passkey/list-user-passkeys", { method: "GET", headers: { cookie: fixture.foreignCookies.map(cookie => cookie.split(";")[0]).join("; ") } });
  expect(foreignRows.error).toBeNull(); expect(foreignRows.data).toMatchObject([{ userId: fixture.foreignSignup.data!.user.id, counter: 1, backedUp: true, deviceType: "application-updated", name: "Application updated", credentialID: assertion.id }]);
  const after = await ctx.readUserState({ userId: fixture.signup.data!.user.id }); expect(after).toMatchObject({ sessions: [{ userId: fixture.signup.data!.user.id }] });
  const foreignAfter = await ctx.readUserState({ userId: fixture.foreignSignup.data!.user.id }); expect(foreignAfter).toEqual(fixture.foreignBefore);
  const replay = await fixture.foreign.$fetch("/passkey/verify-authentication", { method: "POST", body: { response: assertion } }); expect(replay.error).toMatchObject({ status: 400, code: "CHALLENGE_NOT_FOUND" });
  expect(await fixture.events()).toHaveLength(1);
  return { signup: fixture.signup, foreignSignup: fixture.foreignSignup, registered: fixture.registered, before: fixture.before, foreignBefore: fixture.foreignBefore, challenge, result, callback, current, ownerRows, foreignRows, after, foreignAfter, replay, submitted: submitted(fixture) };
}, ["POST /passkey/verify-authentication", "GET /passkey/list-user-passkeys"]);
