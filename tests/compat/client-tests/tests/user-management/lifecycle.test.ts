import { expect } from "bun:test";
import { createHmac } from "node:crypto";
import { getCookieCache } from "better-auth/cookies";
import { z } from "zod";
import { compatScenario, type ScenarioContext } from "../../support/scenario";
import type { FixtureProfile } from "../../support/profiles";

const row = z.record(z.string(), z.unknown());
const userSchema = z.object({ id: z.string(), email: z.string(), emailVerified: z.boolean(), name: z.string(), image: z.string().nullable(), createdAt: z.string(), updatedAt: z.string() }).passthrough();
const stateSchema = z.object({ users: z.array(userSchema), accounts: z.array(row), sessions: z.array(row), verifications: z.array(row), events: z.array(row) });
type LifecycleState = z.infer<typeof stateSchema>;
const profile = (name: string) => `user-lifecycle-${name}` as FixtureProfile;
const path = (name: string, endpoint: string) => `/__test/profiles/user-lifecycle-${name}/api/auth/${endpoint}`;
async function control(ctx: ScenarioContext, name: string, action = "state", fields: Record<string, unknown> = {}) {
  const result = await ctx.rawRequest({ path: "/__test/user-lifecycle/control", method: "POST", json: { profile: name, action, ...fields } });
  expect(result.status).toBe(200);
  return stateSchema.parse(result.body);
}
async function responseBody(response: Response): Promise<unknown> {
  const text = await response.text();
  try { return JSON.parse(text); } catch { return text; }
}
function foreignRows(state: LifecycleState, userId: string) {
  return { users: state.users.filter(user => user.id === userId), accounts: state.accounts.filter(account => account.userId === userId), sessions: state.sessions.filter(session => session.userId === userId) };
}
/** Retain every row field and actual entropy while naming its protocol type. */
function evidence(value: unknown, key = ""): unknown {
  if (value instanceof Date) return value;
  if ((key === "password" || key === "hash") && typeof value === "string" && /^[a-f0-9]{32}:[a-f0-9]{128}$/.test(value)) {
    const [salt, derived] = value.split(":");
    return { token: value, salt: { token: salt, length: salt!.length }, derivedKey: { token: derived, length: derived!.length }, encoding: "hex-lower" };
  }
  if (Array.isArray(value)) return value.map(child => evidence(child));
  if (value && typeof value === "object") return Object.fromEntries(Object.entries(value).map(([name, child]) => [name, evidence(child, name)]));
  return value;
}

function delivery(state: LifecycleState, stage: string) {
  const event = state.events.findLast(event => event.stage === stage);
  if (!event) throw new Error(`Missing actual ${stage} callback`);
  return z.object({ stage: z.string(), user: userSchema, token: z.string(), url: z.string(), request: z.object({ method: z.string(), url: z.string(), marker: z.string().nullable() }), newEmail: z.string().optional() }).passthrough().parse(event);
}
function claims(token: string) {
  const [header, payload, signature] = token.split(".");
  expect(JSON.parse(Buffer.from(header!, "base64url").toString())).toMatchObject({ alg: "HS256" });
  expect(signature).toBe(createHmac("sha256", "compat-test-only-key-not-real-minimum-32chars").update(`${header}.${payload}`).digest("base64url"));
  return z.object({ email: z.string(), updateTo: z.string().optional(), requestType: z.string().optional(), iat: z.number(), exp: z.number() }).passthrough().parse(JSON.parse(Buffer.from(token.split(".")[1]!, "base64url").toString()));
}
async function cacheEvidence(cookies: readonly string[]) {
  const rawCookies = cookies.filter(cookie => cookie.startsWith("better-auth.session_data="));
  return Promise.all(rawCookies.map(async rawCookie => {
    const pair = rawCookie.split(";")[0]!, token = decodeURIComponent(pair.slice(pair.indexOf("=") + 1)), observedAt = Date.now();
    const decoded = await getCookieCache(new Headers({ cookie: pair }), { secret: "compat-test-only-key-not-real-minimum-32chars", strategy: "compact", isSecure: false });
    expect(decoded).not.toBeNull();
    return { compactSessionCache: { token, envelope: JSON.parse(Buffer.from(token, "base64url").toString()), decoded, observedAt, effectiveMaxAgeSeconds: 300, rawCookies: [rawCookie] } };
  }));
}

for (const name of ["default", "required", "delivery"]) {
  compatScenario(`configured verification ${name} protects signup and sign-in delivery defaults and original request receipts`, async ctx => {
    const primary = ctx.actor("owner", profile(name));
    await control(ctx, name, "reset");
    const email = ctx.uniqueEmail(`delivery-${name}`);
    const signup = await primary.client.signUp.email({ email, password: "password123", name: "Delivery Owner", fetchOptions: { headers: { "x-lifecycle-marker": "signup-delivery" } } });
    expect(signup.error).toBeNull();
    if (!signup.data) throw new Error("Configured signup must persist its user");
    expect(signup.data.token === null).toBe(name === "required" || name === "delivery");
    const registered = await control(ctx, name);
    expect(registered.events.filter(event => event.stage === "verification-mail")).toHaveLength(name === "default" ? 0 : 1);
    if (name !== "default") {
      const sent = delivery(registered, "verification-mail");
      expect(sent.user).toEqual(registered.users[0]!);
      expect(sent.request).toEqual({ method: "POST", url: new URL(path(name, "sign-up/email"), ctx.baseURL).href, marker: "signup-delivery" });
      expect(claims(sent.token)).toMatchObject({ email });
      expect(claims(sent.token).exp - claims(sent.token).iat).toBe(90);
    }
    if (name === "delivery") {
      const issuedAt = claims(delivery(registered, "verification-mail").token).iat;
      await Bun.sleep(Math.max(0, (issuedAt + 1) * 1000 - Date.now() + 10));
    }
    const signout = await primary.client.signOut();
    const signin = await primary.client.signIn.email({ email, password: "password123", fetchOptions: { headers: { "x-lifecycle-marker": "signin-delivery" } } });
    if (name !== "default") expect(signin.error).toMatchObject({ status: 403, code: "EMAIL_NOT_VERIFIED" }); else expect(signin.error).toBeNull();
    const signed = await control(ctx, name);
    expect(signed.events.filter(event => event.stage === "verification-mail")).toHaveLength(name === "delivery" ? 2 : name === "required" ? 1 : 0);
    expect(signed.users).toEqual(registered.users); expect(signed.accounts).toEqual(registered.accounts);
    if (name === "delivery") expect(delivery(signed, "verification-mail").request).toEqual({ method: "POST", url: new URL(path(name, "sign-in/email"), ctx.baseURL).href, marker: "signin-delivery" });
    return evidence({ signup, registered, signout, signin, signed });
  }, ["POST /sign-up/email", "POST /sign-in/email"]);
}

for (const failure of ["", "before-verification", "after-verification"]) {
  compatScenario(`configured existing-session verification ${failure || "success"} preserves callbacks, cache snapshot and failure stage`, async ctx => {
    const name = "auto", primary = ctx.actor("owner", profile(name)), foreign = ctx.actor("foreign", profile(name));
    await control(ctx, name, "reset");
    const email = ctx.uniqueEmail("verify-existing"), signup = await primary.client.signUp.email({ email, password: "password123", name: "Original Session Snapshot" });
    const foreignSignup = await foreign.client.signUp.email({ email: ctx.uniqueEmail("verify-foreign"), password: "password123", name: "Foreign Session Snapshot" });
    expect(signup.error).toBeNull(); expect(foreignSignup.error).toBeNull();
    if (!signup.data || !foreignSignup.data) throw new Error("Snapshot verification requires two real sessions");
    await control(ctx, name, "reset");
    const send = await primary.client.sendVerificationEmail({ email, fetchOptions: { headers: { "x-lifecycle-marker": "verification-delivery" } } });
    expect(send.error).toBeNull();
    const sent = await control(ctx, name, "failure", { failure }), mail = delivery(sent, "verification-mail");
    expect(mail.user).toEqual(sent.users.find(user => user.id === signup.data!.user.id)!);
    expect(mail.request).toEqual({ method: "POST", url: new URL(path(name, "send-verification-email"), ctx.baseURL).href, marker: "verification-delivery" });
    let verificationCookies: string[] = [];
    const verify = await primary.client.verifyEmail({ query: { token: mail.token }, fetchOptions: { headers: { "x-lifecycle-marker": "verification-hook" }, onResponse({ response }) { verificationCookies = response.headers.getSetCookie(); } } });
    if (failure) expect(verify.error).toMatchObject({ status: 400, code: "LIFECYCLE_REJECTED", message: `Application ${failure} rejected` }); else expect(verify.error).toBeNull();
    const finished = await control(ctx, name), original = sent.users.find(user => user.id === signup.data!.user.id)!;
    expect(foreignRows(finished, foreignSignup.data.user.id)).toEqual(foreignRows(sent, foreignSignup.data.user.id));
    expect(finished.accounts).toEqual(sent.accounts); expect(finished.sessions).toEqual(sent.sessions);
    expect(finished.users.find(user => user.id === original.id)?.emailVerified).toBe(failure !== "before-verification");
    const callbacks = finished.events.filter(event => ["before-verification", "after-verification"].includes(String(event.stage)));
    expect(callbacks.map(event => event.stage)).toEqual(failure === "before-verification" ? ["before-verification"] : ["before-verification", "after-verification"]);
    expect(callbacks[0]?.user).toEqual(original);
    if (failure !== "before-verification") expect(callbacks[1]?.user).toEqual(finished.users.find(user => user.id === original.id));
    for (const callback of callbacks) expect(callback.request).toEqual({ method: "GET", url: new URL(path(name, `verify-email?token=${encodeURIComponent(mail.token)}`), ctx.baseURL).href, marker: "verification-hook" });
    expect(verificationCookies.filter(cookie => cookie.startsWith("better-auth.session_token="))).toHaveLength(failure ? 0 : 1);
    expect(verificationCookies.filter(cookie => cookie.startsWith("better-auth.session_data="))).toHaveLength(failure ? 0 : 1);
    if (!failure) expect(finished.events.findLast(event => event.stage === "cache")?.user).toEqual({ ...original, emailVerified: true });
    const session = await primary.client.getSession();
    expect(ctx.snapshot(session.data?.session.token)).toEqual(signup.data.token);
    expect(session.data?.user.emailVerified).toBe(!failure);
    await control(ctx, name, "failure", { failure: "" });
    const replay = await primary.client.verifyEmail({ query: { token: mail.token } });
    expect(replay.error).toBeNull();
    const replayed = await control(ctx, name);
    expect(replayed.users.find(user => user.id === original.id)?.emailVerified).toBe(true);
    if (failure !== "before-verification") expect(replayed.events.filter(event => ["before-verification", "after-verification"].includes(String(event.stage)))).toEqual(callbacks);
    return evidence({ signup, foreignSignup, send, sent, verify, verificationCache: await cacheEvidence(verificationCookies), finished, session, replay, replayed });
  }, ["GET /verify-email"]);
}

for (const name of ["delete-mail", "delete-zero", "delete-expired"]) {
  compatScenario(`configured ${name} issues and delivers a real deletion proof, retains sessions and owns expiry and replay`, async ctx => {
    const owner = ctx.actor("owner", profile(name)), secondary = ctx.actor("secondary", profile(name)), foreign = ctx.actor("foreign", profile(name));
    await control(ctx, name, "reset");
    const email = ctx.uniqueEmail("deletion-issued-owner"), signup = await owner.client.signUp.email({ email, password: "password123", name: "Issued Deletion Owner" });
    const secondSession = await secondary.client.signIn.email({ email, password: "password123" });
    const foreignSignup = await foreign.client.signUp.email({ email: ctx.uniqueEmail("deletion-issued-foreign"), password: "password123", name: "Issued Deletion Foreign" });
    expect(signup.error).toBeNull(); expect(secondSession.error).toBeNull(); expect(foreignSignup.error).toBeNull();
    if (!signup.data || !foreignSignup.data) throw new Error("Deletion requires real owner and foreign sessions");
    const before = await control(ctx, name);
    let cookies: string[] = [];
    const requested = await owner.client.deleteUser({ callbackURL: "/lifecycle-return?flow=deletion", fetchOptions: { headers: { "x-lifecycle-marker": "deletion-delivery" }, onResponse({ response }) { cookies = response.headers.getSetCookie(); } } });
    expect(requested.error).toBeNull(); expect(requested.data).toEqual({ success: true, message: "Verification email sent" }); expect(cookies).toEqual([]);
    const issued = await control(ctx, name), mail = delivery(issued, "deletion-mail");
    expect(issued.users).toEqual(before.users); expect(issued.accounts).toEqual(before.accounts); expect(issued.sessions).toEqual(before.sessions);
    expect(mail.user).toEqual(before.users.find(user => user.id === signup.data!.user.id)!);
    expect(mail.request).toEqual({ method: "POST", url: new URL(path(name, "delete-user"), ctx.baseURL).href, marker: "deletion-delivery" });
    expect(mail.token).toMatch(/^[a-z0-9]{32}$/);
    const proof = issued.verifications.find(proof => proof.token === mail.token);
    expect(proof).toMatchObject({ identifierPrefix: "delete-account-", userId: signup.data.user.id });
    expect(Math.abs(Date.parse(String(proof!.expiresAt)) - Date.parse(String(proof!.createdAt)) - (name === "delete-zero" ? 86400 : name === "delete-expired" ? -1 : 90) * 1000)).toBeLessThan(1000);
    const deliveredURL = new URL(mail.url);
    expect(deliveredURL.pathname).toBe(path(name, "delete-user/callback"));
    expect(deliveredURL.searchParams.get("token")).toBe(mail.token); expect(deliveredURL.searchParams.get("callbackURL")).toBe("/lifecycle-return?flow=deletion");
    const retained = await owner.client.getSession(); expect(ctx.snapshot(retained.data?.session.token)).toEqual(signup.data.token);
    const response = await owner.fetch(mail.url, { redirect: "manual", headers: { "x-lifecycle-marker": "deletion-callback" } });
    const callback = { status: response.status, location: response.headers.get("location"), body: await responseBody(response) };
    expect(callback.status).toBe(name === "delete-expired" ? 404 : 302);
    const after = await control(ctx, name);
    expect(after.verifications).toEqual([]);
    expect(foreignRows(after, foreignSignup.data.user.id)).toEqual(foreignRows(before, foreignSignup.data.user.id));
    expect(foreignRows(after, signup.data.user.id)).toEqual(name === "delete-expired" ? foreignRows(before, signup.data.user.id) : { users: [], accounts: [], sessions: [] });
    expect(after.events.filter(event => ["before-delete", "after-delete"].includes(String(event.stage))).map(event => event.stage)).toEqual(name === "delete-expired" ? [] : ["before-delete", "after-delete"]);
    const replayResponse = await owner.fetch(mail.url, { redirect: "manual" }), replay = { status: replayResponse.status, body: await responseBody(replayResponse) };
    expect(replay.status).toBe(404);
    const current = await owner.client.getSession(), otherSession = await secondary.client.getSession();
    if (name !== "delete-expired") {expect(current.data).toBeNull(); expect(otherSession.data).toBeNull();}
    const final = await control(ctx, name); expect(final.users).toEqual(after.users); expect(final.accounts).toEqual(after.accounts); expect(final.sessions).toEqual(after.sessions); expect(final.verifications).toEqual([]);
    return evidence({ signup, secondSession, foreignSignup, before, requested, issued, retained, callback, after, replay, current, otherSession, final });
  }, ["POST /delete-user", "GET /delete-user/callback"]);
}

for (const mode of ["wrong-owner", "before-delete", "after-delete", "deletion-mail"]) {
  compatScenario(`configured deletion ${mode} retains exact delivery, consumption and callback-error ordering`, async ctx => {
    const name = "delete-mail", owner = ctx.actor("owner", profile(name)), foreign = ctx.actor("foreign", profile(name));
    await control(ctx, name, "reset");
    const signup = await owner.client.signUp.email({ email: ctx.uniqueEmail("deletion-order-owner"), password: "password123", name: "Deletion Order Owner" });
    const foreignSignup = await foreign.client.signUp.email({ email: ctx.uniqueEmail("deletion-order-foreign"), password: "password123", name: "Deletion Order Foreign" });
    expect(signup.error).toBeNull(); expect(foreignSignup.error).toBeNull();
    if (!signup.data || !foreignSignup.data) throw new Error("Deletion ordering requires two actual principals");
    const before = await control(ctx, name, "failure", { failure: mode === "deletion-mail" ? mode : "" });
    const requested = await owner.client.deleteUser(); expect(requested.error).toBeNull();
    const issued = await control(ctx, name, "failure", { failure: mode === "before-delete" || mode === "after-delete" ? mode : "" }), mail = delivery(issued, "deletion-mail");
    expect(issued.verifications).toHaveLength(1); expect(issued.users).toEqual(before.users); expect(issued.accounts).toEqual(before.accounts); expect(issued.sessions).toEqual(before.sessions);
    const caller = mode === "wrong-owner" ? foreign : owner;
    const response = await caller.fetch(path(name, `delete-user/callback?token=${encodeURIComponent(mail.token)}`), { redirect: "manual", headers: { "x-lifecycle-marker": "deletion-order" } });
    const callback = { status: response.status, body: await response.json() };
    expect(callback.status).toBe(mode === "wrong-owner" ? 404 : mode === "deletion-mail" ? 200 : 400);
    const after = await control(ctx, name); expect(after.verifications).toEqual([]);
    expect(foreignRows(after, foreignSignup.data.user.id)).toEqual(foreignRows(before, foreignSignup.data.user.id));
    const deletesOwner = mode === "after-delete" || mode === "deletion-mail";
    expect(foreignRows(after, signup.data.user.id)).toEqual(deletesOwner ? { users: [], accounts: [], sessions: [] } : foreignRows(before, signup.data.user.id));
    const callbacks = after.events.filter(event => ["before-delete", "after-delete"].includes(String(event.stage)));
    expect(callbacks.map(event => event.stage)).toEqual(mode === "wrong-owner" ? [] : mode === "before-delete" ? ["before-delete"] : ["before-delete", "after-delete"]);
    for (const event of callbacks) {expect(event.user).toEqual(before.users.find(user => user.id === signup.data!.user.id)!); expect(event.request).toEqual({ method: "GET", url: new URL(path(name, `delete-user/callback?token=${encodeURIComponent(mail.token)}`), ctx.baseURL).href, marker: "deletion-order" });}
    await control(ctx, name, "failure", { failure: "" });
    const replayResponse = await owner.fetch(path(name, `delete-user/callback?token=${encodeURIComponent(mail.token)}`), { redirect: "manual" });
    const replay = { status: replayResponse.status, body: await replayResponse.json() }; expect(replay.status).toBe(404);
    const session = await owner.client.getSession(); if (deletesOwner) expect(session.data).toBeNull(); else expect(session.data?.user.id).toBe(signup.data.user.id);
    const final = await control(ctx, name); expect(final.users).toEqual(after.users); expect(final.accounts).toEqual(after.accounts); expect(final.sessions).toEqual(after.sessions); expect(final.verifications).toEqual([]);
    return evidence({ signup, foreignSignup, before, requested, issued, callback, after, replay, session, final });
  }, ["GET /delete-user/callback"]);
}

for (const mode of ["wrong-password", "maximum", "verify-error", "valid-password", "empty-stale", "stale-default", "no-freshness"]) {
  compatScenario(`configured deletion ${mode} enforces the initialized password policy and fresh-session authority`, async ctx => {
    const name = mode === "no-freshness" ? "delete-no-freshness" : mode === "stale-default" || mode === "empty-stale" ? "delete" : "delete-policy", owner = ctx.actor("owner", profile(name)), foreign = ctx.actor("foreign", profile(name));
    await control(ctx, name, "reset");
    const signup = await owner.client.signUp.email({ email: ctx.uniqueEmail("deletion-password-owner"), password: "password123", name: "Deletion Password Owner" });
    const foreignSignup = await foreign.client.signUp.email({ email: ctx.uniqueEmail("deletion-password-foreign"), password: "password123", name: "Deletion Password Foreign" });
    expect(signup.error).toBeNull(); expect(foreignSignup.error).toBeNull();
    if (!signup.data || !foreignSignup.data) throw new Error("Deletion policy requires physical owner and foreign sessions");
    if (["empty-stale", "stale-default", "no-freshness"].includes(mode)) await control(ctx, name, "session-clock", { token: signup.data.token, createdAt: "2001-01-01T00:00:00.000Z" });
    const before = await control(ctx, name, "failure", { failure: mode === "verify-error" ? "password-verify" : "" });
    const password = mode === "maximum" ? "x".repeat(13) : mode === "wrong-password" ? "notpassword" : mode === "empty-stale" ? "" : mode === "stale-default" || mode === "no-freshness" ? undefined : "password123";
    const remove = await owner.client.deleteUser({ ...(password !== undefined ? { password } : {}) });
    const succeeds = mode === "valid-password" || mode === "no-freshness";
    if (succeeds) expect(remove.error).toBeNull(); else expect(remove.error).toMatchObject({ status: 400, code: mode === "maximum" ? "PASSWORD_TOO_LONG" : mode === "wrong-password" ? "INVALID_PASSWORD" : mode === "verify-error" ? "LIFECYCLE_REJECTED" : "SESSION_EXPIRED" });
    const after = await control(ctx, name); expect(foreignRows(after, foreignSignup.data.user.id)).toEqual(foreignRows(before, foreignSignup.data.user.id));
    expect(foreignRows(after, signup.data.user.id)).toEqual(succeeds ? { users: [], accounts: [], sessions: [] } : foreignRows(before, signup.data.user.id));
    const verifies = after.events.filter(event => event.stage === "password-verify");
    expect(verifies).toHaveLength(["wrong-password", "verify-error", "valid-password"].includes(mode) ? 1 : 0);
    if (verifies.length) expect(verifies[0]).toMatchObject({ password, hash: before.accounts.find(account => account.userId === signup.data!.user.id)?.password });
    expect(after.events.filter(event => ["before-delete", "after-delete"].includes(String(event.stage))).map(event => event.stage)).toEqual(succeeds ? ["before-delete", "after-delete"] : []);
    return evidence({ signup, foreignSignup, before, remove, after });
  }, ["POST /delete-user"]);
}

for (const name of ["no-mail"]) {
  compatScenario(`configured ${name} mailbox-change guard keeps occupied and available stages private`, async ctx => {
    const owner = ctx.actor("owner", profile(name)), foreign = ctx.actor("foreign", profile(name));
    await control(ctx, name, "reset");
    const signup = await owner.client.signUp.email({ email: ctx.uniqueEmail("change-guard"), password: "password123", name: "Change Guard Owner" });
    const target = ctx.uniqueEmail("change-guard-foreign"), foreignSignup = await foreign.client.signUp.email({ email: target, password: "password123", name: "Guard Foreign" });
    expect(signup.error).toBeNull(); expect(foreignSignup.error).toBeNull();
    const before = await control(ctx, name);
    const occupied = await owner.client.changeEmail({ newEmail: target });
    const available = await owner.client.changeEmail({ newEmail: ctx.uniqueEmail("change-guard-new") });
    if (name === "no-mail") {
      expect(occupied.error).toMatchObject({ status: 400, message: "Verification email isn't enabled" });
      expect(available.error).toEqual(occupied.error);
      expect(await control(ctx, name)).toEqual(before);
    } else { expect(occupied.error).toBeNull(); expect(available.error).toBeNull(); }
    return evidence({ signup, foreignSignup, before, occupied, available, after: await control(ctx, name) });
  }, ["POST /change-email"]);
}

compatScenario("configured mailbox changes conceal occupied addresses and preserve complete foreign rows", async ctx => {
  const name = "default", primary = ctx.actor("owner", profile(name)), foreign = ctx.actor("foreign", profile(name));
  await control(ctx, name, "reset");
  const email = ctx.uniqueEmail("mailbox-owner"), foreignEmail = ctx.uniqueEmail("mailbox-foreign");
  const signup = await primary.client.signUp.email({ email, password: "password123", name: "Mailbox Owner" });
  const foreignSignup = await foreign.client.signUp.email({ email: foreignEmail, password: "password123", name: "Mailbox Foreign" });
  expect(signup.error).toBeNull(); expect(foreignSignup.error).toBeNull();
  if (!signup.data || !foreignSignup.data) throw new Error("Mailbox privacy requires both persisted owners");
  const before = await control(ctx, name);
  const occupied = await primary.client.changeEmail({ newEmail: foreignEmail });
  expect(occupied.error).toBeNull(); expect(occupied.data).toEqual({ status: true });
  const after = await control(ctx, name);
  expect(after).toEqual(before);
  const availableEmail = ctx.uniqueEmail("mailbox-available");
  const available = await primary.client.changeEmail({ newEmail: availableEmail });
  expect(available.error).toBeNull(); expect(available.data).toEqual(occupied.data);
  const pending = await control(ctx, name);
  expect(foreignRows(pending, foreignSignup.data.user.id)).toEqual(foreignRows(before, foreignSignup.data.user.id));
  expect(pending.users).toEqual(before.users); expect(pending.accounts).toEqual(before.accounts); expect(pending.sessions).toEqual(before.sessions);
  const delivery = pending.events.find(event => event.stage === "verification-mail");
  expect(delivery?.user).toMatchObject({ id: signup.data.user.id, email: availableEmail });
  return evidence({ signup, foreignSignup, before, occupied, after, available, pending });
}, ["POST /change-email"]);

for (const failure of ["before-delete", "after-delete"]) {
  compatScenario(`configured deletion propagates ${failure} and preserves its persisted stage and foreign rows`, async ctx => {
    const name = "delete", primary = ctx.actor("owner", profile(name)), foreign = ctx.actor("foreign", profile(name));
    await control(ctx, name, "reset");
    const signup = await primary.client.signUp.email({ email: ctx.uniqueEmail("delete-hooks-owner"), password: "password123", name: "Delete Hook Owner" });
    const foreignSignup = await foreign.client.signUp.email({ email: ctx.uniqueEmail("delete-hooks-foreign"), password: "password123", name: "Delete Hook Foreign" });
    expect(signup.error).toBeNull(); expect(foreignSignup.error).toBeNull();
    if (!signup.data || !foreignSignup.data) throw new Error("Deletion hook isolation requires two persisted users");
    const before = await control(ctx, name, "failure", { failure });
    const remove = await primary.client.deleteUser({ fetchOptions: { headers: { "x-lifecycle-marker": "delete-hook" } } });
    expect(remove.error).toMatchObject({ status: 400, code: "LIFECYCLE_REJECTED", message: `Application ${failure} rejected` });
    const after = await control(ctx, name);
    expect(foreignRows(after, foreignSignup.data.user.id)).toEqual(foreignRows(before, foreignSignup.data.user.id));
    expect(after.events.map(event => event.stage)).toEqual(failure === "before-delete" ? ["before-delete"] : ["before-delete", "after-delete"]);
    for (const event of after.events) {
      expect(event.user).toEqual(before.users.find(user => user.id === signup.data!.user.id)!);
      expect(event.request).toMatchObject({ method: "POST", marker: "delete-hook", url: new URL(path(name, "delete-user"), ctx.baseURL).href });
    }
    expect(foreignRows(after, signup.data.user.id)).toEqual(failure === "before-delete" ? foreignRows(before, signup.data.user.id) : { users: [], accounts: [], sessions: [] });
    return evidence({ signup, foreignSignup, before, remove, after });
  }, ["POST /delete-user"]);
}

for (const mode of ["existing", "anonymous", "after-verification", "confirmation-mail"]) {
  compatScenario(`configured verified mailbox ${mode} preserves old confirmation, new verification and persisted stage`, async ctx => {
    const name = "change", owner = ctx.actor("owner", profile(name)), foreign = ctx.actor("foreign", profile(name)), anonymous = ctx.actor("anonymous", profile(name));
    await control(ctx, name, "reset");
    const email = ctx.uniqueEmail("change-confirm-owner"), target = ctx.uniqueEmail("change-confirm-target");
    const signup = await owner.client.signUp.email({ email, password: "password123", name: "Confirmed Original Snapshot" });
    const foreignSignup = await foreign.client.signUp.email({ email: ctx.uniqueEmail("change-confirm-foreign"), password: "password123", name: "Confirmation Foreign" });
    expect(signup.error).toBeNull(); expect(foreignSignup.error).toBeNull();
    if (!signup.data || !foreignSignup.data) throw new Error("Confirmation requires actual owner and foreign sessions");
    expect((await owner.client.sendVerificationEmail({ email })).error).toBeNull();
    const initial = delivery(await control(ctx, name), "verification-mail");
    expect((await owner.client.verifyEmail({ query: { token: initial.token } })).error).toBeNull();
    const before = await control(ctx, name, "reset"), original = before.users.find(user => user.id === signup.data!.user.id)!;
    expect(original.emailVerified).toBe(true);
    await control(ctx, name, "failure", { failure: mode === "confirmation-mail" ? mode : "" });
    const request = await owner.client.changeEmail({ newEmail: target, fetchOptions: { headers: { "x-lifecycle-marker": "old-mailbox" } } });
    expect(request.error).toBeNull();
    const pending = await control(ctx, name), oldMail = delivery(pending, "confirmation-mail");
    expect(oldMail.user).toEqual(original); expect(oldMail.newEmail).toBe(target);
    expect(oldMail.request).toEqual({ method: "POST", url: new URL(path(name, "change-email"), ctx.baseURL).href, marker: "old-mailbox" });
    expect(claims(oldMail.token)).toMatchObject({ email, updateTo: target, requestType: "change-email-confirmation" });
    expect(claims(oldMail.token).exp - claims(oldMail.token).iat).toBe(90);
    expect(pending.users).toEqual(before.users); expect(pending.accounts).toEqual(before.accounts); expect(pending.sessions).toEqual(before.sessions);
    await control(ctx, name, "failure", { failure: "" });
    const wrongOwner = await foreign.client.verifyEmail({ query: { token: oldMail.token } });
    expect(wrongOwner.error).toMatchObject({ status: 401, code: "INVALID_USER" });
    const denied = await control(ctx, name); expect(denied.users).toEqual(before.users); expect(denied.sessions).toEqual(before.sessions);
    expect(denied.events.filter(event => event.stage === "verification-mail")).toEqual([]);
    const confirmer = mode === "anonymous" || mode === "after-verification" ? anonymous : owner;
    const confirm = await confirmer.client.verifyEmail({ query: { token: oldMail.token }, fetchOptions: { headers: { "x-lifecycle-marker": "old-confirmation" } } });
    expect(confirm.error).toBeNull(); expect(confirm.data).toEqual({ status: true });
    const confirmed = await control(ctx, name), newMail = delivery(confirmed, "verification-mail");
    expect(newMail.user).toEqual({ ...original, email: target });
    expect(newMail.request).toEqual({ method: "GET", url: new URL(path(name, `verify-email?token=${encodeURIComponent(oldMail.token)}`), ctx.baseURL).href, marker: "old-confirmation" });
    expect(claims(newMail.token)).toMatchObject({ email, updateTo: target, requestType: "change-email-verification" });
    expect(claims(newMail.token).exp - claims(newMail.token).iat).toBe(90);
    expect(confirmed.users).toEqual(before.users); expect(confirmed.sessions).toEqual(before.sessions);
    await control(ctx, name, "failure", { failure: mode === "after-verification" ? mode : "" });
    let cookies: string[] = [];
    const finish = await confirmer.client.verifyEmail({ query: { token: newMail.token }, fetchOptions: { headers: { "x-lifecycle-marker": "new-verification" }, onResponse({ response }) { cookies = response.headers.getSetCookie(); } } });
    if (mode === "after-verification") expect(finish.error).toMatchObject({ status: 400, code: "LIFECYCLE_REJECTED" }); else expect(finish.error).toBeNull();
    const after = await control(ctx, name), updated = after.users.find(user => user.id === original.id)!;
    expect(updated).toMatchObject({ id: original.id, email: target, emailVerified: true });
    expect(foreignRows(after, foreignSignup.data.user.id)).toEqual(foreignRows(before, foreignSignup.data.user.id));
    expect(after.accounts).toEqual(before.accounts);
    expect(after.sessions.filter(session => session.userId === original.id)).toHaveLength(mode === "anonymous" || mode === "after-verification" ? 2 : 1);
    const hooks = after.events.filter(event => ["before-verification", "after-verification"].includes(String(event.stage)));
    expect(hooks.map(event => event.stage)).toEqual(["after-verification"]); expect(hooks[0]?.user).toEqual(updated);
    expect(hooks[0]?.request).toEqual({ method: "GET", url: new URL(path(name, `verify-email?token=${encodeURIComponent(newMail.token)}`), ctx.baseURL).href, marker: "new-verification" });
    expect(cookies.filter(cookie => cookie.startsWith("better-auth.session_token="))).toHaveLength(mode === "after-verification" ? 0 : 1);
    expect(cookies.filter(cookie => cookie.startsWith("better-auth.session_data="))).toHaveLength(mode === "after-verification" ? 0 : 1);
    let cache: unknown = null, session: unknown = null;
    if (mode !== "after-verification") {
      cache = await cacheEvidence(cookies); const current = await confirmer.client.getSession(); session = current;
      expect(ctx.snapshot(current.data?.user)).toEqual({ ...original, email: target });
      expect(current.data?.session.token === signup.data.token).toBe(mode !== "anonymous");
    }
    await control(ctx, name, "failure", { failure: "" });
    const replay = await confirmer.client.verifyEmail({ query: { token: newMail.token } });
    expect(replay.error).toMatchObject({ status: 401, code: "USER_NOT_FOUND" });
    const replayed = await control(ctx, name); expect(replayed.users).toEqual(after.users); expect(replayed.sessions).toEqual(after.sessions);
    return evidence({ signup, foreignSignup, before, request, pending, wrongOwner, denied, confirm, confirmed, finish, cache, after, session, replay, replayed });
  }, ["POST /change-email", "GET /verify-email"]);
}

for (const name of ["change", "promotion", "promotion-no-mail"]) {
  compatScenario(`configured unverified mailbox ${name} protects promotion and new-mail verification with the original session snapshot`, async ctx => {
    const owner = ctx.actor("owner", profile(name)), foreign = ctx.actor("foreign", profile(name));
    await control(ctx, name, "reset");
    const email = ctx.uniqueEmail("change-unverified-owner"), target = ctx.uniqueEmail("change-unverified-target");
    const signup = await owner.client.signUp.email({ email, password: "password123", name: "Unverified Original Snapshot" });
    const foreignSignup = await foreign.client.signUp.email({ email: ctx.uniqueEmail("change-unverified-foreign"), password: "password123", name: "Unverified Foreign" });
    expect(signup.error).toBeNull(); expect(foreignSignup.error).toBeNull();
    if (!signup.data || !foreignSignup.data) throw new Error("Promotion requires actual principals");
    let oldToken: string | null = null;
    if (name !== "promotion-no-mail") {expect((await owner.client.sendVerificationEmail({ email })).error).toBeNull(); oldToken = delivery(await control(ctx, name), "verification-mail").token;}
    const before = await control(ctx, name, "reset"), original = before.users.find(user => user.id === signup.data!.user.id)!;
    let cookies: string[] = [];
    const change = await owner.client.changeEmail({ newEmail: target, fetchOptions: { headers: { "x-lifecycle-marker": "unverified-change" }, onResponse({ response }) { cookies = response.headers.getSetCookie(); } } });
    expect(change.error).toBeNull(); expect(change.data).toEqual({ status: true });
    const pending = await control(ctx, name), immediate = name !== "change";
    expect(pending.users.find(user => user.id === original.id)?.email).toBe(immediate ? target : email);
    expect(pending.accounts).toEqual(before.accounts); expect(pending.sessions).toEqual(before.sessions);
    expect(foreignRows(pending, foreignSignup.data.user.id)).toEqual(foreignRows(before, foreignSignup.data.user.id));
    expect(pending.events.filter(event => event.stage === "confirmation-mail")).toEqual([]);
    expect(cookies.filter(cookie => cookie.startsWith("better-auth.session_token="))).toHaveLength(immediate ? 1 : 0);
    const cache = await cacheEvidence(cookies);
    let finish: unknown = null;
    if (name !== "promotion-no-mail") {
      const mail = delivery(pending, "verification-mail"); expect(mail.user).toEqual({ ...original, email: target });
      expect(mail.request).toEqual({ method: "POST", url: new URL(path(name, "change-email"), ctx.baseURL).href, marker: "unverified-change" });
      expect(claims(mail.token)).toMatchObject(immediate ? { email: target } : { email, updateTo: target, requestType: "change-email-verification" });
      if (immediate) {expect(claims(mail.token).updateTo).toBeUndefined(); expect(claims(mail.token).requestType).toBeUndefined();}
      expect(claims(mail.token).exp - claims(mail.token).iat).toBe(90);
      const verified = await owner.client.verifyEmail({ query: { token: mail.token } }); finish = verified; expect(verified.error).toBeNull();
    }
    const after = await control(ctx, name), updated = after.users.find(user => user.id === original.id)!;
    expect(updated).toMatchObject({ email: target, emailVerified: name !== "promotion-no-mail" });
    const current = await owner.client.getSession(); expect(ctx.snapshot(current.data?.session.token)).toEqual(signup.data.token);
    if (name !== "promotion-no-mail") expect(ctx.snapshot(current.data?.user)).toEqual({ ...original, email: target, emailVerified: name === "change" });
    const replay = oldToken ? await owner.client.verifyEmail({ query: { token: oldToken } }) : null;
    if (replay) expect(replay.error).toMatchObject({ status: 401, code: "USER_NOT_FOUND" });
    const same = await owner.client.changeEmail({ newEmail: target }); expect(same.error).toMatchObject({ status: 400, message: "Email is the same" });
    const final = await control(ctx, name); expect(final.users).toEqual(after.users); expect(final.accounts).toEqual(after.accounts); expect(final.sessions).toEqual(after.sessions);
    return evidence({ signup, foreignSignup, before, change, pending, cache, finish, after, current, replay, same, final });
  }, ["POST /change-email", "GET /verify-email"]);
}

for (const mode of ["anonymous", "foreign"]) {
  compatScenario(`configured verification ${mode} creates a real owner session without changing foreign authority`, async ctx => {
    const name = "auto", owner = ctx.actor("owner", profile(name)), foreign = ctx.actor("foreign", profile(name)), caller = mode === "foreign" ? foreign : ctx.actor("anonymous", profile(name));
    await control(ctx, name, "reset");
    const email = ctx.uniqueEmail("verify-new-owner"), signup = await owner.client.signUp.email({ email, password: "password123", name: "New Verification Owner" });
    const other = await foreign.client.signUp.email({ email: ctx.uniqueEmail("verify-new-foreign"), password: "password123", name: "New Verification Foreign" });
    expect(signup.error).toBeNull(); expect(other.error).toBeNull(); if (!signup.data || !other.data) throw new Error("New verification session requires actual users");
    const before = await control(ctx, name, "reset");
    expect((await owner.client.sendVerificationEmail({ email })).error).toBeNull();
    const sent = await control(ctx, name), mail = delivery(sent, "verification-mail"); let cookies: string[] = [];
    const verify = await caller.client.verifyEmail({ query: { token: mail.token }, fetchOptions: { onResponse({ response }) { cookies = response.headers.getSetCookie(); } } });
    expect(verify.error).toBeNull();
    const after = await control(ctx, name), original = before.users.find(user => user.id === signup.data!.user.id)!;
    expect(after.users.find(user => user.id === original.id)?.emailVerified).toBe(true);
    expect(after.accounts).toEqual(before.accounts); expect(foreignRows(after, other.data.user.id)).toEqual(foreignRows(before, other.data.user.id));
    expect(after.sessions.filter(session => session.userId === original.id)).toHaveLength(2);
    const cache = await cacheEvidence(cookies), current = await caller.client.getSession();
    expect(ctx.snapshot(current.data?.user)).toEqual({ ...original, emailVerified: true }); expect(current.data?.session.token).not.toEqual(signup.data.token);
    return evidence({ signup, other, before, sent, verify, after, cache, current });
  }, ["GET /verify-email"]);
}

compatScenario("configured expired email verification preserves every row and rejects its real delivered proof on replay", async ctx => {
  const name = "verification-expired", owner = ctx.actor("owner", profile(name)), foreign = ctx.actor("foreign", profile(name));
  await control(ctx, name, "reset");
  const email = ctx.uniqueEmail("expired-email-owner"), signup = await owner.client.signUp.email({ email, password: "password123", name: "Expired Email Owner" });
  const other = await foreign.client.signUp.email({ email: ctx.uniqueEmail("expired-email-foreign"), password: "password123", name: "Expired Email Foreign" });
  expect(signup.error).toBeNull(); expect(other.error).toBeNull();
  expect((await owner.client.sendVerificationEmail({ email })).error).toBeNull();
  const before = await control(ctx, name), mail = delivery(before, "verification-mail");
  expect(claims(mail.token).exp - claims(mail.token).iat).toBe(-1);
  const verify = await owner.client.verifyEmail({ query: { token: mail.token } }), replay = await owner.client.verifyEmail({ query: { token: mail.token } });
  expect(verify.error).toMatchObject({ status: 401, code: "TOKEN_EXPIRED" }); expect(replay).toEqual(verify);
  const after = await control(ctx, name); expect(after).toEqual(before);
  return evidence({ signup, other, before, verify, replay, after });
}, ["GET /verify-email"]);

compatScenario("configured deletion consumes its real proof before the application hook so concurrent replay cannot delete twice", async ctx => {
  const name = "delete-mail", owner = ctx.actor("owner", profile(name)), foreign = ctx.actor("foreign", profile(name));
  await control(ctx, name, "reset");
  const signup = await owner.client.signUp.email({ email: ctx.uniqueEmail("delete-race-owner"), password: "password123", name: "Concurrent Deletion Owner" });
  const other = await foreign.client.signUp.email({ email: ctx.uniqueEmail("delete-race-foreign"), password: "password123", name: "Concurrent Deletion Foreign" });
  expect(signup.error).toBeNull(); expect(other.error).toBeNull(); if (!signup.data || !other.data) throw new Error("Deletion race requires physical principals");
  expect((await owner.client.deleteUser()).error).toBeNull();
  const issued = await control(ctx, name, "hold"), mail = delivery(issued, "deletion-mail");
  expect(issued.verifications).toHaveLength(1);
  const endpoint = path(name, `delete-user/callback?token=${encodeURIComponent(mail.token)}`);
  const first = owner.fetch(endpoint, { redirect: "manual", headers: { "x-lifecycle-marker": "first-deletion" } });
  let held: LifecycleState, released: LifecycleState, replay: { status: number; body: unknown };
  try {
    held = await control(ctx, name, "ready");
    expect(held.verifications).toEqual([]); expect(held.users).toEqual(issued.users); expect(held.accounts).toEqual(issued.accounts); expect(held.sessions).toEqual(issued.sessions);
    const response = await owner.fetch(endpoint, { redirect: "manual", headers: { "x-lifecycle-marker": "concurrent-replay" } });
    replay = { status: response.status, body: await responseBody(response) }; expect(replay.status).toBe(404); expect(replay.body).toEqual({ code: "INVALID_TOKEN", message: "Invalid token" });
  } finally { released = await control(ctx, name, "release"); }
  expect(released).toEqual(held!);
  const response = await first, completed = { status: response.status, body: await responseBody(response) }; expect(completed.status).toBe(200);
  const after = await control(ctx, name);
  expect(foreignRows(after, signup.data.user.id)).toEqual({ users: [], accounts: [], sessions: [] }); expect(foreignRows(after, other.data.user.id)).toEqual(foreignRows(issued, other.data.user.id)); expect(after.verifications).toEqual([]);
  const hooks = after.events.filter(event => ["before-delete", "after-delete"].includes(String(event.stage)));
  expect(hooks.map(event => event.stage)).toEqual(["before-delete", "after-delete"]);
  for (const hook of hooks) expect(hook.request).toEqual({ method: "GET", url: new URL(endpoint, ctx.baseURL).href, marker: "first-deletion" });
  return evidence({ signup, other, issued, held, replay, completed, after });
}, ["GET /delete-user/callback"]);

compatScenario("user update and sensitive mailbox routes reject missing and stale authority before application callbacks or row changes", async ctx => {
  const name = "default", owner = ctx.actor("owner", profile(name)), outsider = ctx.actor("outsider", profile(name));
  await control(ctx, name, "reset");
  let originalCookie = "";
  const signup = await owner.client.signUp.email({ email: ctx.uniqueEmail("lifecycle-rejection"), password: "password123", name: "Authority Owner", fetchOptions: { onResponse({ response }) { originalCookie = response.headers.getSetCookie().map(cookie => cookie.split(";")[0]!).join("; "); } } });
  expect(signup.error).toBeNull(); if (!signup.data) throw new Error("Authority control needs an actual issued session");
  const before = await control(ctx, name), denied = [];
  for (const actor of [outsider, owner]) {
    if (actor === owner) expect((await owner.client.signOut()).error).toBeNull();
    const fetchOptions = actor === owner ? { headers: { cookie: originalCookie } } : {};
    const update = await actor.client.updateUser({ name: "Denied Mutation", fetchOptions }), change = await actor.client.changeEmail({ newEmail: ctx.uniqueEmail("denied-target"), fetchOptions }), remove = await actor.client.deleteUser({ fetchOptions });
    for (const result of [update, change, remove]) expect(result.error).toMatchObject({ status: 401, code: "UNAUTHORIZED", message: "Unauthorized" });
    denied.push({ update, change, remove });
  }
  const after = await control(ctx, name); expect(after.users).toEqual(before.users); expect(after.accounts).toEqual(before.accounts); expect(after.sessions).toEqual([]); expect(after.events).toEqual(before.events);
  return evidence({ signup, before, denied, after });
}, ["POST /update-user", "POST /change-email", "POST /delete-user"]);

for (const mode of ["wrong-password", "maximum", "after-delete"]) {
  compatScenario(`configured deletion body proof checks ${mode} before consumption and revokes only its owner after valid retry`, async ctx => {
    const name = "delete-mail", owner = ctx.actor("owner", profile(name)), foreign = ctx.actor("foreign", profile(name));
    await control(ctx, name, "reset");
    const signup = await owner.client.signUp.email({ email: ctx.uniqueEmail("delete-body-owner"), password: "password123", name: "Deletion Body Owner" });
    const other = await foreign.client.signUp.email({ email: ctx.uniqueEmail("delete-body-foreign"), password: "password123", name: "Deletion Body Foreign" });
    expect(signup.error).toBeNull(); expect(other.error).toBeNull(); if (!signup.data || !other.data) throw new Error("Deletion body proof requires physical users");
    expect((await owner.client.deleteUser()).error).toBeNull();
    const before = await control(ctx, name), mail = delivery(before, "deletion-mail"); expect(before.verifications).toHaveLength(1);
    const denied = await owner.client.deleteUser({ token: mail.token, password: mode === "maximum" ? "x".repeat(129) : "notpassword" });
    expect(denied.error).toMatchObject({ status: 400, code: mode === "maximum" ? "PASSWORD_TOO_LONG" : "INVALID_PASSWORD" });
    const retained = await control(ctx, name); expect(retained).toEqual(before);
    await control(ctx, name, "failure", { failure: mode === "after-delete" ? mode : "" });
    let cookies: string[] = [];
    const completed = await owner.client.deleteUser({ token: mail.token, password: "password123", fetchOptions: { onResponse({ response }) { cookies = response.headers.getSetCookie(); } } });
    if (mode === "after-delete") expect(completed.error).toMatchObject({ status: 400, code: "LIFECYCLE_REJECTED" }); else expect(completed.error).toBeNull();
    expect(cookies).toEqual([]);
    const after = await control(ctx, name); expect(foreignRows(after, signup.data.user.id)).toEqual({ users: [], accounts: [], sessions: [] }); expect(foreignRows(after, other.data.user.id)).toEqual(foreignRows(before, other.data.user.id)); expect(after.verifications).toEqual([]);
    expect(after.events.filter(event => ["before-delete", "after-delete"].includes(String(event.stage))).map(event => event.stage)).toEqual(["before-delete", "after-delete"]);
    return evidence({ signup, other, before, denied, retained, completed, after });
  }, ["POST /delete-user"]);
}

compatScenario("configured direct verification delivery propagates the application error while notification delivery retains its pending stage", async ctx => {
  const name = "default", owner = ctx.actor("owner", profile(name)); await control(ctx, name, "reset");
  const email = ctx.uniqueEmail("delivery-error-owner"), signup = await owner.client.signUp.email({ email, password: "password123", name: "Delivery Error Owner" }); expect(signup.error).toBeNull();
  const before = await control(ctx, name, "failure", { failure: "verification-mail" });
  const direct = await owner.client.sendVerificationEmail({ email }); expect(direct.error).toMatchObject({ status: 400, code: "LIFECYCLE_REJECTED" });
  const delivered = await control(ctx, name); expect(delivered.users).toEqual(before.users); expect(delivered.accounts).toEqual(before.accounts); expect(delivered.sessions).toEqual(before.sessions); expect(delivered.events.filter(event => event.stage === "verification-mail")).toHaveLength(1);
  const change = await owner.client.changeEmail({ newEmail: ctx.uniqueEmail("delivery-error-new") }); expect(change.error).toBeNull();
  const pending = await control(ctx, name); expect(pending.users).toEqual(before.users); expect(pending.accounts).toEqual(before.accounts); expect(pending.sessions).toEqual(before.sessions); expect(pending.events.filter(event => event.stage === "verification-mail")).toHaveLength(2);
  return evidence({ signup, before, direct, delivered, change, pending });
}, ["POST /send-verification-email", "POST /change-email"]);
