import { expect } from "bun:test";
import { z } from "zod";
import { compatScenario } from "../../support/scenario";
import { verifyPassword } from "better-auth/crypto";

async function observedCredential(account: Record<string, unknown>) {
  if (account.providerId !== "credential" || typeof account.password !== "string") return account;
  const hash = account.password;
  expect(hash).toMatch(/^[a-f0-9]{32}:[a-f0-9]{128}$/);
  expect(await verifyPassword({ hash, password: "Password123!" })).toBe(true);
  expect(await verifyPassword({ hash, password: "wrong-password-184" })).toBe(false);
  const [salt, derivedKey] = hash.split(":");
  return { ...account, password: { token: hash, salt: { token: salt, length: salt!.length }, derivedKey: { token: derivedKey, length: derivedKey!.length }, encoding: "hex-lower" } };
}
const stateSchema = z.object({ users: z.array(z.record(z.string(), z.unknown())), accounts: z.array(z.record(z.string(), z.unknown())), sessions: z.array(z.record(z.string(), z.unknown())), verifications: z.array(z.record(z.string(), z.unknown())), events: z.array(z.record(z.string(), z.unknown())) }).passthrough();
async function observedState(value: unknown) {
  const state = stateSchema.parse(value);
  const accounts = await Promise.all(state.accounts.map(observedCredential));
  const events = await Promise.all(state.events.map(async event => event.entity === "account" && event.phase === "after" ? { ...event, record: await observedCredential(z.record(z.string(), z.unknown()).parse(event.record)) } : event));
  return { ...state, accounts, events };
}

compatScenario("additional fields preserve application user account defaults and hidden physical storage across public signup and session reads", async ctx => {
  const foreign = ctx.actor("foreign", "additional-fields");
  const foreignSignup = await foreign.client.signUp.email({ email: ctx.uniqueEmail("foreign"), name: "Foreign", password: "Password123!" });
  expect(foreignSignup.error).toBeNull();
  const foreignId = z.object({ user: z.object({ id: z.string() }) }).parse(foreignSignup.data).user.id;
  const before = await ctx.rawRequest({ path: "/__test/additional-fields/state" }); expect(before.status).toBe(200);
  const owner = ctx.actor("owner", "additional-fields");
  const signup = await owner.client.signUp.email({ email: ctx.uniqueEmail("owner"), name: "Owner", password: "Password123!" });
  expect(signup.error).toBeNull();
  const user = z.object({ user: z.object({ id: z.string(), label: z.literal("user-initial") }).passthrough() }).parse(signup.data).user;
  expect(user).not.toHaveProperty("hidden"); expect(user).not.toHaveProperty("privateColumn"); expect(user).not.toHaveProperty("private_column");
  const session = await owner.client.getSession(); expect(session.error).toBeNull();
  expect(session.data?.user).toMatchObject({ id: user.id, label: "user-initial" });
  expect(session.data?.session).toMatchObject({ label: "session-initial" });
  expect(session.data?.session).not.toHaveProperty("hidden");
  const after = await ctx.rawRequest({ path: "/__test/additional-fields/state" }); expect(after.status).toBe(200);
  const state = z.object({ users: z.array(z.record(z.string(), z.unknown())), accounts: z.array(z.record(z.string(), z.unknown())), sessions: z.array(z.record(z.string(), z.unknown())), verifications: z.array(z.record(z.string(), z.unknown())) }).parse(after.body);
  const original = z.object({ users: z.array(z.record(z.string(), z.unknown())), accounts: z.array(z.record(z.string(), z.unknown())), sessions: z.array(z.record(z.string(), z.unknown())) }).parse(before.body);
  expect(state.users.filter(row => row.id === foreignId)).toEqual(original.users);
  expect(state.accounts.filter(row => row.userId === foreignId)).toEqual(original.accounts);
  expect(state.sessions.filter(row => row.userId === foreignId)).toEqual(original.sessions);
  expect(state.users.find(row => row.id === user.id)).toMatchObject({ label: "user-initial", hidden: "user-secret", private_column: "physical-private" });
  expect(state.accounts.find(row => row.userId === user.id)).toMatchObject({ label: "account-initial", hidden: "account-secret" });
  expect(state.sessions.find(row => row.userId === user.id)).toMatchObject({ label: "session-initial", hidden: "session-secret" });
  return { foreignSignup: ctx.snapshot(foreignSignup), before: await observedState(before.body), signup: ctx.snapshot(signup), session: ctx.snapshot(session), after: await observedState(after.body) };
}, ["POST /sign-up/email", "GET /get-session"]);

compatScenario("additional output transforms await real adapter results retain hidden undefined and changed types before committed after hooks and roll back failed signup", async ctx => {
  const foreign = ctx.actor("foreign-output", "additional-output-fields");
  const foreignSignup = await foreign.client.signUp.email({ email: ctx.uniqueEmail("foreign-output"), name: "Foreign output", password: "Password123!" });
  expect(foreignSignup.error).toBeNull();
  const foreignId = z.object({ user: z.object({ id: z.string() }) }).parse(foreignSignup.data).user.id;
  const before = await ctx.rawRequest({ path: "/__test/additional-fields/state?profile=output" }); expect(before.status).toBe(200);
  const original = stateSchema.parse(before.body);
  const owner = ctx.actor("owner-output", "additional-output-fields");
  const signup = await owner.client.signUp.email({ email: ctx.uniqueEmail("owner-output"), name: "Owner output", password: "Password123!" });
  expect(signup.error).toBeNull();
  const user = z.object({ user: z.object({ id: z.string(), label: z.object({ stored: z.literal("user-initial") }), readonly: z.literal("initial:bound") }).passthrough() }).parse(signup.data).user;
  for (const field of ["hidden", "omitted", "privateColumn", "private_column"]) expect(user).not.toHaveProperty(field);
  const created = await ctx.rawRequest({ path: "/__test/additional-fields/state?profile=output" }); expect(created.status).toBe(200);
  const createdState = stateSchema.parse(created.body);
  const afterHooks = createdState.events.filter(event => event.phase === "after" && z.record(z.string(), z.unknown()).parse(event.record)[event.entity === "user" ? "id" : "userId"] === user.id);
  expect(afterHooks.map(event => event.entity)).toEqual(["user", "account", "session"]);
  for (const event of afterHooks) {
    expect(event).toMatchObject({ action: "create", omittedPresent: true, omittedUndefined: true, persisted: { users: 1, accounts: 1, sessions: 1 } });
    const record = z.record(z.string(), z.unknown()).parse(event.record);
    expect(record.label).toEqual({ stored: `${event.entity}-initial` });
    expect(record.hidden).toBe(`${event.entity}-secret`.toUpperCase());
    expect(record).not.toHaveProperty("omitted");
    expect(record).not.toHaveProperty("private_column");
  }
  const session = await owner.client.getSession(); expect(session.error).toBeNull();
  const read = z.object({ user: z.record(z.string(), z.unknown()), session: z.record(z.string(), z.unknown()) }).parse(session.data);
  expect(read.user).toMatchObject({ id: user.id, label: { stored: "user-initial" }, readonly: "initial:bound" });
  expect(read.session).toMatchObject({ label: { stored: "session-initial" } });
  for (const record of [read.user, read.session]) for (const field of ["hidden", "omitted"]) expect(record).not.toHaveProperty(field);
  const update = await owner.client.updateUser({ name: "Updated output" }); expect(update.error).toBeNull();
  const updatedSession = await owner.client.getSession(); expect(updatedSession.error).toBeNull();
  expect(updatedSession.data?.user).toMatchObject({ id: user.id, name: "Updated output", label: { stored: "user-initial" }, readonly: "updated:bound" });
  const updated = await ctx.rawRequest({ path: "/__test/additional-fields/state?profile=output" }); expect(updated.status).toBe(200);
  const updatedState = stateSchema.parse(updated.body);
  expect(updatedState.users.find(row => row.id === user.id)).toMatchObject({ label: "user-initial", hidden: "user-secret", omitted: "drop", readonly: "updated:bound", private_column: "physical-private" });
  expect(updatedState.accounts.find(row => row.userId === user.id)).toMatchObject({ label: "account-initial", hidden: "account-secret", omitted: "drop" });
  expect(updatedState.sessions.find(row => row.userId === user.id)).toMatchObject({ label: "session-initial", hidden: "session-secret", omitted: "drop" });
  const updatedHook = updatedState.events.find(event => event.phase === "after" && event.entity === "user" && event.action === "update" && z.record(z.string(), z.unknown()).parse(event.record).id === user.id);
  expect(updatedHook).toMatchObject({ omittedPresent: true, omittedUndefined: true, record: { name: "Updated output", label: { stored: "user-initial" }, hidden: "USER-SECRET", readonly: "updated:bound" } });
  const rejected = ctx.actor("rejected-output", "additional-output-fields");
  const failedEmail = ctx.uniqueEmail("rejected-output");
  const rejectedInput = { email: failedEmail, name: "Rejected output", password: "Password123!", label: "throw" };
  const failedSignup = await rejected.client.signUp.email(rejectedInput);
  expect(failedSignup.error).toMatchObject({ status: 422, code: "FAILED_TO_CREATE_USER" });
  const failed = await ctx.rawRequest({ path: "/__test/additional-fields/state?profile=output" }); expect(failed.status).toBe(200);
  const failedState = stateSchema.parse(failed.body);
  expect(failedState.users.some(row => row.email === failedEmail)).toBe(false);
  for (const key of ["users", "accounts", "sessions", "verifications"] as const) expect(failedState[key]).toEqual(updatedState[key]);
  expect(failedState.events.filter(event => event.phase === "after")).toEqual(updatedState.events.filter(event => event.phase === "after"));
  expect(failedState.events.slice(updatedState.events.length)).toContainEqual({ phase: "output", entity: "user", field: "label", value: "throw" });
  for (const key of ["users", "accounts", "sessions"] as const) expect(failedState[key].filter(row => row[key === "users" ? "id" : "userId"] === foreignId)).toEqual(original[key]);
  return { foreignSignup: ctx.snapshot(foreignSignup), before: await observedState(before.body), signup: ctx.snapshot(signup), created: await observedState(created.body), session: ctx.snapshot(session), update: ctx.snapshot(update), updatedSession: ctx.snapshot(updatedSession), updated: await observedState(updated.body), failedSignup: ctx.snapshot(failedSignup), failed: await observedState(failed.body) };
}, ["POST /sign-up/email", "GET /get-session", "POST /update-user"]);

compatScenario("additional field input policies validate before awaited physical binding enforce required readonly and unknown fields and retain foreign rows on errors", async ctx => {
  const foreign = ctx.actor("policy-foreign", "additional-policy-fields");
  const foreignInput = { email: ctx.uniqueEmail("policy-foreign"), name: "Policy foreign", password: "Password123!", label: " foreign " };
  const foreignSignup = await foreign.client.signUp.email(foreignInput); expect(foreignSignup.error).toBeNull();
  const foreignId = z.object({ user: z.object({ id: z.string(), label: z.literal("bound:foreign") }) }).parse(foreignSignup.data).user.id;
  const before = await ctx.rawRequest({ path: "/__test/additional-fields/state?profile=policy" }); expect(before.status).toBe(200);
  const original = stateSchema.parse(before.body);
  const rejections: unknown[] = [];
  for (const [name, extra, code] of [
    ["missing", {}, "MISSING_FIELD"],
    ["invalid", { label: "reject" }, "VALIDATION_ERROR"],
    ["readonly", { label: "allowed", readonly: "forbidden" }, "FIELD_NOT_ALLOWED"],
    ["input-error", { label: "explode" }, "FAILED_TO_CREATE_USER"],
  ] as const) {
    const actor = ctx.actor(`policy-${name}`, "additional-policy-fields");
    const input = { email: ctx.uniqueEmail(name), name, password: "Password123!", ...extra };
    const result = await actor.client.signUp.email(input);
    expect(result.error).toMatchObject({ status: name === "input-error" ? 422 : 400, code });
    const state = await ctx.rawRequest({ path: "/__test/additional-fields/state?profile=policy" }); expect(state.status).toBe(200);
    const actual = stateSchema.parse(state.body);
    for (const key of ["users", "accounts", "sessions", "verifications"] as const) expect(actual[key]).toEqual(original[key]);
    expect(actual.events.filter(event => event.phase === "after")).toEqual(original.events.filter(event => event.phase === "after"));
    rejections.push({ result: ctx.snapshot(result), state: await observedState(state.body) });
  }
  const owner = ctx.actor("policy-owner", "additional-policy-fields");
  const injectedId = "untrusted-additional-owner-id";
  const input = { email: ctx.uniqueEmail("policy-owner"), name: "Policy owner", password: "Password123!", label: " owner ", id: injectedId, unknown: "discard-me", hidden: "overwrite-secret" };
  const signup = await owner.client.signUp.email(input); expect(signup.error).toBeNull();
  const user = z.object({ user: z.object({ id: z.string(), label: z.literal("bound:owner") }).passthrough() }).parse(signup.data).user;
  expect(user.id).not.toBe(injectedId); expect(user).not.toHaveProperty("unknown"); expect(user).not.toHaveProperty("hidden");
  const updateInput = { name: "Updated policy owner", label: " changed ", id: foreignId, unknown: "discard-again" };
  const update = await owner.client.updateUser(updateInput); expect(update.error).toBeNull();
  const forbiddenInput = { name: "Updated policy owner", hidden: "cannot-update-secret" };
  const forbidden = await owner.client.updateUser(forbiddenInput); expect(forbidden.error).toMatchObject({ status: 400, code: "FIELD_NOT_ALLOWED" });
  const read = await owner.client.getSession(); expect(read.error).toBeNull();
  expect(read.data?.user).toMatchObject({ id: user.id, name: "Updated policy owner", label: "bound:changed" });
  const after = await ctx.rawRequest({ path: "/__test/additional-fields/state?profile=policy" }); expect(after.status).toBe(200);
  const actual = stateSchema.parse(after.body);
  expect(actual.users.find(row => row.id === user.id)).toMatchObject({ label: "bound:changed", hidden: "user-secret", private_column: "physical-private" });
  for (const key of ["users", "accounts", "sessions"] as const) expect(actual[key].filter(row => row[key === "users" ? "id" : "userId"] === foreignId)).toEqual(original[key]);
  expect(actual.events.filter(event => event.phase === "validation" && event.value === " owner ")).toHaveLength(1);
  expect(actual.events.filter(event => event.phase === "input" && event.value === "owner")).toHaveLength(1);
  return { foreignSignup: ctx.snapshot(foreignSignup), before: await observedState(before.body), rejections, signup: ctx.snapshot(signup), update: ctx.snapshot(update), forbidden: ctx.snapshot(forbidden), read: ctx.snapshot(read), after: await observedState(after.body) };
}, ["POST /sign-up/email", "POST /update-user", "GET /get-session"]);

compatScenario("additional async input validation is invoked and rejected before any credential or session write while absent optional input remains usable", async ctx => {
  const foreign = ctx.actor("async-foreign", "additional-async-validation-fields");
  const foreignSignup = await foreign.client.signUp.email({ email: ctx.uniqueEmail("async-foreign"), name: "Async foreign", password: "Password123!" }); expect(foreignSignup.error).toBeNull();
  const before = await ctx.rawRequest({ path: "/__test/additional-fields/state?profile=async-validation" }); expect(before.status).toBe(200);
  const original = stateSchema.parse(before.body);
  const rejected = ctx.actor("async-rejected", "additional-async-validation-fields");
  const input = { email: ctx.uniqueEmail("async-rejected"), name: "Async rejected", password: "Password123!", label: "promise" };
  const signup = await rejected.client.signUp.email(input);
  expect(signup.error).toMatchObject({ status: 500, code: "ASYNC_VALIDATION_NOT_SUPPORTED", message: "Async validation is not supported" });
  const updateInput = { name: "Async foreign", label: "update-promise" };
  const update = await foreign.client.updateUser(updateInput);
  expect(update.error).toMatchObject({ status: 500, code: "ASYNC_VALIDATION_NOT_SUPPORTED" });
  const read = await foreign.client.getSession(); expect(read.error).toBeNull();
  const after = await ctx.rawRequest({ path: "/__test/additional-fields/state?profile=async-validation" }); expect(after.status).toBe(200);
  const actual = stateSchema.parse(after.body);
  for (const key of ["users", "accounts", "sessions", "verifications"] as const) expect(actual[key]).toEqual(original[key]);
  expect(actual.events.filter(event => event.phase === "after")).toEqual(original.events.filter(event => event.phase === "after"));
  expect(actual.events.filter(event => event.phase === "validation")).toEqual([
    { phase: "validation", entity: "user", field: "label", value: "promise" },
    { phase: "validation", entity: "user", field: "label", value: "update-promise" },
  ]);
  return { foreignSignup: ctx.snapshot(foreignSignup), before: await observedState(before.body), signup: ctx.snapshot(signup), update: ctx.snapshot(update), read: ctx.snapshot(read), after: await observedState(after.body) };
}, ["POST /sign-up/email", "POST /update-user", "GET /get-session"]);
