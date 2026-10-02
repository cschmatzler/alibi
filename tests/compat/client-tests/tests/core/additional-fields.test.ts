import { expect } from "bun:test";
import { z } from "zod";
import { compatScenario } from "../../support/scenario";
import { authProfilePath } from "../../support/profiles";
import { getCookieCache } from "better-auth/cookies";
import { createHmac } from "node:crypto";
import { verifyPassword } from "better-auth/crypto";

async function observedCredential(account: Record<string, unknown>) {
  if (account.providerId !== "credential" || typeof account.password !== "string") return account;
  const hash = account.password;
  expect(hash).toMatch(/^[a-f0-9]{32}:[a-f0-9]{128}$/);
  const acceptsOriginal = await verifyPassword({ hash, password: "Password123!" });
  const acceptsReplacement = await verifyPassword({ hash, password: "Replacement184!" });
  expect(acceptsOriginal !== acceptsReplacement).toBe(true);
  expect(await verifyPassword({ hash, password: "wrong-password-184" })).toBe(false);
  const [salt, derivedKey] = hash.split(":");
  return { ...account, password: { token: hash, acceptsOriginal, acceptsReplacement, salt: { token: salt, length: salt!.length }, derivedKey: { token: derivedKey, length: derivedKey!.length }, encoding: "hex-lower" } };
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
  const listed=await owner.client.listAccounts(); expect(listed.error).toBeNull();
  const listedAccounts=z.array(z.object({userId:z.literal(user.id),providerId:z.literal("credential"),label:z.object({stored:z.literal("account-initial")})}).passthrough()).parse(listed.data); expect(listedAccounts).toHaveLength(1);
  for(const account of listedAccounts) for(const name of ["password","accessToken","refreshToken","idToken","accessTokenExpiresAt","refreshTokenExpiresAt","hidden","omitted","private_column"]) expect(account).not.toHaveProperty(name);
  const listedState=await ctx.rawRequest({path:"/__test/additional-fields/state?profile=output"}); expect(listedState.status).toBe(200); const listedPhysical=stateSchema.parse(listedState.body);
  for(const key of ["users","accounts","sessions","verifications"] as const) expect(listedPhysical[key]).toEqual(updatedState[key]);
  const rejected = ctx.actor("rejected-output", "additional-output-fields");
  const failedEmail = ctx.uniqueEmail("rejected-output");
  const rejectedInput = { email: failedEmail, name: "Rejected output", password: "Password123!", label: "throw" };
  const failedSignup = await rejected.client.signUp.email(rejectedInput);
  expect(failedSignup.error).toMatchObject({ status: 422, code: "FAILED_TO_CREATE_USER" });
  const failed = await ctx.rawRequest({ path: "/__test/additional-fields/state?profile=output" }); expect(failed.status).toBe(200);
  const failedState = stateSchema.parse(failed.body);
  expect(failedState.users.some(row => row.email === failedEmail)).toBe(false);
  for (const key of ["users", "accounts", "sessions", "verifications"] as const) expect(failedState[key]).toEqual(updatedState[key]);
  expect(failedState.events.filter(event => event.phase === "after")).toEqual(listedPhysical.events.filter(event => event.phase === "after"));
  expect(failedState.events.slice(listedPhysical.events.length)).toContainEqual({ phase: "output", entity: "user", field: "label", value: "throw" });
  for (const key of ["users", "accounts", "sessions"] as const) expect(failedState[key].filter(row => row[key === "users" ? "id" : "userId"] === foreignId)).toEqual(original[key]);
  return { foreignSignup: ctx.snapshot(foreignSignup), before: await observedState(before.body), signup: ctx.snapshot(signup), created: await observedState(created.body), session: ctx.snapshot(session), update: ctx.snapshot(update), updatedSession: ctx.snapshot(updatedSession), updated: await observedState(updated.body), listed:ctx.snapshot(listed),listedState:await observedState(listedState.body), failedSignup: ctx.snapshot(failedSignup), failed: await observedState(failed.body) };
}, ["POST /sign-up/email", "GET /get-session", "POST /update-user", "GET /list-accounts"],30_000);

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


compatScenario("additional cached output keeps raw creation and completed callbacks distinct from authenticated filtered cache and physical read snapshots", async ctx => {
  const foreign = ctx.actor("cached-foreign", "additional-cached-fields");
  const foreignSignup = await foreign.client.signUp.email({ email:ctx.uniqueEmail("cached-foreign"),name:"Cached foreign",password:"Password123!" }); expect(foreignSignup.error).toBeNull();
  const foreignId = z.object({user:z.object({id:z.string()})}).parse(foreignSignup.data).user.id;
  const before = await ctx.rawRequest({path:"/__test/additional-fields/state?profile=cached"}); expect(before.status).toBe(200);
  const owner = ctx.actor("cached-owner", "additional-cached-fields");
  let issuedCookies: string[] = [];
  const signup = await owner.client.signUp.email({email:ctx.uniqueEmail("cached-owner"),name:"Cached owner",password:"Password123!",fetchOptions:{onResponse({response}){ issuedCookies=response.headers.getSetCookie(); }}}); expect(signup.error).toBeNull();
  const userId = z.object({user:z.object({id:z.string()})}).parse(signup.data).user.id;
  const cacheCookie = issuedCookies.find(cookie=>cookie.startsWith("better-auth.session_data=")); expect(cacheCookie).toBeDefined();
  const pair = cacheCookie!.split(";")[0]!, token=decodeURIComponent(pair.slice(pair.indexOf("=")+1)),observedAt=Date.now();
  const envelope = JSON.parse(Buffer.from(token,"base64url").toString());
  const signature = createHmac("sha256","compat-test-only-key-not-real-minimum-32chars").update(JSON.stringify({...envelope.session,expiresAt:envelope.expiresAt})).digest("base64url");
  expect(envelope.signature).toBe(signature);
  const decoded = await getCookieCache(new Headers({cookie:pair}),{secret:"compat-test-only-key-not-real-minimum-32chars",strategy:"compact"}); expect(decoded).not.toBeNull();
  expect(decoded!.user.id).toBe(userId); expect(decoded!.session.token).toBe(z.string().parse(signup.data!.token));
  for (const output of [decoded!.user,decoded!.session]) for (const field of ["hidden","omitted","private_column"]) expect(output).not.toHaveProperty(field);
  const created = await ctx.rawRequest({path:"/__test/additional-fields/state?profile=cached"}); expect(created.status).toBe(200);
  const createdState=stateSchema.parse(created.body);
  const completed=createdState.events.findLast(event=>event.phase==="completed"&&event.path==="/sign-up/email");
  expect(completed).toMatchObject({userOmittedPresent:true,userOmittedUndefined:true,sessionOmittedPresent:true,sessionOmittedUndefined:true,record:{user:{id:userId,label:{stored:"user-initial"},hidden:"USER-SECRET"},session:{label:{stored:"session-initial"},hidden:"SESSION-SECRET"}}});
  const creationVersion=createdState.events.findLast(event=>event.phase==="version"); expect(creationVersion).toMatchObject({userOmittedPresent:true,sessionOmittedPresent:true,user:{hidden:"USER-SECRET"},session:{hidden:"SESSION-SECRET"}});
  const cached=await owner.client.getSession(); expect(cached.error).toBeNull();
  expect(cached.data?.user).toMatchObject({id:userId,label:{stored:"user-initial"}}); expect(cached.data?.session).toMatchObject({label:{stored:"session-initial"}});
  const cacheRead=await ctx.rawRequest({path:"/__test/additional-fields/state?profile=cached"}); expect(cacheRead.status).toBe(200); const cachedState=stateSchema.parse(cacheRead.body);
  expect(cachedState.events.filter(event=>event.phase==="output")).toEqual(createdState.events.filter(event=>event.phase==="output"));
  const cacheVersion=cachedState.events.findLast(event=>event.phase==="version"); expect(cacheVersion).toMatchObject({userOmittedPresent:false,sessionOmittedPresent:false,userOmittedUndefined:true,sessionOmittedUndefined:true});
  for(const output of [z.record(z.string(),z.unknown()).parse(cacheVersion?.user),z.record(z.string(),z.unknown()).parse(cacheVersion?.session)]) expect(output).not.toHaveProperty("hidden");
  const physical=await owner.client.getSession({query:{disableCookieCache:true}}); expect(physical.error).toBeNull(); expect(physical.data?.user).toMatchObject({id:userId,label:{stored:"user-initial"}});
  const after=await ctx.rawRequest({path:"/__test/additional-fields/state?profile=cached"}); expect(after.status).toBe(200); const actual=stateSchema.parse(after.body);
  const physicalVersion=actual.events.findLast(event=>event.phase==="version"); expect(physicalVersion).toMatchObject({userOmittedPresent:true,sessionOmittedPresent:true,userOmittedUndefined:true,sessionOmittedUndefined:true});
  for(const output of [z.record(z.string(),z.unknown()).parse(physicalVersion?.user),z.record(z.string(),z.unknown()).parse(physicalVersion?.session)]) expect(output).not.toHaveProperty("hidden");
  expect(actual.events.filter(event=>event.phase==="output").length).toBeGreaterThan(cachedState.events.filter(event=>event.phase==="output").length);
  expect(actual.events.filter(event=>event.phase==="completed"&&event.path==="/get-session").map(event=>event.record)).toEqual([null,null]);
  const original=stateSchema.parse(before.body);
  for(const key of ["users","accounts","sessions"] as const) expect(actual[key].filter(row=>row[key==="users"?"id":"userId"]===foreignId)).toEqual(original[key]);
  for(const key of ["users","accounts","sessions","verifications"] as const) expect(actual[key]).toEqual(createdState[key]);
  const rejected=await owner.client.changePassword({currentPassword:"wrong-password-184",newPassword:"Replacement184!",revokeOtherSessions:true}); expect(rejected.error).toMatchObject({status:400,code:"INVALID_PASSWORD"});
  const denied=await ctx.rawRequest({path:"/__test/additional-fields/state?profile=cached"}); expect(denied.status).toBe(200); const deniedState=stateSchema.parse(denied.body);
  for(const key of ["users","accounts","sessions","verifications"] as const) expect(deniedState[key]).toEqual(actual[key]);
  const replacement=await owner.client.changePassword({currentPassword:"Password123!",newPassword:"Replacement184!",revokeOtherSessions:true}); expect(replacement.error).toBeNull();
  const replacementData=z.object({token:z.string(),user:z.object({id:z.literal(userId),label:z.object({stored:z.literal("user-initial")})}).passthrough()}).parse(replacement.data); expect(replacementData.token).not.toBe(decoded!.session.token); expect(replacementData.user).not.toHaveProperty("hidden");
  const replaced=await ctx.rawRequest({path:"/__test/additional-fields/state?profile=cached"}); expect(replaced.status).toBe(200); const replacedState=stateSchema.parse(replaced.body);
  const credential=replacedState.accounts.find(row=>row.userId===userId&&row.providerId==="credential")!; expect(await verifyPassword({hash:z.string().parse(credential.password),password:"Replacement184!"})).toBe(true); expect(await verifyPassword({hash:z.string().parse(credential.password),password:"Password123!"})).toBe(false);
  expect(replacedState.sessions.filter(row=>row.userId===userId).map(row=>row.token)).toEqual([replacementData.token]);
  const replacedVersion=replacedState.events.findLast(event=>event.phase==="version"); expect(replacedVersion?.user).not.toHaveProperty("hidden"); expect(replacedVersion?.session).toMatchObject({hidden:"SESSION-SECRET"});
  const replacedCompleted=replacedState.events.findLast(event=>event.phase==="completed"&&event.path==="/change-password"); expect(replacedCompleted).toMatchObject({userOmittedPresent:true,userOmittedUndefined:true,sessionOmittedPresent:true,sessionOmittedUndefined:true});
  const completedRecord=z.object({user:z.record(z.string(),z.unknown()),session:z.record(z.string(),z.unknown())}).parse(replacedCompleted?.record); expect(completedRecord.user).not.toHaveProperty("hidden"); expect(completedRecord.session).toMatchObject({token:replacementData.token,hidden:"SESSION-SECRET"});
  const revoked=await ctx.rawRequest({path:"/__test/profiles/additional-cached-fields/api/auth/get-session?disableCookieCache=true",headers:{cookie:issuedCookies.find(cookie=>cookie.startsWith("better-auth.session_token="))!.split(";")[0]!}}); expect(revoked.status).toBe(200); expect(revoked.body).toBeNull();
  const signedIn=ctx.actor("cache-replacement-signin","additional-cached-fields"); const signIn=await signedIn.client.signIn.email({email:z.string().parse(signup.data?.user.email),password:"Replacement184!"}); expect(signIn.error).toBeNull(); expect(signIn.data?.user).toMatchObject({id:userId,label:{stored:"user-initial"}});
  const final=await ctx.rawRequest({path:"/__test/additional-fields/state?profile=cached"}); expect(final.status).toBe(200); const finalState=stateSchema.parse(final.body);
  const signInVersion=finalState.events.findLast(event=>event.phase==="version"); expect(signInVersion?.user).toMatchObject({hidden:"USER-SECRET"}); expect(signInVersion?.session).toMatchObject({hidden:"SESSION-SECRET"});
  for(const key of ["users","accounts","sessions"] as const) expect(finalState[key].filter(row=>row[key==="users"?"id":"userId"]===foreignId)).toEqual(original[key]);
  const signInToken=z.string().parse(signIn.data?.token),rewindInput={token:signInToken,expiresAt:new Date(Date.now()+3_600_000).toISOString()};
  const rewind=await ctx.rawRequest({path:"/__test/additional-fields/rewind-session?profile=cached",method:"POST",json:rewindInput}); expect(rewind.status).toBe(200);
  const rewound=stateSchema.parse(rewind.body); expect(rewound.sessions.find(row=>row.token===signInToken)?.expiresAt).toBe(rewindInput.expiresAt);
  const refreshed=await signedIn.client.getSession({query:{disableCookieCache:true}}); expect(refreshed.error).toBeNull(); expect(refreshed.data?.session).toMatchObject({token:signInToken,label:{stored:"session-updated"}}); expect(refreshed.data?.user).toMatchObject({id:userId,label:{stored:"user-initial"}});
  const refreshState=await ctx.rawRequest({path:"/__test/additional-fields/state?profile=cached"}); expect(refreshState.status).toBe(200); const refreshedState=stateSchema.parse(refreshState.body);
  expect(refreshedState.sessions.find(row=>row.token===signInToken)).toMatchObject({label:"session-updated",hidden:"session-secret",omitted:"drop"});
  expect(refreshedState.events.filter(event=>event.phase==="on-update")).toEqual([{phase:"on-update",entity:"session",field:"label"}]);
  const refreshedVersion=refreshedState.events.findLast(event=>event.phase==="version"); expect(refreshedVersion?.user).not.toHaveProperty("hidden"); expect(refreshedVersion?.session).toMatchObject({label:{stored:"session-updated"},hidden:"SESSION-SECRET"});
  const refreshedCompleted=refreshedState.events.findLast(event=>event.phase==="completed"&&event.path==="/get-session"); expect(refreshedCompleted).toMatchObject({userOmittedPresent:true,sessionOmittedPresent:true,record:{user:{id:userId},session:{token:signInToken,label:{stored:"session-updated"},hidden:"SESSION-SECRET"}}});
  for(const key of ["users","accounts","sessions"] as const) expect(refreshedState[key].filter(row=>row[key==="users"?"id":"userId"]===foreignId)).toEqual(original[key]);
  return {foreignSignup:ctx.snapshot(foreignSignup),before:await observedState(before.body),signup:ctx.snapshot(signup),signed:{compactSessionCache:{token,envelope,decoded,observedAt,effectiveMaxAgeSeconds:300,rawCookies:[cacheCookie]}},created:await observedState(created.body),cached:ctx.snapshot(cached),cacheRead:await observedState(cacheRead.body),physical:ctx.snapshot(physical),after:await observedState(after.body),rejected:ctx.snapshot(rejected),denied:await observedState(denied.body),replacement:ctx.snapshot(replacement),replaced:await observedState(replaced.body),revoked:ctx.snapshot(revoked),signIn:ctx.snapshot(signIn),final:await observedState(final.body),rewind:await observedState(rewind.body),refreshed:ctx.snapshot(refreshed),refreshState:await observedState(refreshState.body)};
},["POST /sign-up/email","GET /get-session","POST /change-password","POST /sign-in/email"],30_000);


compatScenario("additional plugin input and public policy retain distinct configured adapter precedence and canonical plugin columns",async ctx=>{
  const foreign=ctx.actor("plugin-foreign","additional-plugin-fields"),owner=ctx.actor("plugin-owner","additional-plugin-fields");
  const foreignSignup=await foreign.client.signUp.email({email:ctx.uniqueEmail("plugin-foreign"),name:"Plugin foreign",password:"Password123!"}); expect(foreignSignup.error).toBeNull();
  const foreignId=z.object({user:z.object({id:z.string()})}).parse(foreignSignup.data).user.id;
  const before=await ctx.rawRequest({path:"/__test/additional-fields/state?profile=plugin"}); expect(before.status).toBe(200); const original=stateSchema.parse(before.body);
  const input={email:ctx.uniqueEmail("plugin-owner"),name:"Plugin owner",password:"Password123!",role:"untrusted-overwrite"};
  const signup=await owner.client.signUp.email(input); expect(signup.error).toBeNull();
  const user=z.object({user:z.object({id:z.string(),role:z.literal("observed:plugin-role")}).passthrough()}).parse(signup.data).user; expect(user).not.toHaveProperty("label");
  const read=await owner.client.getSession(); expect(read.error).toBeNull(); expect(read.data?.user).toMatchObject({id:user.id,role:"observed:plugin-role"}); expect(read.data?.user).not.toHaveProperty("label"); expect(read.data?.session).not.toHaveProperty("label");
  const rejectedInput={name:"Plugin owner",role:"cannot-update-role"}; const rejected=await owner.client.updateUser(rejectedInput); expect(rejected.error).toMatchObject({status:400,code:"FIELD_NOT_ALLOWED"});
  const after=await ctx.rawRequest({path:"/__test/additional-fields/state?profile=plugin"}); expect(after.status).toBe(200); const actual=stateSchema.parse(after.body);
  expect(actual.users.find(row=>row.id===user.id)).toMatchObject({label:"plugin-user",role:"plugin-role"}); expect(actual.sessions.find(row=>row.userId===user.id)).toMatchObject({label:"plugin-session"}); expect(actual.accounts.find(row=>row.userId===user.id)).toMatchObject({label:"account-initial"});
  const hooks=actual.events.filter(event=>event.phase==="after"&&z.record(z.string(),z.unknown()).parse(event.record)[event.entity==="user"?"id":"userId"]===user.id);
  for(const hook of hooks) expect(hook.record).toMatchObject({label:{configured:hook.entity==="account"?"account-initial":`plugin-${hook.entity}`}});
  expect(hooks.find(hook=>hook.entity==="user")?.record).toMatchObject({role:"observed:plugin-role"});
  for(const key of ["users","accounts","sessions"] as const) expect(actual[key].filter(row=>row[key==="users"?"id":"userId"]===foreignId)).toEqual(original[key]);
  return {foreignSignup:ctx.snapshot(foreignSignup),before:await observedState(before.body),signup:ctx.snapshot(signup),read:ctx.snapshot(read),rejected:ctx.snapshot(rejected),after:await observedState(after.body)};
},["POST /sign-up/email","GET /get-session","POST /update-user"]);

compatScenario("additional field documentation preserves logical model policies and callable defaults without executing adapter callbacks or revealing physical columns", async ctx => {
  const observations=[];
  for(const mode of ["normal","output","policy","async-validation","cached","plugin"] as const) {
    const profile=mode==="normal" ? "additional-fields" : `additional-${mode}-fields` as const;
    const actor=ctx.actor(`docs-${mode}`,profile);
    const before=await ctx.rawRequest({path:`/__test/additional-fields/state?profile=${mode}`}); expect(before.status).toBe(200);
    const response=await actor.client.$fetch("/open-api/generate-schema",{method:"GET"}); expect(response.error).toBeNull();
    const document=z.object({components:z.object({schemas:z.record(z.string(),z.object({properties:z.record(z.string(),z.unknown()),required:z.array(z.string())}))}),paths:z.record(z.string(),z.unknown())}).passthrough().parse(response.data);
    for(const entity of ["User","Session","Account"] as const) {
      const model=document.components.schemas[entity]!;
      expect(model.properties).toHaveProperty("label.type","string"); expect(model.properties).toHaveProperty("hidden.type","string");
      for(const physical of ["private_column","display_name","user_label"]) expect(model.properties).not.toHaveProperty(physical);
      expect(model.required).not.toContain("hidden");
      if(mode==="normal") {expect(model.properties.label).not.toHaveProperty("default");expect(model.required).toContain("label");}
      if(mode==="plugin") expect(model.properties.label).toEqual({type:"string",default:`${entity.toLowerCase()}-initial`});
    }
    const writable=z.object({post:z.object({requestBody:z.object({content:z.object({"application/json":z.object({schema:z.object({properties:z.record(z.string(),z.unknown()),required:z.array(z.string()).optional()})})})})})}).parse(document.paths["/sign-up/email"]).post.requestBody.content["application/json"].schema;
    if(mode==="normal") expect(writable.required??[]).not.toContain("label");
    if(mode==="policy") {expect(writable.required).toContain("label");expect(writable.properties).not.toHaveProperty("readonly");expect(writable.properties).not.toHaveProperty("hidden");}
    if(mode==="output"||mode==="cached") expect(writable.properties).not.toHaveProperty("readonly");
    if(mode==="plugin") {expect(writable.properties.label).toEqual({type:"string",default:"plugin-user"});expect(writable.properties).not.toHaveProperty("role");expect(document.components.schemas.User!.properties.role).toEqual({type:"string",default:"plugin-role",readOnly:true});}
    const after=await ctx.rawRequest({path:`/__test/additional-fields/state?profile=${mode}`}); expect(after.status).toBe(200);
    const original=stateSchema.parse(before.body),actual=stateSchema.parse(after.body);
    for(const key of ["users","accounts","sessions","verifications"] as const) expect(actual[key]).toEqual(original[key]);
    expect(actual.events.filter(event=>event.phase!=="completed")).toEqual(original.events.filter(event=>event.phase!=="completed"));
    expect(actual.events.filter(event=>event.phase==="completed")).toEqual(mode==="cached" ? [{phase:"completed",path:"/open-api/generate-schema",record:null,userOmittedPresent:null,userOmittedUndefined:null,sessionOmittedPresent:null,sessionOmittedUndefined:null}] : []);
    observations.push({mode,document:ctx.snapshot(response),before:await observedState(before.body),after:await observedState(after.body)});
  }
  return observations;
},["GET /open-api/generate-schema"]);

compatScenario("additional mapped provider fields retain public profile id independently from physical account authority and declared user create update policy", async ctx => {
  const foreign=ctx.actor("mapped-foreign","additional-provider-fields");
  const foreignSignup=await foreign.client.signUp.email({email:ctx.uniqueEmail("mapped-foreign"),name:"Foreign mapped fields",password:"Password123!"});expect(foreignSignup.error).toBeNull();
  const foreignId=z.object({user:z.object({id:z.string()})}).parse(foreignSignup.data).user.id;
  const before=await ctx.rawRequest({path:"/__test/additional-fields/state?profile=provider"});expect(before.status).toBe(200);
  const original={account_id:ctx.uniqueToken("mapped-subject"),name:"Provider fields",email:ctx.uniqueEmail("mapped-owner"),picture:"https://images.example.invalid/additional-fields.png",nickname:"from-provider-184",original:{preserved:true}};
  expect((await ctx.rawRequest({path:"/__test/atlassian/control",method:"POST",json:{profile:original}})).status).toBe(200);
  const owner=ctx.actor("mapped-owner","additional-provider-fields");
  const start=await owner.client.signIn.social({provider:"atlassian",callbackURL:"/dashboard"});expect(start.error).toBeNull();
  const url=new URL(start.data!.url!),path=authProfilePath("additional-provider-fields")+`/callback/atlassian?code=fixture-code&state=${encodeURIComponent(url.searchParams.get("state")!)}`;
  const response=await owner.fetch(ctx.baseURL+path,{redirect:"manual"});expect(response.status).toBe(302);expect(response.headers.get("location")).toBe("/dashboard");
  const created=await ctx.rawRequest({path:"/__test/additional-fields/state?profile=provider"});expect(created.status).toBe(200);const createdState=stateSchema.parse(created.body);
  const account=createdState.accounts.find(row=>row.providerId==="atlassian")!;expect(account).toMatchObject({accountId:original.account_id,providerId:"atlassian"});
  expect(account.userId).not.toBe("mapped-public-id-184");
  const info=await owner.client.$fetch("/account-info",{method:"GET",query:{accountId:account.id}});expect(info.error).toBeNull();
  expect(info.data).toMatchObject({user:{id:"mapped-public-id-184",label:original.nickname,hidden:"provider-cannot-set-hidden",unknown:"provider-unknown"},data:original,account:{id:account.id,accountId:original.account_id,providerId:"atlassian"}});
  const session=await owner.client.getSession();expect(session.error).toBeNull();expect(session.data?.user).toMatchObject({id:account.userId,label:{stored:original.nickname},name:"Mapped Provider fields"});
  for(const name of ["hidden","unknown","private_column"]) expect(session.data?.user).not.toHaveProperty(name);
  const after=await ctx.rawRequest({path:"/__test/additional-fields/state?profile=provider"});expect(after.status).toBe(200);const actual=stateSchema.parse(after.body);
  expect(actual.users.find(row=>row.id===account.userId)).toMatchObject({label:original.nickname,hidden:"user-secret"});
  const initial=stateSchema.parse(before.body);for(const key of ["users","accounts","sessions"] as const) expect(actual[key].filter(row=>row[key==="users"?"id":"userId"]===foreignId)).toEqual(initial[key]);
  const denied=await foreign.client.$fetch("/account-info",{method:"GET",query:{accountId:account.id}});expect(denied.error).not.toBeNull();
  const replay=await owner.fetch(ctx.baseURL+path,{redirect:"manual"});expect(replay.status).toBe(302);expect(new URL(replay.headers.get("location")!,ctx.baseURL).searchParams.get("error")).toBe("state_mismatch");
  const afterDenial=await ctx.rawRequest({path:"/__test/additional-fields/state?profile=provider"});expect(afterDenial.status).toBe(200);const deniedState=stateSchema.parse(afterDenial.body);for(const key of ["users","accounts","sessions","verifications"] as const) expect(deniedState[key]).toEqual(actual[key]);expect(deniedState.mapperReceipts).toEqual(actual.mapperReceipts);
  const changed={...original,name:"Provider updated",nickname:"updated-provider-184"};
  expect((await ctx.rawRequest({path:"/__test/atlassian/control",method:"POST",json:{profile:changed}})).status).toBe(200);
  const updateStart=await owner.client.signIn.social({provider:"atlassian",callbackURL:"/updated"});expect(updateStart.error).toBeNull();
  const updateUrl=new URL(updateStart.data!.url!);
  const updateCallback=await owner.fetch(ctx.baseURL+authProfilePath("additional-provider-fields")+`/callback/atlassian?code=fixture-code&state=${encodeURIComponent(updateUrl.searchParams.get("state")!)}`,{redirect:"manual"});expect(updateCallback.status).toBe(302);expect(updateCallback.headers.get("location")).toBe("/updated");
  const updateSession=await owner.client.getSession();expect(updateSession.error).toBeNull();expect(updateSession.data?.user).toMatchObject({id:account.userId,name:"Mapped Provider updated",label:{stored:changed.nickname},readonly:"updated:bound"});
  for(const name of ["hidden","unknown","private_column"]) expect(updateSession.data?.user).not.toHaveProperty(name);
  const updated=await ctx.rawRequest({path:"/__test/additional-fields/state?profile=provider"});expect(updated.status).toBe(200);const updatedState=stateSchema.parse(updated.body);
  expect(updatedState.users.find(row=>row.id===account.userId)).toMatchObject({label:changed.nickname,name:"Mapped Provider updated",hidden:"user-secret",readonly:"updated:bound"});
  expect(updatedState.accounts.filter(row=>row.userId===account.userId)).toHaveLength(1);expect(updatedState.accounts.find(row=>row.userId===account.userId)).toMatchObject({id:account.id,accountId:original.account_id});
  expect(updatedState.users.filter(row=>row.id===account.userId)).toHaveLength(1);expect(updatedState.sessions.filter(row=>row.userId===account.userId)).toHaveLength(2);
  for(const key of ["users","accounts","sessions"] as const) expect(updatedState[key].filter(row=>row[key==="users"?"id":"userId"]===foreignId)).toEqual(initial[key]);
  expect(updatedState.mapperReceipts).toEqual([original,original,changed]);
  const receipts=await ctx.rawRequest({path:"/__test/atlassian/receipts"});expect(receipts.status).toBe(200);const exchanges=z.array(z.object({path:z.string(),body:z.record(z.string(),z.string()).nullable()}).passthrough()).parse(receipts.body);
  for(const [index,authorization] of [[0,url],[3,updateUrl]] as const) {const verifier=exchanges[index]!.body!.code_verifier!;expect(authorization.searchParams.get("code_challenge")).toBe(Buffer.from(await crypto.subtle.digest("SHA-256",new TextEncoder().encode(verifier))).toString("base64url"));}
  expect(exchanges.map(row=>row.path)).toEqual(["/token","/me","/me","/token","/me"]);
  return {foreignSignup:ctx.snapshot(foreignSignup),before:await observedState(before.body),start:ctx.snapshot(start),callback:{status:response.status,location:response.headers.get("location")},created:await observedState(created.body),info:ctx.snapshot(info),session:ctx.snapshot(session),after:await observedState(after.body),denied:ctx.snapshot(denied),replay:{status:replay.status,location:replay.headers.get("location")},afterDenial:await observedState(afterDenial.body),updateStart:ctx.snapshot(updateStart),updateCallback:{status:updateCallback.status,location:updateCallback.headers.get("location")},updateSession:ctx.snapshot(updateSession),updated:await observedState(updated.body),receipts:exchanges.map(row=>({...row,body:row.body?.code_verifier?{...row.body,code_verifier:{token:row.body.code_verifier,length:row.body.code_verifier.length}}:row.body}))};
},["POST /sign-in/social","GET /callback/{}","GET /account-info","GET /get-session"],30_000);
