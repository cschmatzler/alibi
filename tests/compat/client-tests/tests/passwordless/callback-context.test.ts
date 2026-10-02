import { expect } from "bun:test";
import { z } from "zod";
import { compatScenario } from "../../support/scenario";
import { authProfilePath } from "../../support/profiles";
import { fixtureValue, readUserState, requireUser, verificationCount } from "../../support/verification";

const callback = z.object({ method: z.literal("POST"), path: z.string(), marker: z.literal("issue207"), body: z.unknown(), basePath: z.string(), proofExists: z.boolean() });

compatScenario("passwordless callbacks retain physical request and live issued proof through consumption", async (ctx) => {
  const observations = [];
  for (const kind of ["otp", "magic"] as const) {
    const profile = kind === "otp" ? "passwordless-hashed" : "magic-link-hashed";
    const path = authProfilePath(profile);
    const actor = ctx.actor(kind, profile);
    const email = ctx.uniqueEmail(`callback-${kind}`);
    const body = kind === "otp" ? { email, type: "sign-in" } : { email, metadata: { channel: "callback-probe" } };
    const endpoint = kind === "otp" ? "/email-otp/send-verification-otp" : "/sign-in/magic-link";
    const sent = await actor.fetch(new URL(`${path}${endpoint}?probe=207`, ctx.baseURL), { method: "POST", headers: { "content-type": "application/json", "x-callback-probe": "issue207" }, body: JSON.stringify(body) });
    expect(sent.status).toBe(200);
    const delivery = z.object({ otp: z.string().optional(), token: z.string().optional(), context: callback, generator: callback.omit({ proofExists: true }).optional() }).parse(await fixtureValue(ctx, kind === "otp" ? "/__test/email-otp" : "/__test/magic-link", { email, ...(kind === "otp" ? { type: "sign-in" } : {}) }));
    expect(delivery.context).toEqual({ method: "POST", path: `${path}${endpoint}`, marker: "issue207", body, basePath: path, proofExists: true });
    if (kind === "otp") expect(delivery.generator).toEqual({ method: "POST", path: `${path}${endpoint}`, marker: "issue207", body, basePath: path });
    const foreign = ctx.actor(`${kind}-foreign`, profile);
    const token = kind === "otp" ? delivery.otp! : delivery.token!;
    const consumed = kind === "otp" ? await actor.client.signIn.emailOtp({ email, otp: token }) : await actor.client.magicLink.verify({ query: { token } });
    expect(consumed.error).toBeNull();
    const user = requireUser(consumed.data?.user);
    const state = await readUserState(ctx, user.id);
    expect(state.user?.email).toBe(email);
    expect(state.accounts).toHaveLength(0);
    expect(state.sessions).toHaveLength(1);
    const replay = kind === "otp" ? await foreign.client.signIn.emailOtp({ email, otp: token }) : await foreign.client.magicLink.verify({ query: { token } });
    if (kind === "otp") expect(replay.error?.code).toBe("INVALID_OTP");
    else expect(replay.data).toBeNull();
    const after = await readUserState(ctx, user.id);
    expect(after.sessions).toHaveLength(1);
    if (kind === "otp") expect(await verificationCount(ctx, `sign-in-otp-${email}`)).toBe(0);
    observations.push({ kind, context: delivery.context, generator: delivery.generator ?? null, consumed, state, replay, after });
  }
  return observations;
});

compatScenario("phone sender verifier and completion callbacks observe actual request and consumed ownership", async (ctx) => {
  const { uniquePhone, readPhoneState } = await import("../phone-number/helpers");
  const profile = "phone-custom";
  const path = authProfilePath(profile);
  const actor = ctx.actor("phone", profile);
  const phoneNumber = uniquePhone(ctx, "context");
  async function post(endpoint: string, body: unknown) {
    const response = await actor.fetch(new URL(`${path}${endpoint}`, ctx.baseURL), { method: "POST", headers: { "content-type": "application/json", "x-callback-probe": "issue207" }, body: JSON.stringify(body) });
    return { status: response.status, body: await response.json() as unknown };
  }
  const sent = await post("/phone-number/send-otp", { phoneNumber });
  expect(sent.status).toBe(200);
  const delivery = z.object({ code: z.string(), context: callback }).parse(await fixtureValue(ctx, "/__test/phone-otp", { phoneNumber }));
  expect(delivery.context).toEqual({ method: "POST", path: `${path}/phone-number/send-otp`, marker: "issue207", body: { phoneNumber }, basePath: path, proofExists: true });
  const foreign = await post("/phone-number/verify", { phoneNumber: uniquePhone(ctx, "foreign-context"), code: delivery.code });
  expect(foreign.status).toBe(400);
  expect(await verificationCount(ctx, phoneNumber)).toBe(1);
  const consumed = await post("/phone-number/verify", { phoneNumber, code: delivery.code });
  expect(consumed.status).toBe(200);
  const user = z.object({ user: z.object({ id: z.string() }) }).parse(consumed.body).user;
  const verifier = z.object({ context: callback }).parse(await fixtureValue(ctx, "/__test/phone-otp", { phoneNumber, type: "verifier" }));
  expect(verifier.context).toEqual({ method: "POST", path: `${path}/phone-number/verify`, marker: "issue207", body: { phoneNumber, code: delivery.code }, basePath: path, proofExists: true });
  const events = z.array(z.object({ phoneNumber: z.string(), userId: z.string(), context: callback.optional(), verifiedOwner: z.boolean().optional() })).parse(await fixtureValue(ctx, "/__test/phone-callbacks", {}));
  const completed = events.find((event) => event.phoneNumber === phoneNumber)!;
  expect(completed.userId).toBe(user.id);
  expect(completed.context).toEqual({ ...verifier.context, proofExists: false });
  expect(completed.verifiedOwner).toBe(true);
  const state = await readPhoneState(ctx, profile, user.id);
  expect(state.accounts).toHaveLength(0);
  expect(state.sessions).toHaveLength(1);
  expect(state.user?.phoneNumberVerified).toBe(true);
  const replay = await post("/phone-number/verify", { phoneNumber, code: delivery.code });
  expect(replay.status).toBe(400);
  expect(await verificationCount(ctx, phoneNumber)).toBe(0);
  expect((await readPhoneState(ctx, profile, user.id)).sessions).toHaveLength(1);
  // Retain the entire captured request while binding its generated proof to
  // the comparer's existing opaque-token identity contract. The assertions
  // above independently require the exact delivered code in both callbacks.
  const capture = (context: z.infer<typeof callback>) => ({ ...context, body: { ...z.object({ phoneNumber: z.string(), code: z.string() }).parse(context.body), code: { token: z.object({ code: z.string() }).parse(context.body).code } } });
  return { sent, foreign, consumed, verifier: {context:capture(verifier.context)}, completed: {...completed, context:capture(completed.context!)}, state, replay };
});

compatScenario("email OTP override reset and current-mailbox change retain the originating request", async (ctx) => {
  const { readOtp } = await import("./helpers");
  const profile = "passwordless-proof";
  const path = authProfilePath(profile);
  const actor = ctx.actor("owner", profile);
  const email = ctx.uniqueEmail("callback-origin");
  const target = ctx.uniqueEmail("callback-target");
  const signup = await actor.client.signUp.email({ email, password: "password123", name: "Callback owner" });
  const user = requireUser(signup.data?.user);
  async function post(endpoint: string, body: unknown) {
    const response = await actor.fetch(new URL(`${path}${endpoint}`, ctx.baseURL), { method: "POST", headers: { "content-type": "application/json", "x-callback-probe": "issue207" }, body: JSON.stringify(body) });
    return { status: response.status, body: await response.json() as unknown };
  }
  async function capture(recipient: string, type: string, endpoint: string, body: unknown) {
    const delivery = z.object({ otp: z.string(), context: callback }).parse(await fixtureValue(ctx, "/__test/email-otp", { email: recipient, type }));
    expect(delivery.context).toEqual({ method: "POST", path: `${path}${endpoint}`, marker: "issue207", body, basePath: path, proofExists: true });
    return delivery;
  }
  const verification = await post("/send-verification-email", { email });
  expect(verification.status).toBe(200);
  const origin = await capture(email, "email-verification", "/send-verification-email", { email });
  const changedRequest = { newEmail: target, otp: origin.otp };
  const requestChange = await post("/email-otp/request-email-change", changedRequest);
  expect(requestChange.status).toBe(200);
  const targetDelivery = await capture(target, "change-email", "/email-otp/request-email-change", changedRequest);
  const changed = await actor.client.emailOtp.changeEmail({ newEmail: target, otp: targetDelivery.otp });
  expect(changed.error).toBeNull();
  expect(await verificationCount(ctx, `email-verification-otp-${email}`)).toBe(0);
  const reset = await post("/email-otp/request-password-reset", { email: target });
  expect(reset.status).toBe(200);
  const resetDelivery = await capture(target, "forget-password", "/email-otp/request-password-reset", { email: target });
  const resetPassword = await actor.client.emailOtp.resetPassword({ email: target, otp: await readOtp(ctx, target, "forget-password"), password: "replacement-password123" });
  expect(resetPassword.error).toBeNull();
  const state = await readUserState(ctx, user.id);
  expect(state.user?.email).toBe(target);
  expect(state.user?.emailVerified).toBe(true);
  expect(state.accounts).toHaveLength(1);
  expect(state.sessions).toHaveLength(1);
  expect(await verificationCount(ctx, `forget-password-otp-${target}`)).toBe(0);
  const changeContext = { ...targetDelivery.context, body: { ...changedRequest, otp: {token:origin.otp} } };
  return { signup, verification, origin:origin.context, requestChange, target:changeContext, changed, reset, resetContext:resetDelivery.context, resetPassword, state };
});
