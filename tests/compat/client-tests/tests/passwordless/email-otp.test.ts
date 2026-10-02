import { expect } from "bun:test";
import { createHmac } from "node:crypto";
import { Cookie } from "tough-cookie";
import { z } from "zod";
import { expireVerification, readUserState, requireUser, verificationCount } from "../../support/verification";
import { compatScenario } from "../../support/scenario";
import { passwordlessClient, readOtp } from "./helpers";
import { authProfilePath, type FixtureProfile } from "../../support/profiles";

compatScenario("email OTP signs up a verified user and consumes its scoped code once", async (ctx) => {
  const client = passwordlessClient(ctx);
  const email = ctx.uniqueEmail("otp-signup");
  const send = await client.emailOtp.sendVerificationOtp({ email, type: "sign-in" });
  expect(send.error).toBeNull();
  const otp = await readOtp(ctx, email, "sign-in");
  expect(await verificationCount(ctx, `sign-in-otp-${email}`)).toBe(1);
  const signIn = await client.signIn.emailOtp({ email: email.toUpperCase(), otp, name: "OTP Owner" });
  expect(signIn.error).toBeNull();
  const user = requireUser(signIn.data?.user);
  expect(user.emailVerified).toBe(true);
  const session = await client.getSession();
  expect(session.data?.user.id).toBe(user.id);
  const state = await readUserState(ctx, user.id);
  expect(state.sessions).toHaveLength(1);
  expect(state.sessions.at(0)?.userId).toBe(user.id);
  const replay = await client.signIn.emailOtp({ email, otp });
  expect(replay.error?.code).toBe("INVALID_OTP");
  expect(await verificationCount(ctx, `sign-in-otp-${email}`)).toBe(0);
  return { send: ctx.snapshot(send), signIn: ctx.snapshot(signIn), session: ctx.snapshot(session), replay: ctx.snapshot(replay), state: ctx.snapshot(state) };
}, ["POST /email-otp/send-verification-otp", "POST /sign-in/email-otp"]);

compatScenario("email OTP session cookies respect signed empty and nonempty browser preferences", async (ctx) => {
  const observations = [];
  for (const [index, preference] of [undefined, "", "false", "true"].entries()) {
    const client = passwordlessClient(ctx, `preference-${index}`);
    const email = ctx.uniqueEmail(`otp-preference-${index}`);
    const issued = await client.emailOtp.sendVerificationOtp({ email, type: "sign-in" });
    expect(issued.error).toBeNull();
    const otp = await readOtp(ctx, email, "sign-in");
    const secret = ["compat", "test", "only", "key", "not", "real", "minimum", "32chars"].join("-");
    const cookie = preference === undefined ? undefined : `better-auth.dont_remember=${encodeURIComponent(`${preference}.${createHmac("sha256", secret).update(preference).digest("base64")}`)}`;
    const responseCookies: string[] = [];
    const signedIn = await client.signIn.emailOtp({
      email, otp,
      fetchOptions: {
        ...(cookie ? { headers: { cookie } } : {}),
        onSuccess({ response }: { response: Response }) { responseCookies.push(...response.headers.getSetCookie()); },
      },
    });
    expect(signedIn.error).toBeNull();
    const user = requireUser(signedIn.data?.user);
    const state = await readUserState(ctx, user.id);
    expect(state.sessions).toHaveLength(1);
    expect(state.sessions.at(0)?.token).toBe(signedIn.data?.token);
    const expiry = z.string().parse(state.sessions.at(0)?.expiresAt);
    expect(Date.parse(expiry) - Date.now()).toBeGreaterThan(604_795_000);
    expect(Date.parse(expiry) - Date.now()).toBeLessThanOrEqual(604_801_000);
    const cookies = responseCookies.map(value => {
      const parsed = Cookie.parse(value);
      if (!parsed) throw new Error("Authentication must emit valid session cookies");
      return parsed;
    });
    const sessionCookie = cookies.find(value => value.key === "better-auth.session_token");
    if (!sessionCookie) throw new Error("Successful OTP sign-in must issue its session cookie");
    const persistent = preference === undefined || preference === "";
    expect(sessionCookie.httpOnly).toBe(true);
    expect(sessionCookie.path).toBe("/");
    expect(sessionCookie.maxAge).toBe(persistent ? 604_800 : null);
    expect(cookies.some(value => value.key === "better-auth.dont_remember")).toBe(!persistent);
    const current = await client.getSession();
    expect(current.data?.user.id).toBe(user.id);
    expect(current.data?.session.token).toBe(signedIn.data?.token);
    const replay = await client.signIn.emailOtp({ email, otp });
    expect(replay.error?.code).toBe("INVALID_OTP");
    expect(await verificationCount(ctx, `sign-in-otp-${email}`)).toBe(0);
    observations.push({ preference: preference ?? null, signedIn, state, current, replay });
  }
  return ctx.snapshot(observations);
}, ["POST /sign-in/email-otp"]);

compatScenario("email OTP check preserves the code until email verification consumes it", async (ctx) => {
  const client = passwordlessClient(ctx);
  const email = ctx.uniqueEmail("otp-verify");
  const signup = await client.signUp.email({ email, password: "password123", name: "Unverified Owner" });
  const user = requireUser(signup.data?.user);
  const send = await client.emailOtp.sendVerificationOtp({ email, type: "email-verification" });
  const otp = await readOtp(ctx, email, "email-verification");
  const check = await client.emailOtp.checkVerificationOtp({ email, type: "email-verification", otp });
  expect(check.error).toBeNull();
  const wrongCheck = await client.emailOtp.checkVerificationOtp({ email, type: "email-verification", otp: "incorrect" });
  expect(wrongCheck.error?.code).toBe("INVALID_OTP");
  const before = await readUserState(ctx, user.id);
  expect(before.user?.emailVerified).toBe(false);
  expect(await verificationCount(ctx, `email-verification-otp-${email}`)).toBe(1);
  const verify = await client.emailOtp.verifyEmail({ email, otp });
  expect(verify.error).toBeNull();
  expect(verify.data?.token).toBeNull();
  const state = await readUserState(ctx, user.id);
  expect(state.user?.emailVerified).toBe(true);
  const replay = await client.emailOtp.verifyEmail({ email, otp });
  expect(replay.error?.code).toBe("INVALID_OTP");
  expect(await verificationCount(ctx, `email-verification-otp-${email}`)).toBe(0);
  return { send: ctx.snapshot(send), check: ctx.snapshot(check), wrongCheck: ctx.snapshot(wrongCheck), verify: ctx.snapshot(verify), replay: ctx.snapshot(replay), state: ctx.snapshot(state) };
}, ["POST /email-otp/check-verification-otp", "POST /email-otp/verify-email"]);

compatScenario("email OTP rejects wrong mailbox scope exhausted attempts and expiry", async (ctx) => {
  const client = passwordlessClient(ctx);
  const email = ctx.uniqueEmail("otp-reject");
  await client.emailOtp.sendVerificationOtp({ email, type: "sign-in" });
  const otp = await readOtp(ctx, email, "sign-in");
  const wrongEmail = await client.signIn.emailOtp({ email: ctx.uniqueEmail("foreign"), otp });
  const wrongScope = await client.emailOtp.verifyEmail({ email, otp });
  expect(wrongEmail.error?.code).toBe("INVALID_OTP");
  expect(wrongScope.error?.code).toBe("INVALID_OTP");
  const attempts = [];
  for (let i = 0; i < 3; i += 1) {
    const attempt = await client.signIn.emailOtp({ email, otp: "incorrect" });
    expect(attempt.error?.code).toBe("INVALID_OTP");
    attempts.push(ctx.snapshot(attempt));
  }
  const exhausted = await client.signIn.emailOtp({ email, otp });
  expect(exhausted.error?.code).toBe("TOO_MANY_ATTEMPTS");
  expect(await verificationCount(ctx, `sign-in-otp-${email}`)).toBe(0);
  await client.emailOtp.sendVerificationOtp({ email, type: "sign-in" });
  const fresh = await readOtp(ctx, email, "sign-in");
  await expireVerification(ctx, `sign-in-otp-${email}`);
  const expired = await client.signIn.emailOtp({ email, otp: fresh });
  expect(expired.error?.code).toBe("OTP_EXPIRED");
  expect(await verificationCount(ctx, `sign-in-otp-${email}`)).toBe(0);
  return { wrongEmail: ctx.snapshot(wrongEmail), wrongScope: ctx.snapshot(wrongScope), attempts, exhausted: ctx.snapshot(exhausted), expired: ctx.snapshot(expired) };
}, ["POST /sign-in/email-otp"]);

compatScenario("email OTP password reset and deprecated request alias update credentials and verification", async (ctx) => {
  const client = passwordlessClient(ctx);
  const email = ctx.uniqueEmail("otp-password");
  const signup = await client.signUp.email({ email, password: "old-password123", name: "Password Owner" });
  const user = requireUser(signup.data?.user);
  const request = await client.emailOtp.requestPasswordReset({ email });
  expect(request.error).toBeNull();
  const requestAlias = await client.forgetPassword.emailOtp({ email });
  expect(requestAlias.error).toBeNull();
  const otp = await readOtp(ctx, email, "forget-password");
  const invalidPassword = await client.emailOtp.resetPassword({ email, otp, password: "short" });
  expect(invalidPassword.error?.status).toBe(400);
  const reset = await client.emailOtp.resetPassword({ email, otp, password: "new-password123" });
  expect(reset.error).toBeNull();
  const state = await readUserState(ctx, user.id);
  expect(state.user?.emailVerified).toBe(true);
  expect(state.accounts.filter(account => account.providerId === "credential")).toHaveLength(1);
  const replay = await client.emailOtp.resetPassword({ email, otp, password: "replay-password123" });
  expect(replay.error?.code).toBe("INVALID_OTP");
  await client.signOut();
  const oldPassword = await client.signIn.email({ email, password: "old-password123" });
  expect(oldPassword.error).not.toBeNull();
  const newPassword = await client.signIn.email({ email, password: "new-password123" });
  expect(newPassword.error).toBeNull();
  return { request: ctx.snapshot(request), requestAlias: ctx.snapshot(requestAlias), invalidPassword: ctx.snapshot(invalidPassword), reset: ctx.snapshot(reset), replay: ctx.snapshot(replay), oldPassword: ctx.snapshot(oldPassword), newPassword: ctx.snapshot(newPassword), state: ctx.snapshot(state) };
}, ["POST /email-otp/request-password-reset", "POST /forget-password/email-otp", "POST /email-otp/reset-password"]);

compatScenario("email OTP email change binds the requesting user and preserves its session identity", async (ctx) => {
  const owner = passwordlessClient(ctx);
  const foreign = passwordlessClient(ctx, "foreign");
  const email = ctx.uniqueEmail("otp-change-owner");
  const target = ctx.uniqueEmail("otp-change-target");
  const signup = await owner.signUp.email({ email, password: "password123", name: "Owner" });
  const user = requireUser(signup.data?.user);
  await foreign.signUp.email({ email: ctx.uniqueEmail("otp-change-foreign"), password: "password123", name: "Foreign" });
  const initial = await owner.getSession();
  const request = await owner.emailOtp.requestEmailChange({ newEmail: target });
  expect(request.error).toBeNull();
  const otp = await readOtp(ctx, target, "change-email");
  const foreignChange = await foreign.emailOtp.changeEmail({ newEmail: target, otp });
  expect(foreignChange.error?.code).toBe("INVALID_OTP");
  const guestChange = await passwordlessClient(ctx, "visitor").emailOtp.changeEmail({ newEmail: target, otp });
  expect(guestChange.error?.status).toBe(401);
  expect(await verificationCount(ctx, `change-email-otp-${email}-${target}`)).toBe(1);
  const change = await owner.emailOtp.changeEmail({ newEmail: target, otp });
  expect(change.error).toBeNull();
  const session = await owner.getSession();
  expect(session.data?.session.id).toBe(initial.data?.session.id);
  expect(session.data?.user.email).toBe(target);
  const state = await readUserState(ctx, user.id);
  expect(state.user?.email).toBe(target);
  expect(state.user?.emailVerified).toBe(true);
  const replay = await owner.emailOtp.changeEmail({ newEmail: target, otp });
  expect(replay.error?.message).toBe("Email is the same");
  expect(await verificationCount(ctx, `change-email-otp-${email}-${target}`)).toBe(0);
  const unauthorized = await passwordlessClient(ctx, "visitor").emailOtp.requestEmailChange({ newEmail: target });
  expect(unauthorized.error?.status).toBe(401);
  return { initial: ctx.snapshot(initial), request: ctx.snapshot(request), foreignChange: ctx.snapshot(foreignChange), guestChange: ctx.snapshot(guestChange), change: ctx.snapshot(change), session: ctx.snapshot(session), replay: ctx.snapshot(replay), unauthorized: ctx.snapshot(unauthorized), state: ctx.snapshot(state) };
}, ["POST /email-otp/request-email-change", "POST /email-otp/change-email"]);

compatScenario("email OTP proof revokes unverified credentials linked accounts and previous sessions", async (ctx) => {
  const oldClient = passwordlessClient(ctx, "previous");
  const owner = passwordlessClient(ctx);
  const email = ctx.uniqueEmail("otp-promote");
  const signup = await oldClient.signUp.email({ email, password: "unproven-password123", name: "Unproven" });
  const user = requireUser(signup.data?.user);
  await ctx.seedOAuthAccount({ email, providerId: "google", accountId: "unproven-google-id" });
  const before = await readUserState(ctx, user.id);
  expect(before.accounts).toHaveLength(2);
  await owner.emailOtp.sendVerificationOtp({ email, type: "sign-in" });
  const otp = await readOtp(ctx, email, "sign-in");
  const proof = await owner.signIn.emailOtp({ email, otp });
  expect(proof.error).toBeNull();
  expect(proof.data?.user.id).toBe(user.id);
  const oldSession = await oldClient.getSession();
  expect(oldSession.data).toBeNull();
  const state = await readUserState(ctx, user.id);
  expect(state.accounts).toHaveLength(0);
  expect(state.sessions).toHaveLength(1);
  expect(state.user?.emailVerified).toBe(true);
  const unprovenPassword = await oldClient.signIn.email({ email, password: "unproven-password123" });
  expect(unprovenPassword.error).not.toBeNull();
  return { before: ctx.snapshot(before), proof: ctx.snapshot(proof), oldSession: ctx.snapshot(oldSession), unprovenPassword: ctx.snapshot(unprovenPassword), state: ctx.snapshot(state) };
}, ["POST /sign-in/email-otp"]);

compatScenario("email OTP server-only create and get remain unavailable as public routes", async (ctx) => {
  const client = passwordlessClient(ctx);
  const email = ctx.uniqueEmail("otp-server");
  const created = await ctx.rawRequest({ path: "/__test/server-api", method: "POST", json: { operation: "create-email-otp", email, type: "sign-in" } });
  expect(created.status).toBe(200);
  const generated = z.string().min(1).safeParse(created.body);
  if (!generated.success) throw new Error("Server-only OTP creation must return a code");
  const unrelatedIdentifier = ctx.uniqueToken("otp-unrelated-expired");
  const seeded = await ctx.rawRequest({ path: "/__test/verification-state", method: "POST", json: { action: "seed", identifier: unrelatedIdentifier, value: "unrelated-expired-proof", expiresAt: "2001-01-01T00:00:00.000Z" } });
  expect(seeded.status).toBe(200);
  expect(await verificationCount(ctx, unrelatedIdentifier)).toBe(1);
  const retrieved = await ctx.rawRequest({ path: "/__test/server-api", method: "POST", json: { operation: "get-email-otp", email, type: "sign-in" } });
  expect(retrieved.status).toBe(200);
  const parsed = z.object({ otp: z.string() }).safeParse(retrieved.body);
  if (!parsed.success) throw new Error("Server-only OTP retrieval must return the code object");
  expect(parsed.data.otp).toBe(generated.data);
  expect(await verificationCount(ctx, unrelatedIdentifier)).toBe(0);
  expect(await verificationCount(ctx, `sign-in-otp-${email}`)).toBe(1);
  const publicCreate = await ctx.rawRequest({ path: "/api/auth/email-otp/create-verification-otp", method: "POST", json: { email, type: "sign-in" } });
  const publicGet = await ctx.rawRequest({ path: `/api/auth/email-otp/get-verification-otp?email=${encodeURIComponent(email)}&type=sign-in` });
  expect(publicCreate.status).toBe(404);
  expect(publicGet.status).toBe(404);
  const signIn = await client.signIn.emailOtp({ email, otp: generated.data });
  expect(signIn.error).toBeNull();
  const empty = await ctx.rawRequest({ path: "/__test/server-api", method: "POST", json: { operation: "get-email-otp", email, type: "sign-in" } });
  expect(empty.body).toEqual({ otp: null });
  return { serverCreated: created.status, serverRetrieved: retrieved.status, publicCreate: ctx.snapshot(publicCreate), publicGet: ctx.snapshot(publicGet), signIn: ctx.snapshot(signIn), empty: ctx.snapshot(empty) };
});

compatScenario("email OTP concurrent verification grants exactly one session", async (ctx) => {
  const issuer = passwordlessClient(ctx, "issuer");
  const email = ctx.uniqueEmail("otp-race");
  await issuer.emailOtp.sendVerificationOtp({ email, type: "sign-in" });
  const otp = await readOtp(ctx, email, "sign-in");
  // The controlled server interface returns both complete concurrent results
  // ordered by status. Scheduling order is deliberately not a wire contract.
  const response = await ctx.rawRequest({ path: "/__test/server-api", method: "POST", json: { operation: "race-email-otp", email, type: "sign-in", otp } });
  expect(response.status).toBe(200);
  const race = z.object({ results: z.tuple([
    z.object({ status: z.literal(200), body: z.object({ token: z.string(), user: z.object({ id: z.string(), email: z.string(), emailVerified: z.boolean() }).passthrough() }).passthrough() }),
    z.object({ status: z.literal(400), body: z.object({ code: z.literal("INVALID_OTP"), message: z.string() }).passthrough() }),
  ]) }).safeParse(response.body);
  if (!race.success) throw new Error("Exactly one concurrent server call must authenticate and the other must reject the consumed proof");
  const user = race.data.results[0].body.user;
  expect(user.email).toBe(email);
  expect(user.emailVerified).toBe(true);
  const state = await readUserState(ctx, user.id);
  expect(state.sessions).toHaveLength(1);
  expect(state.sessions.at(0)?.token).toBe(race.data.results[0].body.token);
  expect(await verificationCount(ctx, `sign-in-otp-${email}`)).toBe(0);
  return { race: ctx.snapshot(response), state: ctx.snapshot(state) };
}, ["POST /sign-in/email-otp"]);

compatScenario("email OTP validates all body fields before issuing or consuming authentication state", async (ctx) => {
  const results = [];
  for (const [path, json] of [
    ["/api/auth/email-otp/send-verification-otp", {}],
    ["/api/auth/email-otp/check-verification-otp", {}],
    ["/api/auth/email-otp/verify-email", {}],
    ["/api/auth/email-otp/request-password-reset", {}],
    ["/api/auth/forget-password/email-otp", {}],
    ["/api/auth/email-otp/reset-password", {}],
    ["/api/auth/email-otp/send-verification-otp", { email: null, type: "other" }],
    ["/api/auth/sign-in/email-otp", { email: 5, otp: false, name: null, image: 1 }],
    ["/api/auth/email-otp/change-email", {}],
    ["/api/auth/email-otp/request-email-change", { newEmail: "new@example.com", otp: null }],
    ["/api/auth/email-otp/send-verification-otp", { email: "a@b.c", type: "sign-in" }],
    ["/api/auth/email-otp/send-verification-otp", { email: "a..b@example.com", type: "sign-in" }],
  ] satisfies ReadonlyArray<readonly [string, unknown]>) {
    const response = await ctx.rawRequest({ path, method: "POST", json });
    expect(response.status).toBe(400);
    results.push(ctx.snapshot(response));
  }
  expect(await verificationCount(ctx, "sign-in-otp-a@b.c")).toBe(0);
  expect(await verificationCount(ctx, "sign-in-otp-a..b@example.com")).toBe(0);
  return results;
});

compatScenario("email OTP signup applies username normalization validation and collision checks after consuming proof", async (ctx) => {
  const client = ctx.actor().client;
  const email = ctx.uniqueEmail("otp-username-owner");
  await client.emailOtp.sendVerificationOtp({ email, type: "sign-in" });
  const invalid = await client.signIn.emailOtp({ email, otp: await readOtp(ctx, email, "sign-in"), username: "ab" });
  expect(invalid.error?.code).toBe("USERNAME_TOO_SHORT");
  expect(await verificationCount(ctx, `sign-in-otp-${email}`)).toBe(0);
  await client.emailOtp.sendVerificationOtp({ email, type: "sign-in" });
  const signedIn = await client.signIn.emailOtp({ email, otp: await readOtp(ctx, email, "sign-in"), username: "Mixed.Owner" });
  expect(signedIn.error).toBeNull();
  const user = requireUser(signedIn.data?.user);
  expect(user.username).toBe("mixed.owner");
  expect(user.displayUsername).toBe("mixed.owner");
  const available = await client.isUsernameAvailable({ username: "MIXED.OWNER" });
  expect(available.data?.available).toBe(false);
  const ownerBefore = await readUserState(ctx, user.id);
  const otherEmail = ctx.uniqueEmail("otp-username-duplicate");
  const foreign = ctx.actor("foreign-username").client;
  await foreign.emailOtp.sendVerificationOtp({ email: otherEmail, type: "sign-in" });
  const duplicateProof = await readOtp(ctx, otherEmail, "sign-in");
  const duplicate = await foreign.signIn.emailOtp({ email: otherEmail, otp: duplicateProof, username: "MIXED.OWNER" });
  expect(duplicate.error?.code).toBe("USERNAME_IS_ALREADY_TAKEN");
  expect(await verificationCount(ctx, `sign-in-otp-${otherEmail}`)).toBe(0);
  expect(await readUserState(ctx, user.id)).toEqual(ownerBefore);
  const duplicateReplay = await foreign.signIn.emailOtp({ email: otherEmail, otp: duplicateProof, username: "Foreign.Owner" });
  expect(duplicateReplay.error?.code).toBe("INVALID_OTP");
  await foreign.emailOtp.sendVerificationOtp({ email: otherEmail, type: "sign-in" });
  const retry = await foreign.signIn.emailOtp({ email: otherEmail, otp: await readOtp(ctx, otherEmail, "sign-in"), username: "Foreign.Owner" });
  expect(retry.error).toBeNull();
  const foreignUser = requireUser(retry.data?.user);
  expect(foreignUser.username).toBe("foreign.owner");
  expect(foreignUser.displayUsername).toBe("foreign.owner");
  const foreignState = await readUserState(ctx, foreignUser.id);
  expect(foreignState.accounts).toHaveLength(0);
  expect(foreignState.sessions).toHaveLength(1);
  const state = await readUserState(ctx, user.id);
  expect(state).toEqual(ownerBefore);
  expect(state.accounts).toHaveLength(0);
  expect(state.sessions).toHaveLength(1);
  const current = await client.getSession();
  expect(current.data?.user.id).toBe(user.id);
  const configured = await configuredPasswordlessUsernames(ctx);
  return { invalid, signedIn, available, duplicate, duplicateReplay, retry, foreignState, state, current, configured };
}, ["POST /sign-in/email-otp", "POST /is-username-available"]);

async function configuredPasswordlessUsernames(ctx: import("../../support/scenario").ScenarioContext) {
  const observations = [];
  for (const [profile, raw, stored, display] of [
    ["signup-username-pre", " Pre-Owner ", "pre_owner", "pre_owner"],
    ["signup-username-implicit", " Implicit-Owner ", "implicit_owner", "implicit_owner"],
    ["signup-username-post", " Post-Owner ", "post_owner", "post_owner"],
    ["signup-username-preserve", "Preserved.Owner", "Preserved.Owner", "Preserved.Owner"],
    ["signup-username-unicode", "ΟΣ", "ος", "ος"],
    ["signup-username-limits", "Xy", "xy", "xy"],
    ["signup-username-display-pre", "Display_Pre", "display_pre", "MIXED DISPLAY"],
    ["signup-username-display-post", "Display_Post", "display_post", "MIXED DISPLAY"],
    ["signup-username-display-disabled", "Hidden_Display", "hidden_display", undefined],
    ["signup-username-immutable", "Immutable.Owner", "immutable.owner", "immutable.owner"],
    ["signup-username-readonly", "Readonly.Owner", null, null],
    ["signup-username-throw", "Valid.Owner", "valid.owner", "valid.owner"],
  ] satisfies ReadonlyArray<readonly [FixtureProfile, string, string | null, string | null | undefined]>) {
    for (const method of ["email-otp", ...(profile === "signup-username-post" ? ["phone-number"] : [])]) {
      expect((await ctx.rawRequest({path:"/__test/signup-policy", method:"POST", json:{operation:"mode",mode:"normal"}})).status).toBe(200);
      const actor = ctx.actor(`${profile}-${method}`, profile);
      const state = async () => {
        // Read physical ownership columns through a profile that registers both username fields.
        const response = await ctx.rawRequest({path:"/__test/signup-policy/state?profile=signup-username-post"});
        expect(response.status).toBe(200);
        return z.object({users:z.array(z.record(z.string(),z.unknown())),accounts:z.array(z.unknown()),sessions:z.array(z.unknown()),verifications:z.array(z.unknown()),events:z.array(z.record(z.string(),z.unknown()))}).parse(response.body);
      };
      const path = (route: string) => `${authProfilePath(profile)}${route}`;
      const phoneNumber = `+1555${String(Bun.hash(ctx.uniqueToken(`${profile}-${method}`))).slice(0,7)}`;
      const email = ctx.uniqueEmail(`${profile}-${method}`);
      const identity = method === "email-otp" ? {email} : {phoneNumber};
      const issue = async () => {
        const sent = await ctx.rawRequest({path:path(method === "email-otp" ? "/email-otp/send-verification-otp" : "/phone-number/send-otp"),method:"POST",json:{...identity,...(method === "email-otp" ? {type:"sign-in"} : {})}});
        expect(sent.status).toBe(200);
        const delivered = (await state()).events.findLast(event => event.stage === (method === "email-otp" ? "otp" : "phone-otp"));
        return z.string().min(1).parse(delivered?.[method === "email-otp" ? "otp" : "code"]);
      };
      const admit = (proof: string, username: string | null) => actor.fetch(new URL(path(method === "email-otp" ? "/sign-in/email-otp" : "/phone-number/verify"),ctx.baseURL), {method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({...identity,[method === "email-otp" ? "otp" : "code"]:proof,...(username === null ? {} : {username}),...(profile.includes("display-pre") || profile.includes("display-post") ? {displayUsername:" mixed display "} : profile.endsWith("display-disabled") ? {displayUsername:"Ignored Display"} : {})})}).then(async response => {const text=await response.text();return {status:response.status,body:text ? JSON.parse(text) : null};});
      const before = await state();
      const invalidProof = await issue();
      const invalid = await admit(invalidProof,profile.endsWith("readonly") ? raw : profile.endsWith("throw") ? "explode" : "a");
      expect(invalid.status).toBe(profile.endsWith("throw") ? 500 : 400);
      if (!profile.endsWith("throw")) expect(invalid.body.code).toBe(profile.endsWith("readonly") ? "FIELD_NOT_ALLOWED" : "USERNAME_TOO_SHORT");
      const denied = await state();
      expect(denied.users).toEqual(before.users);
      expect(denied.accounts).toEqual(before.accounts);
      expect(denied.sessions).toEqual(before.sessions);
      expect(await verificationCount(ctx,method === "email-otp" ? `sign-in-otp-${email}` : phoneNumber)).toBe(0);
      const invalidReplay = await admit(invalidProof,raw);
      expect(invalidReplay.body.code).toBe(method === "email-otp" ? "INVALID_OTP" : "OTP_NOT_FOUND");
      const proof = await issue();
      const username = profile.endsWith("readonly") ? null : method === "phone-number" ? " Phone-Owner " : raw;
      const signedIn = await admit(proof,username);
      expect(signedIn.status).toBe(200);
      const user = requireUser(signedIn.body.user);
      expect(user.username).toBe(method === "phone-number" ? "phone_owner" : stored);
      expect(user.displayUsername).toBe(method === "phone-number" ? "phone_owner" : display);
      const saved = await state();
      const persisted = saved.users.find(row => row.id === user.id);
      expect(persisted?.username).toBe(method === "phone-number" ? "phone_owner" : stored);
      expect(persisted?.displayUsername).toBe(method === "phone-number" ? "phone_owner" : display ?? null);
      expect(saved.accounts).toEqual(before.accounts);
      expect(saved.sessions).toHaveLength(before.sessions.length + 1);
      expect(saved.users).toHaveLength(before.users.length + 1);
      const callbacks = saved.events.filter(event => event.stage === "username");
      if (["signup-username-pre","signup-username-implicit","signup-username-post"].includes(profile)) {
        expect(callbacks.filter(event => event.callback === "normalize")).toHaveLength(profile === "signup-username-post" ? 7 : 5);
        expect(callbacks[0]?.value).toBe("a");
      }
      const replay = await admit(proof,username);
      expect(replay.body.code).toBe(method === "email-otp" ? "INVALID_OTP" : "OTP_NOT_FOUND");
      const current = await actor.client.getSession();
      expect(current.data?.user.id).toBe(user.id);
      observations.push({profile,method,invalid,invalidReplay,signedIn,replay,current,users:saved.users,accounts:saved.accounts,sessions:saved.sessions,callbacks,hook:saved.events.filter(event=>event.stage==="username-hook")});
    }
  }
  return observations;
}
