import { expect } from "bun:test";
import { createAuthClient } from "better-auth/client";
import { anonymousClient, emailOTPClient, magicLinkClient, phoneNumberClient } from "better-auth/client/plugins";
import { passkeyClient } from "@better-auth/passkey/client";
import { compatScenario, type ScenarioContext } from "../../support/scenario";
import { authProfilePath } from "../../support/profiles";
import { Authenticator } from "../../support/authenticator";
import { credential, oneTap } from "../one-tap/helpers";

const profile = "anonymous-methods" as const;
function client(ctx: ScenarioContext, name: string) {
  return createAuthClient({ baseURL: ctx.baseURL + authProfilePath(profile),
    plugins: [anonymousClient(), emailOTPClient(), magicLinkClient(), phoneNumberClient(), passkeyClient()],
    fetchOptions: { customFetchImpl: ctx.actor(name, profile).fetch } });
}
async function state(ctx: ScenarioContext) {
  const value = await ctx.rawRequest({ path: "/__test/anonymous/state" });
  expect(value.status).toBe(200);
  return value.body as { users: any[]; accounts: any[]; sessions: any[]; events: any[] };
}
async function delivery(ctx: ScenarioContext, key: string) {
  const result = await ctx.rawRequest({ path: `/__test/anonymous/delivery?key=${encodeURIComponent(key)}` });
  expect(result.status).toBe(200); expect(result.body).not.toBeNull();
  return result.body as Record<string, any>;
}
function observedDelivery(value: Record<string, any>) {
  // Retain every actual delivery field; only the random code value uses the
  // existing token namespace. Unwrapping returns the exact submitted bytes.
  const result = { ...value };
  for (const field of ["otp", "code"]) if (typeof value[field] === "string") {
    result[field] = { token: value[field] }; expect(result[field].token).toBe(value[field]);
  }
  return result;
}
function observedAssertion(value: ReturnType<Authenticator["authenticate"]>) {
  const decoded = JSON.parse(Buffer.from(value.response.clientDataJSON, "base64url").toString());
  expect(Buffer.from(JSON.stringify(decoded)).toString("base64url")).toBe(value.response.clientDataJSON);
  const handle = Buffer.from(value.response.userHandle, "base64url").toString();
  expect(Buffer.from(handle).toString("base64url")).toBe(value.response.userHandle);
  return { ...value, response: { ...value.response,
    clientDataJSON: { ...decoded, origin: { url: decoded.origin } },
    signature: { token: value.response.signature },
    userHandle: { id: value.response.userHandle, decoded: { id: handle } },
  } };
}

for (const method of ["magic", "email-otp", "email-otp-verification", "email-verification", "phone", "one-tap", "passkey"] as const) {
  const route = method === "magic" ? "GET /magic-link/verify" : method === "email-otp" ? "POST /sign-in/email-otp" : method === "email-otp-verification" ? "POST /email-otp/verify-email" : method === "email-verification" ? "GET /verify-email" : method === "phone" ? "POST /phone-number/verify" : method === "one-tap" ? "POST /one-tap/callback" : "POST /passkey/verify-authentication";
  compatScenario(`anonymous ${method} verified login transfers only the actual anonymous owner and preserves rejected proof state`, async ctx => {
    const primary = client(ctx, "primary"), foreign = client(ctx, "foreign"), enrolled = client(ctx, "enrolled");
    const foreignSignup = await foreign.signUp.email({ email: ctx.uniqueEmail("methods-foreign"), password: "password123", name: "Foreign" });
    expect(foreignSignup.error).toBeNull();
    const foreignBefore = await ctx.readUserState({ userId: foreignSignup.data!.user.id });
    const email = ctx.uniqueEmail(`methods-${method}`), preparation: unknown[] = [];
    let ownerId: string | undefined, device: Authenticator | undefined, registrationOptions: any;
    if (method === "email-otp-verification" || method === "email-verification" || method === "passkey") {
      const signup = await enrolled.signUp.email({ email, name: "Enrolled", password: "password123" });
      expect(signup.error).toBeNull(); ownerId = signup.data!.user.id; preparation.push(signup);
      if (method === "passkey") {
        device = new Authenticator();
        const options = await enrolled.$fetch("/passkey/generate-register-options", { method: "GET" }); expect(options.error).toBeNull();
        registrationOptions = options.data;
        const registered = await enrolled.$fetch("/passkey/verify-registration", { method: "POST", body: { response: device.register(options.data, ctx.baseURL), name: "Anonymous upgrade device" } });
        expect(registered.error).toBeNull(); preparation.push({ options, registered });
        const out = await enrolled.signOut(); expect(out.error).toBeNull(); preparation.push(out);
      }
    }
    const anonymous = await primary.signIn.anonymous(); expect(anonymous.error).toBeNull();
    const original = await primary.getSession(); expect(original.data!.user.id).toBe(anonymous.data!.user.id);
    const before = await state(ctx); expect(before.events).toEqual([]);
    let issued: unknown = null, delivered: Record<string, any> | null = null, denied: any, accepted: any, replay: any;
    const proofs: unknown[] = [], rejectedSnapshots: unknown[] = [];
    async function rejectUnchanged() {
      const rejected = await state(ctx);
      expect(rejected).toEqual(before);
      const session = await primary.getSession();
      expect(session.data!.session.token).toBe(original.data!.session.token);
      rejectedSnapshots.push({ rejected, session });
    }
    if (method === "magic") {
      issued = await primary.signIn.magicLink({ email, name: "Mailbox Owner", metadata: { method: "anonymous-upgrade" } });
      expect((issued as any).error).toBeNull(); delivered = await delivery(ctx, `magic:${email}`);
      expect(delivered).toMatchObject({ email, metadata: { method: "anonymous-upgrade" } });
      denied = await ctx.rawRequest({ actor: "primary", path: `${authProfilePath(profile)}/magic-link/verify?token=wrong-actual-mailbox-proof`, redirect: "manual" });
      expect(denied.status).toBe(302);
      await rejectUnchanged();
      accepted = await primary.magicLink.verify({ query: { token: delivered.token } }); expect(accepted.error).toBeNull();
      replay = await ctx.rawRequest({ actor: "primary", path: `${authProfilePath(profile)}/magic-link/verify?token=${encodeURIComponent(delivered.token)}`, redirect: "manual" }); expect(replay.status).toBe(302);
    } else if (method === "email-otp" || method === "email-otp-verification") {
      const type = method === "email-otp" ? "sign-in" : "email-verification";
      issued = await primary.emailOtp.sendVerificationOtp({ email, type }); expect((issued as any).error).toBeNull();
      delivered = await delivery(ctx, `${type}:${email}`); expect(delivered).toMatchObject({ email, type });
      const verify = (otp: string) => method === "email-otp" ? primary.signIn.emailOtp({ email, otp, name: "Mailbox Owner" }) : primary.emailOtp.verifyEmail({ email, otp });
      denied = await verify("wrong-actual-mailbox-proof"); expect(denied.error).toMatchObject({ status: 400, code: "INVALID_OTP" });
      await rejectUnchanged();
      accepted = await verify(delivered.otp); expect(accepted.error).toBeNull();
      replay = await verify(delivered.otp); expect(replay.error).toMatchObject({ status: 400, code: "INVALID_OTP" });
    } else if (method === "email-verification") {
      issued = await enrolled.sendVerificationEmail({ email }); expect((issued as any).error).toBeNull();
      delivered = await delivery(ctx, `verification:${email}`); expect(delivered.email).toBe(email);
      denied = await primary.verifyEmail({ query: { token: "wrong-actual-email-proof" } }); expect(denied.error).not.toBeNull();
      await rejectUnchanged();
      accepted = await primary.verifyEmail({ query: { token: delivered.token } }); expect(accepted.error).toBeNull();
      // Signed email proof reuse is Source-legal; it must never transfer the
      // already-deleted anonymous identity again.
      replay = await primary.verifyEmail({ query: { token: delivered.token } }); expect(replay.error).toBeNull();
    } else if (method === "phone") {
      const phoneNumber = "+15550007891";
      issued = await primary.phoneNumber.sendOtp({ phoneNumber }); expect((issued as any).error).toBeNull();
      delivered = await delivery(ctx, `phone:${phoneNumber}`); expect(delivered.phoneNumber).toBe(phoneNumber);
      denied = await primary.phoneNumber.verify({ phoneNumber, code: "wrong-actual-phone-proof" }); expect(denied.error).toMatchObject({ status: 400, code: "INVALID_OTP" });
      await rejectUnchanged();
      accepted = await primary.phoneNumber.verify({ phoneNumber, code: delivered.code }); expect(accepted.error).toBeNull();
      replay = await primary.phoneNumber.verify({ phoneNumber, code: delivered.code }); expect(replay.error).not.toBeNull();
    } else if (method === "one-tap") {
      const claims = { sub: "anonymous-method-google-subject", email, email_verified: true, name: "Google Owner" };
      const wrong = await credential(claims, {}, true), token = await credential(claims); proofs.push({ wrong, token });
      denied = await oneTap(ctx, wrong, profile, "primary"); expect((denied as any).response.error).not.toBeNull();
      await rejectUnchanged();
      accepted = await oneTap(ctx, token, profile, "primary"); expect((accepted as any).response.error).toBeNull();
      replay = await oneTap(ctx, token, profile, "primary"); expect((replay as any).response.error).toBeNull();
    } else {
      const challenge = await primary.$fetch("/passkey/generate-authenticate-options", { method: "GET" }); expect(challenge.error).toBeNull();
      const wrong = device!.authenticate({ ...(challenge.data as object), challenge: "wrong-signed-anonymous-challenge" }, ctx.baseURL);
      expect(wrong.response.userHandle).toBe(registrationOptions.user.id);
      denied = await primary.$fetch("/passkey/verify-authentication", { method: "POST", body: { response: wrong } }); expect(denied.error).toMatchObject({ status: 400, code: "AUTHENTICATION_FAILED" });
      await rejectUnchanged();
      const options = await primary.$fetch("/passkey/generate-authenticate-options", { method: "GET" }); expect(options.error).toBeNull();
      const proof = device!.authenticate(options.data, ctx.baseURL); expect(proof.response.userHandle).toBe(registrationOptions.user.id);
      accepted = await primary.$fetch("/passkey/verify-authentication", { method: "POST", body: { response: proof } }); expect(accepted.error).toBeNull();
      replay = await primary.$fetch("/passkey/verify-authentication", { method: "POST", body: { response: proof } }); expect(replay.error).toMatchObject({ status: 400, code: "CHALLENGE_NOT_FOUND" });
      proofs.push({ challenge, wrong: observedAssertion(wrong), options, submitted: observedAssertion(proof) });
    }
    const current = await primary.getSession(); expect(current.error).toBeNull(); expect(current.data).not.toBeNull();
    expect(current.data!.user.id).not.toBe(anonymous.data!.user.id);
    if (ownerId) expect(current.data!.user.id).toBe(ownerId);
    const after = await state(ctx); expect(after.events).toHaveLength(1);
    const event = after.events[0]!;
    expect(event).toMatchObject({ mode: "methods", anonymousUser: { user: { id: anonymous.data!.user.id }, session: { token: original.data!.session.token, userId: anonymous.data!.user.id } }, newUser: { user: { id: current.data!.user.id }, session: { userId: current.data!.user.id } } });
    expect(event.anonymousUser).toEqual(ctx.snapshot(original.data));
    // Signed email verification publishes the original pre-update user with
    // only emailVerified changed; the authoritative current row is newer.
    const expectedNewUser = method === "email-verification"
      ? { ...(preparation[0] as any).data.user, emailVerified: true }
      : current.data!.user;
    expect(event.newUser.user).toEqual(ctx.snapshot(expectedNewUser));
    expect(event.newUser.session.token).not.toBe(original.data!.session.token);
    expect(event.path).toBe(route.slice(route.indexOf(" ") + 1));
    expect(after.users.some(row => row.id === anonymous.data!.user.id)).toBe(false);
    expect(after.sessions.some(row => row.userId === anonymous.data!.user.id)).toBe(false);
    expect(after.accounts.some(row => row.userId === anonymous.data!.user.id)).toBe(false);
    expect(after.sessions.some(row => row.userId === current.data!.user.id && row.token === current.data!.session.token)).toBe(true);
    expect(await ctx.readUserState({ userId: foreignSignup.data!.user.id })).toEqual(foreignBefore);
    let passkeys: unknown = null;
    if (method === "passkey") {
      passkeys = await primary.$fetch("/passkey/list-user-passkeys", { method: "GET" });
      expect((passkeys as any).error).toBeNull();
      expect((passkeys as any).data).toMatchObject([{ userId: ownerId, counter: 2 }]);
    }
    const old = await ctx.readUserState({ userId: anonymous.data!.user.id }); expect(old).toMatchObject({ user: null, sessions: [], accounts: [] });
    return { method, foreignSignup, foreignBefore, preparation, anonymous, original, before, issued,
      delivered: delivered ? observedDelivery(delivered) : null, denied, rejectedSnapshots, accepted, replay, proofs, current, after, old, passkeys,
      foreignAfter: await ctx.readUserState({ userId: foreignSignup.data!.user.id }) };
  }, [route]);
}
