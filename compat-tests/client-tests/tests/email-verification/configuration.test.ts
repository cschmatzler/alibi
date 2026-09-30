import { expect } from "bun:test";
import { z } from "zod";
import { compatScenario } from "../../support/scenario";

const stateSchema = z.object({
  user: z.object({ id: z.string(), email: z.string(), emailVerified: z.boolean() }),
  accounts: z.array(z.object({ userId: z.string(), accountId: z.string(), providerId: z.string() }).passthrough()),
  sessions: z.array(z.object({ id: z.string(), userId: z.string(), token: z.string() }).passthrough()),
}).passthrough();
const deliverySchema = z.object({ token: z.string(), url: z.string() });

compatScenario("required email verification issues proof without a session and gates sign-in until verification", async (ctx) => {
  const actor = ctx.actor("owner", "email-verification-required");
  const email = ctx.uniqueEmail("required-verification");
  const signup = await actor.client.signUp.email({ email, password: "password123", name: "Required Verification", username: "ab", displayUsername: "invalid display !" });
  expect(signup.error).toBeNull();
  if (!signup.data?.user) throw new Error("Required registration must persist its user");
  const userId = signup.data.user.id;
  expect(signup.data.token).toBeNull();
  expect(signup.data.user.emailVerified).toBe(false);
  expect(signup.data.user.createdAt).toBeInstanceOf(Date);
  const coreUser = z.record(z.string(), z.unknown()).parse(ctx.snapshot(signup.data.user));
  expect(Object.hasOwn(coreUser, "username")).toBe(false);
  expect(Object.hasOwn(coreUser, "displayUsername")).toBe(false);
  const registered = stateSchema.parse(await ctx.readUserState({ userId }));
  expect(registered.user).toMatchObject({ id: userId, email, emailVerified: false });
  expect(registered.accounts).toMatchObject([{ providerId: "credential", userId, accountId: userId }]);
  expect(registered.sessions).toEqual([]);
  const unavailableUsername = await ctx.rawRequest({path:"/__test/profiles/email-verification-required/api/auth/is-username-available", method:"POST", json:{username:"ab"}});
  expect(unavailableUsername).toEqual({status:404,location:null,body:null});
  const anonymous = await actor.client.getSession();
  expect(anonymous.data).toBeNull();
  const delivery = deliverySchema.parse(await ctx.readVerificationEmail({ email }));
  const payload: unknown = JSON.parse(Buffer.from(delivery.token.split(".")[1] ?? "", "base64url").toString());
  const claims = z.object({ email: z.literal(email), iat: z.number(), exp: z.number() }).parse(payload);
  expect(claims.exp - claims.iat).toBe(90);
  const blocked = await actor.client.signIn.email({ email, password: "password123" });
  expect(blocked.error).toMatchObject({ status: 403, code: "EMAIL_NOT_VERIFIED" });
  const denied = stateSchema.parse(await ctx.readUserState({ userId }));
  expect(denied).toEqual(registered);
  const verification = await actor.client.verifyEmail({ query: { token: delivery.token } });
  expect(ctx.snapshot(verification.data)).toEqual({ status: true, user: null });
  const verified = stateSchema.parse(await ctx.readUserState({ userId }));
  expect(verified.user).toMatchObject({ id: userId, email, emailVerified: true });
  expect(verified.sessions).toEqual([]);
  const signin = await actor.client.signIn.email({ email, password: "password123" });
  expect(signin.error).toBeNull();
  const session = await actor.client.getSession();
  expect(session.data?.user.id).toBe(userId);
  expect(session.data?.session.token).toBe(signin.data?.token);
  const signedIn = stateSchema.parse(await ctx.readUserState({ userId }));
  expect(signedIn.sessions).toMatchObject([{ id: session.data?.session.id, token: signin.data?.token, userId }]);
  return { signup, registered, unavailableUsername, anonymous, delivery, blocked, denied, verification, verified, signin, session, signedIn };
}, ["POST /sign-up/email", "GET /verify-email", "POST /sign-in/email"]);

compatScenario("sendOnSignUp false suppresses signup mail while sign-in verification remains required", async (ctx) => {
  const actor = ctx.actor("owner", "email-verification-no-signup-mail");
  const email = ctx.uniqueEmail("verification-no-signup-mail");
  const signup = await actor.client.signUp.email({ email, password: "password123", name: "Explicit Signup Delivery" });
  expect(signup.error).toBeNull();
  if (!signup.data?.user) throw new Error("Registration must persist its user");
  const userId = signup.data.user.id;
  expect(signup.data.token).toBeNull();
  expect(await ctx.readVerificationEmail({ email })).toBeNull();
  const registered = stateSchema.parse(await ctx.readUserState({ userId }));
  expect(registered.sessions).toEqual([]);
  const blocked = await actor.client.signIn.email({ email, password: "password123" });
  expect(blocked.error).toMatchObject({ status: 403, code: "EMAIL_NOT_VERIFIED" });
  const delivery = deliverySchema.parse(await ctx.readVerificationEmail({ email }));
  const denied = stateSchema.parse(await ctx.readUserState({ userId }));
  expect(denied).toEqual(registered);
  const verification = await actor.client.verifyEmail({ query: { token: delivery.token } });
  expect(verification.error).toBeNull();
  const signin = await actor.client.signIn.email({ email, password: "password123" });
  expect(signin.error).toBeNull();
  const signedIn = stateSchema.parse(await ctx.readUserState({ userId }));
  expect(signedIn.user.emailVerified).toBe(true);
  expect(signedIn.sessions).toMatchObject([{ token: signin.data?.token, userId }]);
  return { signup, registered, blocked, delivery, denied, verification, signin, signedIn };
}, ["POST /sign-up/email", "GET /verify-email", "POST /sign-in/email"]);

compatScenario("failed signup notifications retain the credential and proof while direct verification mail reports failure", async (ctx) => {
  const actor = ctx.actor("owner", "email-verification-failing-notifications");
  const email = ctx.uniqueEmail("verification-failed-notification");
  const signup = await actor.client.signUp.email({ email, password: "password123", name: "Delivery Failure" });
  expect(signup.error).toBeNull();
  if (!signup.data?.user) throw new Error("A failed notification must retain registration");
  const userId = signup.data.user.id;
  expect(signup.data.token).toBeNull();
  const registered = stateSchema.parse(await ctx.readUserState({ userId }));
  expect(registered.accounts).toMatchObject([{ providerId: "credential", userId, accountId: userId }]);
  expect(registered.sessions).toEqual([]);
  const delivery = deliverySchema.parse(await ctx.readVerificationEmail({ email }));
  const blocked = await actor.client.signIn.email({ email, password: "password123" });
  expect(blocked.error).toMatchObject({ status: 403, code: "EMAIL_NOT_VERIFIED" });
  const direct = await actor.client.sendVerificationEmail({ email });
  expect(direct.error).toMatchObject({ status: 400, message: "fixture delivery failed" });
  const denied = stateSchema.parse(await ctx.readUserState({ userId }));
  expect(denied).toEqual(registered);
  const verification = await actor.client.verifyEmail({ query: { token: delivery.token } });
  expect(ctx.snapshot(verification.data)).toEqual({ status: true, user: null });
  const signin = await actor.client.signIn.email({ email, password: "password123" });
  expect(signin.error).toBeNull();
  const signedIn = stateSchema.parse(await ctx.readUserState({ userId }));
  expect(signedIn.user.emailVerified).toBe(true);
  expect(signedIn.sessions).toMatchObject([{ token: signin.data?.token, userId }]);
  return { signup, registered, delivery, blocked, direct, denied, verification, signin, signedIn };
}, ["POST /sign-up/email", "GET /verify-email", "POST /sign-in/email"]);
