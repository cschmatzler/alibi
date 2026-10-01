import { expect } from "bun:test";
import { compatScenario } from "../../support/scenario";

compatScenario("social sign-in preserves previously granted account scopes", async (ctx) => {
  const owner = ctx.actor();
  const email = ctx.uniqueEmail("oauth-retained-scopes");
  const sub = ctx.uniqueToken("oauth-retained-scope-sub");
  const signup = await owner.client.signUp.email({ email, password: "password123", name: "Scope Owner" });
  expect(signup.error).toBeNull();
  const accountId = await ctx.seedOAuthAccount({ email, providerId: "google", accountId: sub, scope: "calendar,drive", idToken: "old-id-token" });
  await ctx.setSocialProfile({ sub, email, emailVerified: true, name: "Google Scope Owner" });
  const started = await owner.client.signIn.social({ provider: "google", callbackURL: "/scopes" });
  expect(started.error).toBeNull();
  const state = new URL(started.data!.url!).searchParams.get("state");
  expect(state).toBeTruthy();
  const callback = await ctx.rawRequest({ path: `/api/auth/callback/google?code=compat-code&state=${encodeURIComponent(state!)}`, redirect: "manual" });
  expect(callback.status).toBe(302);
  expect(callback.location).toBe("/scopes");
  const session = await owner.client.getSession();
  expect(session.data?.user.id).toBe(signup.data?.user.id);
  expect(session.data?.session.userId).toBe(signup.data?.user.id);
  const listed = await owner.client.listAccounts();
  expect(listed.error).toBeNull();
  const google = listed.data?.find((account) => account.providerId === "google");
  expect(google?.id).toBe(accountId);
  expect(google?.accountId).toBe(sub);
  expect(google?.scopes).toEqual(["calendar", "drive"]);
  return { callback, session, listed };
});
