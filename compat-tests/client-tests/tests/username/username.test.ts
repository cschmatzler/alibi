import { expect } from "bun:test";
import { compatScenario } from "../../support/scenario";

compatScenario("username availability follows normalized persisted usernames", async (ctx) => {
  const actor = ctx.actor();
  const username = ctx.uniqueToken("username").replace(/-/g, "_");
  const before = await actor.client.isUsernameAvailable({ username: username.toUpperCase() });
  expect(before.data).toEqual({ available: true });
  const signup = await actor.client.signUp.email({
    email: ctx.uniqueEmail("admin-username"), password: "password123", name: "Username User", username: username.toUpperCase(),
  });
  expect(signup.error).toBeNull();
  expect(signup.data?.user.username).toBe(username);
  if (!signup.data) throw new Error("username owner must exist");
  const stateBefore = await ctx.readUserState({ userId: signup.data.user.id });
  const taken = await ctx.actor("guest").client.isUsernameAvailable({ username });
  const differentCase = await ctx.actor("guest").client.isUsernameAvailable({ username: username.toUpperCase() });
  const unrelated = await ctx.actor("guest").client.isUsernameAvailable({ username: "another_available_username" });
  expect(taken.data).toEqual({ available: false });
  expect(differentCase.data).toEqual({ available: false });
  expect(unrelated.data).toEqual({ available: true });
  const stateAfter = await ctx.readUserState({ userId: signup.data.user.id });
  expect(stateAfter).toEqual(stateBefore);
  const session = await actor.client.getSession();
  expect(session.data?.user.username).toBe(username);
  return { before: ctx.snapshot(before), signup: ctx.snapshot(signup), taken: ctx.snapshot(taken), differentCase: ctx.snapshot(differentCase), unrelated: ctx.snapshot(unrelated), session: ctx.snapshot(session) };
}, ["POST /sign-up/email", "POST /is-username-available"]);

compatScenario("username availability rejects invalid names before lookup", async (ctx) => {
  const client = ctx.actor().client;
  const empty = await client.isUsernameAvailable({ username: "" });
  const tooShort = await client.isUsernameAvailable({ username: "ab" });
  const tooLong = await client.isUsernameAvailable({ username: "a".repeat(31) });
  const invalid = await client.isUsernameAvailable({ username: "bad+username" });
  expect(empty.error).toMatchObject({ status: 422, code: "INVALID_USERNAME" });
  expect(tooShort.error).toMatchObject({ status: 422, code: "USERNAME_TOO_SHORT" });
  expect(tooLong.error).toMatchObject({ status: 422, code: "USERNAME_TOO_LONG" });
  expect(invalid.error).toMatchObject({ status: 422, code: "INVALID_USERNAME" });
  return { empty: ctx.snapshot(empty), tooShort: ctx.snapshot(tooShort), tooLong: ctx.snapshot(tooLong), invalid: ctx.snapshot(invalid) };
});
