import { expect } from "bun:test";
import { compatScenario, type ScenarioContext } from "../../support/scenario";
import { authProfilePath } from "../../support/profiles";

type State = {
  users: { id: string; name: string; email: string; emailVerified: boolean; image: string | null }[];
  accounts: { id: string; userId: string; accountId: string; providerId: string; accessToken: string | null }[];
  sessions: { id: string; userId: string; token: string }[];
  receipts: { path: string; body: unknown }[];
};
async function state(ctx: ScenarioContext) {
  const result = await ctx.rawRequest({ path: "/__test/social-provider/state" });
  expect(result.status).toBe(200);
  return result.body as State;
}

compatScenario("Discord profile defaults persist original provider owners names and avatar URLs", async ctx => {
  const fixture = "social-discord-default";
  const foreign = ctx.actor("foreign", fixture);
  const foreignSignup = await foreign.client.signUp.email({ email: ctx.uniqueEmail("discord-profile-foreign"), password: "password123", name: "Foreign Owner" });
  expect(foreignSignup.error).toBeNull();
  const foreignBefore = await ctx.readUserState({ userId: foreignSignup.data!.user.id });
  const before = await state(ctx);
  const table = [
    { mode: "global", id: "4194304", username: "Username", global_name: "Global Name", avatar: "fixture", discriminator: "0", verified: true, name: "Global Name", image: "https://cdn.discordapp.com/avatars/4194304/fixture.png" },
    { mode: "animated", id: "8388608", username: "Fallback Name", global_name: "", avatar: "a_fixture", discriminator: "0", verified: true, name: "Fallback Name", image: "https://cdn.discordapp.com/avatars/8388608/a_fixture.gif" },
    { mode: "modern", id: "12582912", username: "Modern User", global_name: null, avatar: null, discriminator: "0", verified: true, name: "Modern User", image: "https://cdn.discordapp.com/embed/avatars/3.png" },
    { mode: "legacy", id: "16777216", username: "Legacy User", global_name: null, avatar: null, discriminator: "1234", verified: true, name: "Legacy User", image: "https://cdn.discordapp.com/embed/avatars/4.png" },
    { mode: "empty-name", id: "20971520", username: "", global_name: null, avatar: "fixture", discriminator: "0", verified: true, name: "", image: "https://cdn.discordapp.com/avatars/20971520/fixture.png" },
    // The shifted integer is 2^53+1: Number rounds before remainder, yielding 2, not 3.
    { mode: "rounded-large", id: "37778931862957165903872", username: "Rounded User", global_name: null, avatar: null, discriminator: "0", verified: true, name: "Rounded User", image: "https://cdn.discordapp.com/embed/avatars/2.png" },
    { mode: "overflow-large", id: "1" + "0".repeat(340), username: "Overflow User", global_name: null, avatar: null, discriminator: "0", verified: true, name: "Overflow User", image: "https://cdn.discordapp.com/embed/avatars/NaN.png" },
    { mode: "unverified", id: "25165824", username: "Unverified User", global_name: "Unverified Global", avatar: "fixture", discriminator: "0", verified: false, name: "Unverified Global", image: "https://cdn.discordapp.com/avatars/25165824/fixture.png" },
  ];
  const results = [];
  for (const [index, entry] of table.entries()) {
    const { mode, name, image, ...fields } = entry;
    const profile = { ...fields, email: ctx.uniqueEmail(`discord-profile-${mode}`) };
    const control = await ctx.rawRequest({ path: "/__test/social-provider/profile", method: "POST", json: profile });
    expect(control.status).toBe(200);
    const actor = ctx.actor(mode, fixture);
    const signin = await actor.client.signIn.social({ provider: "discord", callbackURL: "/social-done", disableRedirect: true });
    expect(signin.error).toBeNull();
    const issuedState = new URL(signin.data!.url!).searchParams.get("state");
    if (!issuedState) throw new Error("genuine issued state required");
    const callbackResponse = await actor.fetch(`${authProfilePath(fixture)}/callback/discord?${new URLSearchParams({ code: "fixture-code", state: issuedState })}`, { redirect: "manual" });
    const callback = { status: callbackResponse.status, location: callbackResponse.headers.get("location"), body: await callbackResponse.text() };
    expect(callback).toMatchObject({ status: 302, location: "/social-done" });
    const current = await actor.client.getSession();
    expect(current.error).toBeNull();
    if (!current.data) throw new Error("real provider session required");
    expect(current.data.user).toMatchObject({ email: profile.email, name, image, emailVerified: entry.verified });
    expect(current.data.user.id).not.toBe(foreignSignup.data!.user.id);
    expect(current.data.session.userId).toBe(current.data.user.id);
    const after = await state(ctx);
    expect(after.users).toHaveLength(before.users.length + index + 1);
    expect(after.accounts).toHaveLength(before.accounts.length + index + 1);
    expect(after.sessions).toHaveLength(before.sessions.length + index + 1);
    expect(after.receipts).toHaveLength((index + 1) * 2);
    expect(after.users.find(row => row.id === current.data!.user.id)).toMatchObject({ email: profile.email, name, image, emailVerified: entry.verified });
    expect(after.accounts.filter(row => row.userId === current.data!.user.id)).toEqual([expect.objectContaining({ accountId: profile.id, providerId: "discord", userId: current.data.user.id, accessToken: "fixture-discord-access" })]);
    expect(after.sessions.filter(row => row.userId === current.data!.user.id)).toEqual([expect.objectContaining({ token: current.data.session.token, userId: current.data.user.id })]);
    expect(await ctx.readUserState({ userId: foreignSignup.data!.user.id })).toEqual(foreignBefore);
    results.push({ mode, control, signin: ctx.snapshot(signin), callback, current: ctx.snapshot(current), after });
  }
  const foreignAfter = await ctx.readUserState({ userId: foreignSignup.data!.user.id }), foreignCurrent = await foreign.client.getSession();
  expect(foreignAfter).toEqual(foreignBefore);
  expect(foreignCurrent.data!.session.token).toBe(foreignSignup.data!.token!);
  return { foreignSignup: ctx.snapshot(foreignSignup), foreignBefore, before, results, foreignAfter, foreignCurrent: ctx.snapshot(foreignCurrent) };
}, ["state"]);
