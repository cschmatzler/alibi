import { expect } from "bun:test";

import { compatScenario } from "../../../support/scenario";

compatScenario(
  "explicit null username keeps display-only ownership while omission derives a login alias",
  async (ctx) => {
    const display = "occupied_display";
    const foreign = ctx.actor("foreign");
    const foreignSignup = await foreign.client.signUp.email({
      email: ctx.uniqueEmail("null-display-foreign"),
      name: "Foreign Owner",
      password: "foreign-password-123",
      username: display,
    });
    expect(foreignSignup.error).toBeNull();
    const foreignBefore = await ctx.readUserState({ userId: foreignSignup.data!.user.id });
    const owner = ctx.actor("owner");
    const signup = await owner.client.$fetch("/sign-up/email", {
      method: "POST",
      body: {
        email: ctx.uniqueEmail("null-display-owner"),
        name: "Display Only Owner",
        password: "password123",
        username: null,
        displayUsername: display,
      },
    });
    expect(signup.error).toBeNull();
    const id = (signup.data as any).user.id;
    expect((signup.data as any).user).toMatchObject({
      id,
      username: null,
      displayUsername: display,
    });
    const current = await owner.client.getSession();
    expect(current.data!.user).toMatchObject({ id, username: null, displayUsername: display });
    const ownerBefore = await ctx.readUserState({ userId: id });
    const state = async () => ({
      owner: await ctx.readUserState({ userId: id }),
      foreign: await ctx.readUserState({ userId: foreignSignup.data!.user.id }),
    });
    const before = await state();
    const guest = ctx.actor("guest");
    const omitted = await guest.client.signUp.email({
      email: ctx.uniqueEmail("omitted-display-owner"),
      name: "Omitted Owner",
      password: "password123",
      displayUsername: display,
    });
    expect(omitted.error).toMatchObject({ status: 400, code: "USERNAME_IS_ALREADY_TAKEN" });
    expect(await state()).toEqual(before);
    const denied = await guest.client.signIn.username({
      username: display,
      password: "password123",
    });
    expect(denied.error).toMatchObject({ status: 401, code: "INVALID_USERNAME_OR_PASSWORD" });
    const available = await guest.client.isUsernameAvailable({ username: display });
    expect(available.data).toEqual({ available: false });
    expect(await state()).toEqual(before);
    expect(await ctx.readUserState({ userId: id })).toEqual(ownerBefore);
    expect(await ctx.readUserState({ userId: foreignSignup.data!.user.id })).toEqual(foreignBefore);
    const derived = await guest.client.signUp.email({
      email: ctx.uniqueEmail("derived-display-owner"),
      name: "Derived Owner",
      password: "password123",
      displayUsername: "Fresh_Display",
    });
    expect(derived.error).toBeNull();
    expect(derived.data!.user).toMatchObject({
      username: "fresh_display",
      displayUsername: "Fresh_Display",
    });
    return ctx.snapshot({ foreignSignup, signup, current, omitted, denied, available, derived });
  },
  [
    "POST /sign-up/email",
    "POST /sign-in/username",
    "POST /is-username-available",
    "GET /get-session",
  ],
);
