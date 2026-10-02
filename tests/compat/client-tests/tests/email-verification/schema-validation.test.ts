import { expect } from "bun:test";

import { compatScenario } from "../../support/scenario";

compatScenario(
  "verification email schemas reject malformed fields before delivery or user mutation",
  async (ctx) => {
    const actor = ctx.actor();
    const email = ctx.uniqueEmail("verification-schema");
    const signup = await actor.client.signUp.email({
      email,
      password: "password123",
      name: "Verification Schema",
    });
    const user = signup.data?.user;

    if (!user) {
      throw new Error("Schema checks require an existing unverified authenticated user");
    }

    const before = await ctx.readUserState({ userId: user.id });
    expect(await ctx.readVerificationEmail({ email })).toBeNull();

    const rejected = [];

    for (const { json, error } of [
      {
        json: { email: null, callbackURL: 5 },
        error: { message: "Invalid callbackURL: expected a string" },
      },
      { json: { email, callbackURL: null }, error: { code: "VALIDATION_ERROR" } },
      { json: { email: "a..b@fixture.test" }, error: { code: "VALIDATION_ERROR" } },
      { json: { email: "a@fixture.c" }, error: { code: "VALIDATION_ERROR" } },
      { json: {}, error: { code: "VALIDATION_ERROR" } },
    ]) {
      const response = await ctx.rawRequest({
        path: "/api/auth/send-verification-email",
        method: "POST",
        json,
      });
      expect(response.status).toBe(400);
      expect(response.body).toMatchObject(error);

      rejected.push(response);
    }

    expect(await ctx.readVerificationEmail({ email })).toBeNull();

    const after = await ctx.readUserState({ userId: user.id });
    expect(after).toEqual(before);

    const valid = await actor.client.sendVerificationEmail({
      email,
      callbackURL: "/verified?case=schema",
    });
    expect(valid.error).toBeNull();

    const delivery = await ctx.readVerificationEmail({ email });
    expect(delivery).toMatchObject({ token: expect.any(String), url: expect.any(String) });

    return { signup, before, rejected, after, valid, delivery };
  },
);
