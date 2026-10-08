import { expect } from "bun:test";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "configured snake casing retains public field names and physical owner writes",
  async (ctx) => {
    const owner = ctx.actor("owner", "snake-casing");
    const signup = await owner.client.signUp.email({
      email: ctx.uniqueEmail("casing"),
      password: "password123",
      name: "Original casing",
    });
    expect(signup.error).toBeNull();
    const updated = await owner.client.updateUser({ name: "Updated casing" });
    expect(updated.error).toBeNull();
    const session = await owner.client.getSession();
    expect(session.data!.user).toMatchObject({
      id: signup.data!.user.id,
      name: "Updated casing",
      emailVerified: false,
    });
    const persisted = await ctx.rawRequest({
      path: `/__test/casing/state?userId=${signup.data!.user.id}`,
    });
    expect(persisted.body).toEqual({
      users: [
        {
          id: signup.data!.user.id,
          name: "Updated casing",
          email: signup.data!.user.email,
          verified: 0,
        },
      ],
      sessions: [{ owner: signup.data!.user.id }],
    });
    const schema = await owner.client.$fetch<any>("/open-api/generate-schema", { method: "GET" });
    expect(schema.error).toBeNull();
    const properties =
      schema.data.paths["/sign-up/email"].post.requestBody.content["application/json"].schema
        .properties;
    expect(properties).toHaveProperty("email");
    expect(properties).toHaveProperty("password");
    expect(properties).toHaveProperty("name");
    expect(properties).not.toHaveProperty("email_verified");
    return ctx.snapshot({
      signup,
      updated,
      session,
      persisted: {
        ...persisted,
        body: {
          ...(persisted.body as any),
          sessions: (persisted.body as any).sessions.map((row: any) => ({ userId: row.owner })),
        },
      },
      schemaFields: Object.keys(properties).sort(),
    });
  },
  ["POST /sign-up/email", "POST /update-user", "GET /get-session", "GET /open-api/generate-schema"],
);
