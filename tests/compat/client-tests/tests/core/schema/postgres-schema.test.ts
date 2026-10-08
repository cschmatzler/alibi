import { expect, test } from "bun:test";

import { compatScenario } from "../../../support/scenario";
if (!process.env.BETTER_AUTH_TEST_POSTGRES_URL)
  test.skip("Postgres schema qualification needs BETTER_AUTH_TEST_POSTGRES_URL", () => {});
else
  compatScenario(
    "Postgres schemaName migrates and qualifies writes outside the connection search_path",
    async (ctx) => {
      const before = await ctx.rawRequest({ path: "/__test/postgres-schema/state" });
      expect(before.body).toEqual({
        schemaExists: true,
        connectionUsesNamespace: false,
        users: [],
        sessions: [],
      });
      const owner = ctx.actor("owner", "postgres-schema");
      const signup = await owner.client.signUp.email({
        email: ctx.uniqueEmail("postgres-schema"),
        password: "password123",
        name: "Namespace owner",
      });
      expect(signup.error).toBeNull();
      const update = await owner.client.updateUser({ name: "Qualified update" });
      expect(update.error).toBeNull();
      const session = await owner.client.getSession();
      expect(session.data!.user).toMatchObject({
        id: signup.data!.user.id,
        name: "Qualified update",
      });
      const after = await ctx.rawRequest({ path: "/__test/postgres-schema/state" });
      expect(after.body).toEqual({
        schemaExists: true,
        connectionUsesNamespace: false,
        users: [
          { id: signup.data!.user.id, name: "Qualified update", email: signup.data!.user.email },
        ],
        sessions: [{ owner: signup.data!.user.id }],
      });
      await owner.client.signOut();
      const revoked = await ctx.rawRequest({ path: "/__test/postgres-schema/state" });
      expect((revoked.body as any).sessions).toEqual([]);
      return ctx.snapshot({ before, signup, update, session, after, revoked });
    },
    ["POST /sign-up/email", "POST /update-user", "GET /get-session", "POST /sign-out"],
  );
