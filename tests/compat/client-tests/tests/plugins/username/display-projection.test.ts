import { expect } from "bun:test";

import { compatScenario } from "../../../support/scenario";

// includeDisplayUsername is an internal projection flag selected by the server
// username({ displayUsername: false }) option, not a client request option.
for (const profile of ["signup-username-preserve", "signup-username-display-disabled"] as const) {
  compatScenario(
    `username ${profile} projects display names consistently across sign-in and session`,
    async (ctx) => {
      await ctx.rawRequest({
        path: "/__test/signup-policy",
        method: "POST",
        json: { operation: "mode", mode: "normal" },
      });
      const owner = ctx.actor("owner", profile);
      const enabled = profile !== "signup-username-display-disabled";
      const signup = await owner.client.signUp.email({
        email: ctx.uniqueEmail("display-projection"),
        password: "password123",
        name: "Display Owner",
        username: "Owner_Name",
        ...(enabled ? { displayUsername: "Shown Owner" } : {}),
      });
      expect(signup.error).toBeNull();
      const canonical = enabled ? "Owner_Name" : "owner_name";
      const signin = await ctx
        .actor("guest", profile)
        .client.signIn.username({ username: canonical, password: "password123" });
      expect(signin.error).toBeNull();
      expect(signin.data?.user.username).toBe(canonical);
      const session = await ctx.actor("guest", profile).client.getSession();
      expect(session.data?.user.id).toBe(signup.data!.user.id);
      for (const user of [signup.data!.user, signin.data!.user, session.data!.user]) {
        if (enabled) expect(user.displayUsername).toBe("Shown Owner");
        else expect(user).not.toHaveProperty("displayUsername");
      }
      const before = await ctx.readUserState({ userId: signup.data!.user.id });
      const wrong = await ctx
        .actor("wrong", profile)
        .client.signIn.username({ username: canonical, password: "wrong-password" });
      expect(wrong.error).toMatchObject({ status: 401, code: "INVALID_USERNAME_OR_PASSWORD" });
      expect(await ctx.readUserState({ userId: signup.data!.user.id })).toEqual(before);
      return ctx.snapshot({ signup, signin, session, wrong, before });
    },
    ["POST /sign-up/email", "POST /sign-in/username", "GET /get-session"],
  );
}
