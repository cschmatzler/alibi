import { expect } from "bun:test";

import { compatScenario } from "../../../support/scenario";
import { signUpAndPromoteAdmin } from "./helpers";
compatScenario(
  "admin email collision rejects case variants without transferring identity or credentials",
  async (ctx) => {
    const admin = await signUpAndPromoteAdmin(ctx);
    expect(admin.signup.error).toBeNull();
    const owners: {
      email: string;
      password: string;
      signup: Awaited<ReturnType<typeof admin.client.signUp.email>>;
    }[] = [];
    for (const label of ["a", "b"]) {
      const email = ctx.uniqueEmail("collision-" + label);
      const password = "password-" + label + "123";
      const signup = await ctx
        .actor(label)
        .client.signUp.email({ email, password, name: "Owner " + label });
      expect(signup.error).toBeNull();
      owners.push({ email, password, signup });
    }
    const read = async () =>
      Promise.all(owners.map((o) => ctx.readUserState({ userId: o.signup.data!.user.id })));
    const before = await read();
    const denied = [];
    for (const email of [owners[1]!.email, owners[1]!.email.toUpperCase()]) {
      const result = await admin.adminClient.admin.updateUser({
        userId: owners[0]!.signup.data!.user.id,
        data: { email, name: "must-not-commit" },
      });
      expect(result.error).toMatchObject({
        status: 400,
        code: "USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL",
      });
      expect(await read()).toEqual(before);
      denied.push(result);
    }
    const controls = [];
    for (const [index, owner] of owners.entries()) {
      const signin = await ctx
        .actor("retry-" + index)
        .client.signIn.email({ email: owner.email, password: owner.password });
      expect(signin.error).toBeNull();
      expect(signin.data!.user.id).toBe(owner.signup.data!.user.id);
      expect(signin.data!.user.name).toBe("Owner " + (index === 0 ? "a" : "b"));
      controls.push(signin);
    }
    return ctx.snapshot({ owners: owners.map((o) => o.signup), before, denied, controls });
  },
  ["POST /admin/update-user", "POST /sign-in/email"],
);
