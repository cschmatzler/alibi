import { expect } from "bun:test";

import { SignJWT } from "jose";

import { compatScenario } from "../../../support/scenario";

compatScenario(
  "verification accepts signed proof without time claims and ignores arbitrary audience",
  async (ctx) => {
    const foreign = ctx.actor("foreign");
    const foreignSignup = await foreign.client.signUp.email({
      email: ctx.uniqueEmail("optional-claims-foreign"),
      password: "password123",
      name: "Foreign owner",
    });
    expect(foreignSignup.error).toBeNull();
    const foreignBefore = await ctx.readUserState({ userId: foreignSignup.data!.user.id });
    const observations = [];
    for (const mode of ["optional-claims", "delivered-control"] as const) {
      const owner = ctx.actor(mode);
      const email = ctx.uniqueEmail(mode);
      const signup = await owner.client.signUp.email({
        email,
        password: "password123",
        name: "Proof owner",
      });
      expect(signup.error).toBeNull();
      const before: any = await ctx.readUserState({ userId: signup.data!.user.id });
      expect(before.user.emailVerified).toBe(false);
      let proof: string;
      if (mode === "optional-claims") {
        proof = await new SignJWT({ email, aud: "unrelated-application-audience" })
          .setProtectedHeader({ alg: "HS256" })
          .sign(new TextEncoder().encode("compat-test-only-key-not-real-minimum-32chars"));
        const claims = JSON.parse(Buffer.from(proof.split(".")[1]!, "base64url").toString());
        expect(claims).toEqual({ email, aud: "unrelated-application-audience" });
      } else {
        expect((await owner.client.sendVerificationEmail({ email })).error).toBeNull();
        proof = ((await ctx.readVerificationEmail({ email })) as { token: string }).token;
        expect(proof).toBeString();
      }
      const guest = ctx.actor(`${mode}-guest`);
      let cookies: string[] = [];
      const verified = await guest.client.verifyEmail({
        query: { token: proof },
        fetchOptions: {
          onResponse({ response }) {
            cookies = response.headers.getSetCookie();
          },
        },
      });
      expect(verified.error).toBeNull();
      expect(cookies.filter((cookie) => cookie.startsWith("better-auth.session"))).toEqual([]);
      const after: any = await ctx.readUserState({ userId: signup.data!.user.id });
      expect(after.user).toEqual({ ...before.user, emailVerified: true });
      expect(after.accounts).toEqual(before.accounts);
      expect(after.sessions).toEqual(before.sessions);
      const session = await guest.client.getSession();
      expect(session.data).toBeNull();
      observations.push(ctx.snapshot({ verified, cookies, session, before, after }));
    }
    expect(await ctx.readUserState({ userId: foreignSignup.data!.user.id })).toEqual(foreignBefore);
    return { observations, foreign: ctx.snapshot(foreignBefore) };
  },
  ["GET /verify-email", "POST /send-verification-email", "GET /get-session"],
);
