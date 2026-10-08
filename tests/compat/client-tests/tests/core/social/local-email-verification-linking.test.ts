import { expect } from "bun:test";

import { SignJWT } from "jose";

import { authProfilePath } from "../../../support/profiles";
import { compatScenario } from "../../../support/scenario";
for (const verified of [false, true]) {
  compatScenario(
    `implicit OAuth linking requires local email verification: ${verified}`,
    async (ctx) => {
      const profile = "generic-token-local-verified";
      const owner = ctx.actor("owner", profile);
      const email = ctx.uniqueEmail("local-owner");
      const signup = await owner.client.signUp.email({
        email,
        name: "Local owner",
        password: "password123",
      });
      expect(signup.error).toBeNull();
      expect(signup.data!.user.emailVerified).toBe(false);
      if (verified) {
        const token = await new SignJWT({ email })
          .setProtectedHeader({ alg: "HS256" })
          .setIssuedAt()
          .setExpirationTime("5m")
          .sign(new TextEncoder().encode("compat-test-only-key-not-real-minimum-32chars"));
        const proof = await ctx
          .actor("verifier", "user-lifecycle-auto")
          .client.verifyEmail({ query: { token } });
        expect(proof.error).toBeNull();
      }
      const before = await ctx.readUserState({ userId: signup.data!.user.id });
      expect((before as any).user.emailVerified).toBe(verified);
      await ctx.rawRequest({
        path: "/__test/generic-token/control",
        method: "POST",
        json: {
          profile: { id: "incoming-subject", email, name: "Provider owner", email_verified: true },
        },
      });
      const guest = ctx.actor("guest", profile);
      const start = await guest.client.signIn.social({
        provider: "generic",
        callbackURL: "/dashboard",
      });
      expect(start.error).toBeNull();
      const state = new URL(start.data!.url!).searchParams.get("state")!;
      const callback = await guest.fetch(
        ctx.baseURL +
          authProfilePath(profile) +
          `/callback/generic?code=link-code&state=${encodeURIComponent(state)}`,
        { redirect: "manual" },
      );
      expect(callback.status).toBe(302);
      const location = callback.headers.get("location")!;
      const after = await ctx.readUserState({ userId: signup.data!.user.id });
      const session = await guest.client.getSession();
      if (verified) {
        expect(location).toBe("/dashboard");
        expect(session.data!.user.id).toBe(signup.data!.user.id);
        expect((after as any).accounts).toHaveLength((before as any).accounts.length + 1);
        expect((after as any).accounts.find((a: any) => a.providerId === "generic")).toMatchObject({
          userId: signup.data!.user.id,
          accountId: "incoming-subject",
        });
        expect((after as any).sessions).toHaveLength((before as any).sessions.length + 1);
      } else {
        expect(new URL(location, ctx.baseURL).searchParams.get("error")).toBe("account_not_linked");
        expect(after).toEqual(before);
        expect(session.data).toBeNull();
      }
      return ctx.snapshot({
        signup,
        before,
        callback: { status: callback.status, location },
        after,
        session,
      });
    },
    ["POST /sign-in/social", "GET /callback/{}"],
  );
}
