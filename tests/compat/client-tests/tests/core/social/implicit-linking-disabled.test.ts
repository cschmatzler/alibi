import { expect } from "bun:test";

import { SignJWT } from "jose";

import { authProfilePath } from "../../../support/profiles";
import { compatScenario } from "../../../support/scenario";
compatScenario(
  "disabled implicit OAuth linking still permits explicit authenticated linking and returning provider login",
  async (ctx) => {
    const profile = "generic-token-implicit-disabled";
    const owner = ctx.actor("owner", profile);
    const guest = ctx.actor("guest", profile);
    const email = ctx.uniqueEmail("explicit-owner");
    const signup = await owner.client.signUp.email({
      email,
      name: "Local owner",
      password: "password123",
    });
    expect(signup.error).toBeNull();
    const token = await new SignJWT({ email })
      .setProtectedHeader({ alg: "HS256" })
      .setIssuedAt()
      .setExpirationTime("5m")
      .sign(new TextEncoder().encode("compat-test-only-key-not-real-minimum-32chars"));
    expect((await ctx.actor("verifier").client.verifyEmail({ query: { token } })).error).toBeNull();
    const userId = signup.data!.user.id;
    const before = (await ctx.readUserState({ userId })) as any;
    expect(before.user.emailVerified).toBe(true);
    await ctx.rawRequest({
      path: "/__test/generic-token/control",
      method: "POST",
      json: { profile: { id: "explicit-subject", email, name: "Incoming", email_verified: true } },
    });
    const callback = async (actor: typeof owner, url: string) => {
      const state = new URL(url).searchParams.get("state")!;
      const r = await actor.fetch(
        ctx.baseURL +
          authProfilePath(profile) +
          `/callback/generic?code=link-code&state=${encodeURIComponent(state)}`,
        { redirect: "manual" },
      );
      return { status: r.status, location: r.headers.get("location") };
    };
    const implicit = await guest.client.signIn.social({
      provider: "generic",
      callbackURL: "/dashboard",
    });
    expect(implicit.error).toBeNull();
    const denied = await callback(guest, implicit.data!.url!);
    expect(new URL(denied.location!, ctx.baseURL).searchParams.get("error")).toBe(
      "account_not_linked",
    );
    expect(await ctx.readUserState({ userId })).toEqual(before);
    expect((await guest.client.getSession()).data).toBeNull();
    const start = await owner.client.linkSocial({ provider: "generic", callbackURL: "/settings" });
    expect(start.error).toBeNull();
    const linked = await callback(owner, start.data!.url!);
    expect(linked.status).toBe(302);
    expect(new URL(linked.location!, ctx.baseURL).pathname).toBe("/settings");
    const afterLink = (await ctx.readUserState({ userId })) as any;
    expect(afterLink.accounts).toHaveLength(before.accounts.length + 1);
    expect(afterLink.accounts.find((a: any) => a.providerId === "generic")).toMatchObject({
      userId,
      accountId: "explicit-subject",
    });
    expect(afterLink.user).toEqual(before.user);
    expect((await owner.client.getSession()).data!.user.id).toBe(userId);
    const returning = await guest.client.signIn.social({
      provider: "generic",
      callbackURL: "/dashboard",
    });
    expect(returning.error).toBeNull();
    const accepted = await callback(guest, returning.data!.url!);
    expect(new URL(accepted.location!, ctx.baseURL).pathname).toBe("/dashboard");
    const session = await guest.client.getSession();
    expect(session.data!.user.id).toBe(userId);
    const after = (await ctx.readUserState({ userId })) as any;
    expect(after.accounts).toEqual(afterLink.accounts);
    expect(after.sessions).toHaveLength(afterLink.sessions.length + 1);
    return ctx.snapshot({
      signup,
      before,
      denied,
      start,
      linked,
      afterLink,
      accepted,
      session,
      after,
    });
  },
  ["POST /sign-in/social", "POST /link-social", "GET /callback/{}"],
);
