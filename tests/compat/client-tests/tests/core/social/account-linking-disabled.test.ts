import { expect } from "bun:test";

import { authProfilePath } from "../../../support/profiles";
import { compatScenario } from "../../../support/scenario";
compatScenario(
  "disabled account linking allows first social signup and exact returning binding but denies new implicit and explicit links",
  async (ctx) => {
    const profile = "generic-token-linking-disabled";
    const owner = ctx.actor("owner", profile);
    const guest = ctx.actor("guest", profile);
    const email = ctx.uniqueEmail("disabled-owner");
    const select = async (id: string) =>
      ctx.rawRequest({
        path: "/__test/generic-token/control",
        method: "POST",
        json: { profile: { id, email, name: "Social owner", email_verified: true } },
      });
    const callback = async (actor: typeof owner, url: string) => {
      const state = new URL(url).searchParams.get("state")!;
      const r = await actor.fetch(
        ctx.baseURL +
          authProfilePath(profile) +
          `/callback/generic?code=real-code&state=${encodeURIComponent(state)}`,
        { redirect: "manual" },
      );
      return { status: r.status, location: r.headers.get("location")! };
    };
    await select("first-subject");
    const first = await owner.client.signIn.social({
      provider: "generic",
      callbackURL: "/dashboard",
    });
    expect(first.error).toBeNull();
    const created = await callback(owner, first.data!.url!);
    expect(created.location).toBe("/dashboard");
    const session = await owner.client.getSession();
    expect(session.data!.user.email).toBe(email);
    expect(session.data!.user.emailVerified).toBe(true);
    const userId = session.data!.user.id;
    const before = (await ctx.readUserState({ userId })) as any;
    expect(before.accounts).toHaveLength(1);
    await select("incoming-subject");
    const implicit = await guest.client.signIn.social({
      provider: "generic",
      callbackURL: "/dashboard",
    });
    expect(implicit.error).toBeNull();
    const denied = await callback(guest, implicit.data!.url!);
    expect(new URL(denied.location, ctx.baseURL).searchParams.get("error")).toBe(
      "account_not_linked",
    );
    expect(await ctx.readUserState({ userId })).toEqual(before);
    const explicit = await owner.client.linkSocial({
      provider: "generic",
      callbackURL: "/settings",
    });
    expect(explicit.error).toBeNull();
    const explicitDenied = await callback(owner, explicit.data!.url!);
    expect(new URL(explicitDenied.location, ctx.baseURL).searchParams.get("error")).toBe(
      "unable_to_link_account",
    );
    expect(await ctx.readUserState({ userId })).toEqual(before);
    const unlink = await owner.client.unlinkAccount({
      accountId: before.accounts[0].id,
    });
    expect(unlink.error!.code).toBe("FAILED_TO_UNLINK_LAST_ACCOUNT");
    expect(await ctx.readUserState({ userId })).toEqual(before);
    await select("first-subject");
    const returning = await guest.client.signIn.social({
      provider: "generic",
      callbackURL: "/dashboard",
    });
    expect(returning.error).toBeNull();
    const accepted = await callback(guest, returning.data!.url!);
    expect(accepted.location).toBe("/dashboard");
    const returned = await guest.client.getSession();
    expect(returned.data!.user.id).toBe(userId);
    const after = (await ctx.readUserState({ userId })) as any;
    expect(after.accounts).toEqual(before.accounts);
    expect(after.sessions).toHaveLength(before.sessions.length + 1);
    return ctx.snapshot({
      created,
      session,
      before,
      denied,
      explicitDenied,
      unlink,
      accepted,
      returned,
      after,
    });
  },
  ["POST /sign-in/social", "POST /link-social", "GET /callback/{}", "POST /unlink-account"],
);
