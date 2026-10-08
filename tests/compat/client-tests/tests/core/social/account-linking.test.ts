import { expect } from "bun:test";

import { authProfilePath } from "../../../support/profiles";
import { compatScenario, type ScenarioContext } from "../../../support/scenario";

const profile = "account-linking-different-emails";

type Row = Record<string, unknown>;

type UserState = {
  user: Row | null;
  accounts: Row[];
  sessions: Row[];
};

async function completeGoogleCallback(
  actor: ReturnType<ScenarioContext["actor"]>,
  url: string,
  callbackURL: string,
) {
  const state = new URL(url).searchParams.get("state");
  expect(state).toBeTruthy();

  const response = await actor.fetch(
    `${authProfilePath(profile)}/callback/google?${new URLSearchParams({ code: "compat-code", state: state! })}`,
    { redirect: "manual" },
  );
  return {
    status: response.status,
    location: response.headers.get("location"),
    expected: callbackURL,
  };
}

compatScenario(
  "accountLinking.allowDifferentEmails links, unlinks and relinks a different provider email",
  async (ctx) => {
    const actor = ctx.actor("linker", profile);
    const email = ctx.uniqueEmail("account-linking-local");
    const signup = await actor.client.signUp.email({
      email,
      password: "password123",
      name: "Linking Local User",
    });
    expect(signup.error).toBeNull();

    // A second stored account keeps the default last-account unlink rejection
    // out of the way while the policy under test stays disabled.
    const seeded = await ctx.seedOAuthAccount({
      email,
      providerId: "github",
      accountId: ctx.uniqueToken("account-linking-github-sub"),
    });

    const providerEmail = ctx.uniqueEmail("account-linking-provider");
    await ctx.setSocialProfile({
      sub: ctx.uniqueToken("account-linking-google-sub"),
      email: providerEmail,
      name: "Provider Email User",
      emailVerified: true,
      idTokenValid: true,
    });

    const link = await actor.client.linkSocial({
      provider: "google",
      callbackURL: "/different-email-linked",
      disableRedirect: true,
    });
    expect(link.error).toBeNull();

    const linked = await completeGoogleCallback(actor, link.data!.url!, "/different-email-linked");
    expect(linked).toMatchObject({ status: 302, location: "/different-email-linked" });

    const session = await actor.client.getSession();
    expect(session.data?.user.email).toEqual(email);

    const accounts = await actor.client.listAccounts();
    expect(accounts.data!.map((row) => row.providerId).sort()).toEqual([
      "credential",
      "github",
      "google",
    ]);

    const before = (await ctx.readUserState({ userId: signup.data!.user.id })) as UserState;
    const google = before.accounts.find((row) => row.providerId === "google");
    expect(google).toBeTruthy();

    const unlink = await actor.client.unlinkAccount({
      accountId: String(google!.id),
    });
    expect(unlink.data).toEqual({ status: true });

    const afterUnlink = (await ctx.readUserState({
      userId: signup.data!.user.id,
    })) as UserState;
    expect(afterUnlink.accounts.map((row) => row.providerId).sort()).toEqual(["credential", "github"]);

    const relink = await actor.client.linkSocial({
      provider: "google",
      callbackURL: "/different-email-relinked",
      disableRedirect: true,
    });
    expect(relink.error).toBeNull();

    const relinked = await completeGoogleCallback(
      actor,
      relink.data!.url!,
      "/different-email-relinked",
    );
    expect(relinked).toMatchObject({ status: 302, location: "/different-email-relinked" });

    const afterRelink = (await ctx.readUserState({
      userId: signup.data!.user.id,
    })) as UserState;
    expect(afterRelink.accounts.map((row) => row.providerId).sort()).toEqual(["credential", "github", "google"]);

    return {
      signup: ctx.snapshot(signup),
      seeded: true,
      providerEmail,
      link: ctx.snapshot(link),
      linked,
      session: ctx.snapshot(session),
      accounts: ctx.snapshot(accounts),
      unlink: ctx.snapshot(unlink),
      afterUnlink,
      relinked,
      afterRelink,
    };
  },
  ["POST /link-social", "GET /list-accounts", "POST /unlink-account"],
);
