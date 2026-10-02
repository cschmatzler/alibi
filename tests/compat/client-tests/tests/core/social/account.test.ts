import { expect } from "bun:test";

import { compatScenario } from "../../../support/scenario";

function extractState(url: string | undefined) {
  if (!url) {
    throw new Error("missing OAuth URL");
  }

  const state = new URL(url).searchParams.get("state");

  if (!state) {
    throw new Error("missing OAuth state");
  }

  return state;
}

compatScenario("link social creates an account that listAccounts returns", async (ctx) => {
  const primary = ctx.actor();
  const email = ctx.uniqueEmail("oauth-link-social");
  const sub = ctx.uniqueToken("oauth-link-sub");
  await ctx.setSocialProfile({
    email,
    sub,
    name: "Linked Google User",
    emailVerified: true,
    idTokenValid: true,
  });

  const signup = await primary.client.signUp.email({
    email,
    password: "password123",
    name: "Credential User",
  });
  const link = await primary.client.linkSocial({
    provider: "google",
    callbackURL: "/settings",
  });
  const state = extractState(link.data?.url);
  const callback = await ctx.rawRequest({
    path: `/api/auth/callback/google?code=compat-code&state=${encodeURIComponent(state)}`,
    redirect: "manual",
  });
  const accounts = await primary.client.listAccounts();

  return {
    signup: ctx.snapshot(signup),
    link: {
      redirect: link.data?.redirect,
      hasState: Boolean(state),
    },
    callback: ctx.snapshot(callback),
    accounts: ctx.snapshot(accounts),
  };
});

compatScenario("unlink account removes the linked google account", async (ctx) => {
  const primary = ctx.actor();
  const email = ctx.uniqueEmail("oauth-unlink-social");
  const sub = ctx.uniqueToken("oauth-unlink-sub");
  await ctx.setSocialProfile({
    email,
    sub,
    name: "Unlink Google User",
    emailVerified: true,
    idTokenValid: true,
  });

  await primary.client.signUp.email({
    email,
    password: "password123",
    name: "Credential User",
  });
  const link = await primary.client.linkSocial({
    provider: "google",
    callbackURL: "/settings",
  });
  const state = extractState(link.data?.url);
  await ctx.rawRequest({
    path: `/api/auth/callback/google?code=compat-code&state=${encodeURIComponent(state)}`,
    redirect: "manual",
  });

  const before = await primary.client.listAccounts();
  const googleAccount = before.data?.find((account) => account.providerId === "google");

  if (!googleAccount?.id) {
    throw new Error("missing google account after link");
  }

  const unlink = await primary.client.unlinkAccount({
    accountId: googleAccount.id,
  });
  expect(unlink.error).toBeNull();
  expect(unlink.data?.status).toBe(true);

  const after = await primary.client.listAccounts();

  return {
    before: ctx.snapshot(before),
    unlink: ctx.snapshot(unlink),
    after: ctx.snapshot(after),
  };
});

compatScenario("link social with idToken adds a google account", async (ctx) => {
  const primary = ctx.actor();
  const email = ctx.uniqueEmail("oauth-link-id-token");
  const sub = ctx.uniqueToken("oauth-link-id-token-sub");
  await ctx.setSocialProfile({
    email,
    sub,
    name: "Link ID Token User",
    emailVerified: true,
    idTokenValid: true,
  });

  await primary.client.signUp.email({
    email,
    password: "password123",
    name: "Credential User",
  });

  const link = await primary.client.linkSocial({
    provider: "google",
    callbackURL: "/settings",
    idToken: {
      token: "compat-google-id-token",
    },
  });
  const accounts = await primary.client.listAccounts();

  return {
    link: ctx.snapshot(link),
    accounts: ctx.snapshot(accounts),
  };
});

compatScenario("github link social creates an account that listAccounts returns", async (ctx) => {
  const primary = ctx.actor();
  const email = ctx.uniqueEmail("oauth-github-link-social");
  await ctx.setGitHubProfile({
    id: ctx.uniqueToken("oauth-github-link-id"),
    login: ctx.uniqueToken("oauth-github-link-login"),
    emails: [
      {
        email,
        primary: true,
        verified: true,
        visibility: "private",
      },
    ],
  });

  const signup = await primary.client.signUp.email({
    email,
    password: "password123",
    name: "Credential User",
  });
  const link = await primary.client.linkSocial({
    provider: "github",
    callbackURL: "/settings",
  });
  const state = extractState(link.data?.url);
  const callback = await ctx.rawRequest({
    path: `/api/auth/callback/github?code=compat-code&state=${encodeURIComponent(state)}`,
    redirect: "manual",
  });
  const accounts = await primary.client.listAccounts();

  return {
    signup: ctx.snapshot(signup),
    link: {
      redirect: link.data?.redirect,
      hasState: Boolean(state),
    },
    callback: ctx.snapshot(callback),
    accounts: ctx.snapshot(accounts),
  };
});

compatScenario("github unlink account removes the linked github account", async (ctx) => {
  const primary = ctx.actor();
  const email = ctx.uniqueEmail("oauth-github-unlink-social");
  await ctx.setGitHubProfile({
    id: ctx.uniqueToken("oauth-github-unlink-id"),
    login: ctx.uniqueToken("oauth-github-unlink-login"),
    emails: [
      {
        email,
        primary: true,
        verified: true,
        visibility: "private",
      },
    ],
  });

  await primary.client.signUp.email({
    email,
    password: "password123",
    name: "Credential User",
  });
  const link = await primary.client.linkSocial({
    provider: "github",
    callbackURL: "/settings",
  });
  const state = extractState(link.data?.url);
  await ctx.rawRequest({
    path: `/api/auth/callback/github?code=compat-code&state=${encodeURIComponent(state)}`,
    redirect: "manual",
  });

  const before = await primary.client.listAccounts();
  const githubAccount = before.data?.find((account) => account.providerId === "github");

  if (!githubAccount?.id) {
    throw new Error("missing github account after link");
  }

  const unlink = await primary.client.unlinkAccount({
    accountId: githubAccount.id,
  });
  expect(unlink.error).toBeNull();
  expect(unlink.data?.status).toBe(true);

  const after = await primary.client.listAccounts();

  return {
    before: ctx.snapshot(before),
    unlink: ctx.snapshot(unlink),
    after: ctx.snapshot(after),
  };
});
