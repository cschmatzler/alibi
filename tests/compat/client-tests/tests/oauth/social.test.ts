import { compatScenario } from "../../support/scenario";

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

function summarizeLocation(location: string | null) {
  if (!location) {
    throw new Error("missing redirect location");
  }
  const url = new URL(location, "http://compat.local");
  return {
    pathname: url.pathname,
    params: Object.fromEntries(url.searchParams.entries()),
  };
}

compatScenario("social sign-in rejects invalid callbackURL", async (ctx) => {
  const primary = ctx.actor();
  const signIn = await primary.client.signIn.social({
    provider: "google",
    callbackURL: "http://malicious.com",
  });

  return {
    signIn: ctx.snapshot(signIn),
  };
});

compatScenario("social sign-in redirects new users to newUserCallbackURL", async (ctx) => {
  const primary = ctx.actor();
  const email = ctx.uniqueEmail("oauth-social-new-user");
  const sub = ctx.uniqueToken("oauth-google-sub");
  await ctx.setSocialProfile({
    email,
    sub,
    name: "Oauth Google User",
    emailVerified: true,
    idTokenValid: true,
  });

  const signIn = await primary.client.signIn.social({
    provider: "google",
    callbackURL: "/dashboard",
    newUserCallbackURL: "/welcome",
  });
  const state = extractState(signIn.data?.url);
  const callback = await ctx.rawRequest({
    path: `/api/auth/callback/google?code=compat-code&state=${encodeURIComponent(state)}`,
    redirect: "manual",
  });
  const session = await primary.client.getSession();

  return {
    signIn: {
      redirect: signIn.data?.redirect,
      hasState: Boolean(state),
    },
    callback: ctx.snapshot(callback),
    session: ctx.snapshot(session),
  };
});

compatScenario("social sign-in redirects existing users to callbackURL", async (ctx) => {
  const primary = ctx.actor();
  const email = ctx.uniqueEmail("oauth-social-existing");
  const sub = ctx.uniqueToken("oauth-google-existing-sub");
  await ctx.setSocialProfile({
    email,
    sub,
    name: "Existing Google User",
    emailVerified: true,
    idTokenValid: true,
  });

  const first = await primary.client.signIn.social({
    provider: "google",
    callbackURL: "/dashboard",
    newUserCallbackURL: "/welcome",
  });
  const firstState = extractState(first.data?.url);
  const firstCallback = await ctx.rawRequest({
    path: `/api/auth/callback/google?code=compat-code&state=${encodeURIComponent(firstState)}`,
    redirect: "manual",
  });
  await primary.client.signOut();

  const second = await primary.client.signIn.social({
    provider: "google",
    callbackURL: "/dashboard",
    newUserCallbackURL: "/welcome",
  });
  const secondState = extractState(second.data?.url);
  const secondCallback = await ctx.rawRequest({
    path: `/api/auth/callback/google?code=compat-code&state=${encodeURIComponent(secondState)}`,
    redirect: "manual",
  });
  const session = await primary.client.getSession();

  return {
    firstCallback: ctx.snapshot(firstCallback),
    secondCallback: ctx.snapshot(secondCallback),
    session: ctx.snapshot(session),
  };
});

compatScenario("social sign-in with idToken returns token and session", async (ctx) => {
  const primary = ctx.actor();
  const email = ctx.uniqueEmail("oauth-social-id-token");
  const sub = ctx.uniqueToken("oauth-google-id-token-sub");
  await ctx.setSocialProfile({
    email,
    sub,
    name: "Google ID Token User",
    emailVerified: true,
    idTokenValid: true,
  });

  const signIn = await primary.client.signIn.social({
    provider: "google",
    callbackURL: "/dashboard",
    idToken: {
      token: "compat-google-id-token",
    },
  });
  const session = await primary.client.getSession();

  return {
    signIn: ctx.snapshot(signIn),
    session: ctx.snapshot(session),
  };
});

compatScenario(
  "social callback POST redirects to GET and preserves TS param precedence",
  async (ctx) => {
    const primary = ctx.actor();
    const email = ctx.uniqueEmail("oauth-social-post-callback");
    const sub = ctx.uniqueToken("oauth-google-post-callback-sub");
    await ctx.setSocialProfile({
      email,
      sub,
      name: "Oauth Google POST Callback User",
      emailVerified: true,
      idTokenValid: true,
    });

    const signIn = await primary.client.signIn.social({
      provider: "google",
      callbackURL: "/dashboard",
    });
    const state = extractState(signIn.data?.url);
    const callbackPost = await ctx.rawRequest({
      path: `/api/auth/callback/google?state=${encodeURIComponent(state)}`,
      method: "POST",
      json: {
        code: "compat-code",
        state: "body-state-should-lose",
      },
      redirect: "manual",
    });
    const redirect = summarizeLocation(callbackPost.location);
    const callbackGet = await ctx.rawRequest({
      path: callbackPost.location ?? "",
      redirect: "manual",
    });
    const session = await primary.client.getSession();

    return {
      callbackPost: {
        status: callbackPost.status,
        locationPath: redirect.pathname,
        usesQueryState: redirect.params.state === state,
        keepsBodyCode: redirect.params.code === "compat-code",
      },
      callbackGet: ctx.snapshot(callbackGet),
      session: ctx.snapshot(session),
    };
  },
);

compatScenario("github social sign-in redirects new users to newUserCallbackURL", async (ctx) => {
  const primary = ctx.actor();
  const email = ctx.uniqueEmail("oauth-github-social-new-user");
  await ctx.setGitHubProfile({
    id: ctx.uniqueToken("oauth-github-id"),
    login: ctx.uniqueToken("oauth-github-login"),
    emails: [
      {
        email,
        primary: true,
        verified: true,
        visibility: "private",
      },
    ],
  });

  const signIn = await primary.client.signIn.social({
    provider: "github",
    callbackURL: "/dashboard",
    newUserCallbackURL: "/welcome",
  });
  const state = extractState(signIn.data?.url);
  const callback = await ctx.rawRequest({
    path: `/api/auth/callback/github?code=compat-code&state=${encodeURIComponent(state)}`,
    redirect: "manual",
  });
  const session = await primary.client.getSession();

  return {
    signIn: {
      redirect: signIn.data?.redirect,
      hasState: Boolean(state),
    },
    callback: ctx.snapshot(callback),
    session: ctx.snapshot(session),
  };
});

compatScenario("github social sign-in redirects existing users to callbackURL", async (ctx) => {
  const primary = ctx.actor();
  const email = ctx.uniqueEmail("oauth-github-social-existing");
  await ctx.setGitHubProfile({
    id: ctx.uniqueToken("oauth-github-existing-id"),
    login: ctx.uniqueToken("oauth-github-existing-login"),
    emails: [
      {
        email,
        primary: true,
        verified: true,
        visibility: "private",
      },
    ],
  });

  const first = await primary.client.signIn.social({
    provider: "github",
    callbackURL: "/dashboard",
    newUserCallbackURL: "/welcome",
  });
  const firstState = extractState(first.data?.url);
  const firstCallback = await ctx.rawRequest({
    path: `/api/auth/callback/github?code=compat-code&state=${encodeURIComponent(firstState)}`,
    redirect: "manual",
  });
  await primary.client.signOut();

  const second = await primary.client.signIn.social({
    provider: "github",
    callbackURL: "/dashboard",
    newUserCallbackURL: "/welcome",
  });
  const secondState = extractState(second.data?.url);
  const secondCallback = await ctx.rawRequest({
    path: `/api/auth/callback/github?code=compat-code&state=${encodeURIComponent(secondState)}`,
    redirect: "manual",
  });
  const session = await primary.client.getSession();

  return {
    firstCallback: ctx.snapshot(firstCallback),
    secondCallback: ctx.snapshot(secondCallback),
    session: ctx.snapshot(session),
  };
});

compatScenario(
  "github social sign-in with unverified fallback email does not link existing user",
  async (ctx) => {
    const primary = ctx.actor();
    const email = ctx.uniqueEmail("oauth-github-unverified");

    await primary.client.signUp.email({
      email,
      password: "password123",
      name: "Credential User",
    });
    await primary.client.signOut();

    await ctx.setGitHubProfile({
      id: ctx.uniqueToken("oauth-github-unverified-id"),
      login: ctx.uniqueToken("oauth-github-unverified-login"),
      emails: [
        {
          email,
          primary: true,
          verified: false,
          visibility: "private",
        },
      ],
    });

    const signIn = await primary.client.signIn.social({
      provider: "github",
      callbackURL: "/dashboard",
    });
    const state = extractState(signIn.data?.url);
    const callback = await ctx.rawRequest({
      path: `/api/auth/callback/github?code=compat-code&state=${encodeURIComponent(state)}`,
      redirect: "manual",
    });
    const session = await primary.client.getSession();

    return {
      signIn: {
        redirect: signIn.data?.redirect,
        hasState: Boolean(state),
      },
      callback: ctx.snapshot(callback),
      session: ctx.snapshot(session),
    };
  },
);

compatScenario(
  "github social sign-in without callbackURL redirects back to app root",
  async (ctx) => {
    const primary = ctx.actor();
    const email = ctx.uniqueEmail("oauth-github-default-callback");
    await ctx.setGitHubProfile({
      id: ctx.uniqueToken("oauth-github-default-id"),
      login: ctx.uniqueToken("oauth-github-default-login"),
      emails: [
        {
          email,
          primary: true,
          verified: true,
          visibility: "private",
        },
      ],
    });

    const signIn = await primary.client.signIn.social({
      provider: "github",
    });
    const state = extractState(signIn.data?.url);
    const callback = await ctx.rawRequest({
      path: `/api/auth/callback/github?code=compat-code&state=${encodeURIComponent(state)}`,
      redirect: "manual",
    });
    const session = await primary.client.getSession();

    return {
      signIn: {
        redirect: signIn.data?.redirect,
        hasState: Boolean(state),
      },
      callback: ctx.snapshot(callback),
      session: ctx.snapshot(session),
    };
  },
);
