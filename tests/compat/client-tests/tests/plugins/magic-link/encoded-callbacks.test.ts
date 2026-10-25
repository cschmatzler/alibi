import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";
import { magicLinkClient, readMagicLink } from "./helpers";

// Upstream reference: packages/better-auth/src/plugins/magic-link/magic-link.test.ts :: "magic link callback URL encoding" (1.7.12).
compatScenario(
  "magic-link verify keeps percent-encoded callback query values instead of decoding them twice",
  async (ctx) => {
    const client = magicLinkClient(ctx);
    const email = ctx.uniqueEmail("magic-encoded");
    const encodedQuery =
      "sig=a%2Bb&returnTo=https%3A%2F%2Fexample.com%2Fresume%3Fstate%3Dabc%26step%3D2";
    const verify = async (url: URL) => {
      const response = await ctx.rawRequest({
        path: `${url.pathname}${url.search}`,
        redirect: "manual",
      });
      expect(response.status).toBe(302);
      return response;
    };

    const welcome = await client.signIn.magicLink({
      email,
      callbackURL: "/cb",
      newUserCallbackURL: `/welcome?${encodedQuery}`,
    });
    expect(welcome.error).toBeNull();
    const created = await verify(new URL((await readMagicLink(ctx, email)).url));
    expect(new URL(created.location!, ctx.baseURL).search).toBe(`?${encodedQuery}`);

    const existing = await client.signIn.magicLink({
      email,
      callbackURL: `/cb?${encodedQuery}`,
    });
    expect(existing.error).toBeNull();
    const signedIn = await verify(new URL((await readMagicLink(ctx, email)).url));
    expect(new URL(signedIn.location!, ctx.baseURL).search).toBe(`?${encodedQuery}`);

    const failing = await client.signIn.magicLink({
      email,
      callbackURL: "/cb",
      errorCallbackURL: `/error?${encodedQuery}`,
    });
    expect(failing.error).toBeNull();
    const invalid = new URL((await readMagicLink(ctx, email)).url);
    invalid.searchParams.set("token", "invalid-token");
    const rejected = await verify(invalid);
    const location = new URL(rejected.location!, ctx.baseURL);
    expect(Object.fromEntries(location.searchParams)).toEqual({
      sig: "a+b",
      returnTo: "https://example.com/resume?state=abc&step=2",
      error: "INVALID_TOKEN",
    });

    return {
      welcome: ctx.snapshot(welcome),
      created: ctx.snapshot(created),
      existing: ctx.snapshot(existing),
      signedIn: ctx.snapshot(signedIn),
      failing: ctx.snapshot(failing),
      rejected: ctx.snapshot(rejected),
    };
  },
  ["GET /magic-link/verify"],
);
