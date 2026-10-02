import { expect } from "bun:test";

import { compatScenario } from "../../../support/scenario";

compatScenario("get access token returns stored unexpired token", async (ctx) => {
  const primary = ctx.actor();
  const email = ctx.uniqueEmail("core-oauth-valid");

  const signup = await primary.client.signUp.email({
    email,
    password: "password123",
    name: "OAuth Access User",
  });
  const accountId = await ctx.seedOAuthAccount({
    email,
    accessToken: "still-valid-access-token",
    refreshToken: "seed-refresh-token",
    accessTokenExpiresAt: "2099-01-01T00:00:00Z",
    refreshTokenExpiresAt: "2099-01-01T00:00:00Z",
  });

  const accessToken = await primary.client.getAccessToken({
    accountId,
  });
  expect(accessToken.error).toBeNull();
  expect(accessToken.data?.accessToken).toBe("still-valid-access-token");

  return {
    signup: ctx.snapshot(signup),
    accessToken: ctx.snapshot(accessToken),
  };
});

compatScenario("get access token refreshes expired token", async (ctx) => {
  const primary = ctx.actor();
  const email = ctx.uniqueEmail("core-oauth-refresh");

  const signup = await primary.client.signUp.email({
    email,
    password: "password123",
    name: "OAuth Refresh User",
  });
  const accountId = await ctx.seedOAuthAccount({
    email,
    accessToken: "stale-access-token",
    refreshToken: "seed-refresh-token",
    accessTokenExpiresAt: "2000-01-01T00:00:00Z",
    refreshTokenExpiresAt: "2099-01-01T00:00:00Z",
  });

  const accessToken = await primary.client.getAccessToken({
    accountId,
  });
  expect(accessToken.error).toBeNull();
  expect(accessToken.data?.accessToken).toBe("new-access-token");

  return {
    signup: ctx.snapshot(signup),
    accessToken: ctx.snapshot(accessToken),
  };
});

compatScenario("refresh token returns a fresh token set", async (ctx) => {
  const primary = ctx.actor();
  const email = ctx.uniqueEmail("core-refresh-token");

  const signup = await primary.client.signUp.email({
    email,
    password: "password123",
    name: "Refresh Token User",
  });
  const accountId = await ctx.seedOAuthAccount({
    email,
    accessToken: "stale-access-token",
    refreshToken: "seed-refresh-token",
    accessTokenExpiresAt: "2000-01-01T00:00:00Z",
    refreshTokenExpiresAt: "2099-01-01T00:00:00Z",
  });

  const refresh = await primary.client.refreshToken({
    accountId,
  });
  expect(refresh.error).toBeNull();
  expect(refresh.data?.accessToken).toBe("new-access-token");

  return {
    signup: ctx.snapshot(signup),
    refresh: ctx.snapshot(refresh),
  };
});

compatScenario("refresh token surfaces provider refresh failure", async (ctx) => {
  const primary = ctx.actor();
  const email = ctx.uniqueEmail("core-refresh-fail");

  const signup = await primary.client.signUp.email({
    email,
    password: "password123",
    name: "Refresh Failure User",
  });
  const accountId = await ctx.seedOAuthAccount({
    email,
    accessToken: "stale-access-token",
    refreshToken: "seed-refresh-token",
    accessTokenExpiresAt: "2000-01-01T00:00:00Z",
    refreshTokenExpiresAt: "2099-01-01T00:00:00Z",
  });
  await ctx.setOAuthRefreshMode("error");

  const refresh = await primary.client.refreshToken({
    accountId,
  });
  expect(refresh.error?.code).toBe("FAILED_TO_REFRESH_ACCESS_TOKEN");

  return {
    signup: ctx.snapshot(signup),
    refresh: ctx.snapshot(refresh),
  };
});

compatScenario(
  "account token routes reject conflicting and foreign account selectors",
  async (ctx) => {
    const primary = ctx.actor();
    const email = ctx.uniqueEmail("core-conflicting-selectors");
    await primary.client.signUp.email({
      email,
      password: "password123",
      name: "Account Selector User",
    });
    const accountId = await ctx.seedOAuthAccount({ email });
    await ctx.actor("other").client.signUp.email({
      email: ctx.uniqueEmail("core-other-account-owner"),
      password: "password123",
      name: "Other Account Owner",
    });
    const responses = [];

    for (const route of ["get-access-token", "refresh-token"]) {
      for (const json of [
        { accountId, useAccountCookie: true },
        { accountId, providerId: "mock" },
      ]) {
        const response = await ctx.rawRequest({ path: `/api/auth/${route}`, method: "POST", json });
        expect(response.status).toBe(400);
        expect((response.body as { code: string }).code).toBe("VALIDATION_ERROR");

        responses.push(response);
      }

      const foreign = await ctx.rawRequest({
        actor: "other",
        path: `/api/auth/${route}`,
        method: "POST",
        json: { accountId },
      });
      expect(foreign.status).toBe(400);
      expect((foreign.body as { code: string }).code).toBe("ACCOUNT_NOT_FOUND");

      responses.push(foreign);
    }

    return responses;
  },
);
