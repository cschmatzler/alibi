import { expect } from "bun:test";
import { compatScenario } from "../../../support/scenario";
import { authProfilePath } from "../../../support/profiles";

compatScenario("microsoft published default authorization preserves ordered scopes PKCE and foreign principals", async ctx => {
  const foreign = ctx.actor("foreign"), signup = await foreign.client.signUp.email({ email: ctx.uniqueEmail("foreign"), password: "Password123!", name: "Foreign" });
  expect(signup.error).toBeNull();
  const before = await ctx.rawRequest({ path: "/__test/social-provider/state" }); expect(before.status).toBe(200);
  const result = await ctx.actor("microsoft", "social-microsoft-default").client.signIn.social({ provider: "microsoft", callbackURL: "/dashboard", scopes: ["requested-scope", "openid"], loginHint: "login@example.invalid", additionalParams: { custom: "value with space" } });
  expect(result.error).toBeNull();
  const url = new URL(result.data!.url!);
  expect(url.origin).toBe("https://login.microsoftonline.com"); expect(url.pathname).toBe("/common/oauth2/v2.0/authorize");
  expect(url.searchParams.getAll("scope")).toEqual(["openid profile email User.Read offline_access requested-scope openid"]);
  expect(url.searchParams.getAll("client_id")).toEqual(["fixture-social-client"]);
  expect(url.searchParams.getAll("state")).toHaveLength(1); expect(url.searchParams.get("state")).toBeTruthy();
  expect(url.searchParams.get("response_type")).toBe("code"); expect(url.searchParams.get("code_challenge_method")).toBe("S256"); expect(url.searchParams.get("code_challenge")).toBeTruthy();
  expect(url.searchParams.get("login_hint")).toBe("login@example.invalid"); expect(url.searchParams.get("custom")).toBe("value with space"); expect(url.searchParams.has("nonce")).toBeFalse();
  expect(url.searchParams.get("redirect_uri")).toBe(ctx.baseURL + authProfilePath("social-microsoft-default") + "/callback/microsoft");
  const after = await ctx.rawRequest({ path: "/__test/social-provider/state" }); expect(after.status).toBe(200); expect(after.body).toEqual(before.body);
  const receipts = await ctx.rawRequest({ path: "/__test/microsoft/receipts" }); expect(receipts.status).toBe(200); expect(receipts.body).toEqual([]);
  return { signup: ctx.snapshot(signup), result: ctx.snapshot(result), before: before.body, after: after.body, receipts: receipts.body };
}, ["POST /sign-in/social"]);
