import { expect } from "bun:test";
import { createAuthClient } from "better-auth/client";
import { twoFactorClient } from "better-auth/client/plugins";
import type { ScenarioContext } from "../../support/scenario";
import { authProfilePath } from "../../support/profiles";

/** Actual schema rejection must precede authoritative session lookup. */
export async function disableGuestValidation(ctx: ScenarioContext, profile?: "two-factor-passwordless") {
  const path = profile ? authProfilePath(profile) : "/api/auth";
  const malformed = await ctx.rawRequest({
    actor: "disable-schema-guest", path: `${path}/two-factor/disable`, method: "POST", json: { password: null },
  });
  expect(malformed).toMatchObject({ status: 400, body: {
    code: "VALIDATION_ERROR", message: "[body.password] Invalid input: expected string, received null",
  } });
  const missing = await ctx.rawRequest({
    actor: "disable-schema-guest", path: `${path}/two-factor/disable`, method: "POST", json: {},
  });
  expect(missing).toMatchObject(profile ? { status: 401, body: {
    code: "UNAUTHORIZED", message: "Unauthorized",
  } } : { status: 400, body: {
    code: "VALIDATION_ERROR", message: "[body.password] Invalid input: expected string, received undefined",
  } });
  const client = createAuthClient({baseURL: profile ? `${ctx.baseURL}${path}` : ctx.baseURL,
    plugins: [twoFactorClient()], fetchOptions: {customFetchImpl:ctx.actor("disable-sdk-guest",profile).fetch}});
  const valid = await client.twoFactor.disable({password:"password123"});
  expect(valid.error).toMatchObject({status:401,code:"UNAUTHORIZED",message:"Unauthorized"});
  return {malformed,missing,valid};
}
