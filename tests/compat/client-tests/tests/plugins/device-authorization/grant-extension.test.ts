import { expect } from "bun:test";

import { compatScenario } from "../../../support/scenario";
type Context = Parameters<Parameters<typeof compatScenario>[1]>[0];
function actor(ctx: Context, name = "owner") {
  return ctx.actor(name, "device-grant").client;
}
async function state(ctx: Context, code: string) {
  return (
    await ctx.rawRequest({
      path: `/__test/device-grant/control?deviceCode=${encodeURIComponent(code)}`,
    })
  ).body as any;
}
async function issue(ctx: Context, owner: ReturnType<typeof actor>, nonce: string) {
  const result = await owner.$fetch<any>("/device/code", {
    method: "POST",
    body: { audience: "application-api", nonce, scope: "read" },
  });
  expect(result.error).toBeNull();
  const row = (await state(ctx, result.data.device_code)).rows[0];
  expect(row).toMatchObject({
    deviceCode: result.data.device_code,
    clientId: "application-client",
    audience: "application-api",
    nonce,
    status: "pending",
  });
  return result;
}
compatScenario(
  "device grant request validation and OpenAPI extensions reflect the configured protocol",
  async (ctx) => {
    const owner = actor(ctx);
    const missing = await owner.$fetch<any>("/device/code", {
      method: "POST",
      body: { nonce: "valid-nonce" },
    });
    expect(missing.error).toMatchObject({ status: 400, error: "application_invalid_request" });
    const denied = await owner.$fetch<any>("/device/code", {
      method: "POST",
      body: { audience: "foreign-api", nonce: "valid-nonce" },
    });
    expect(denied.error).toMatchObject({ status: 422, error: "invalid_audience" });
    const empty = await state(ctx, "absent");
    expect(empty.rows).toEqual([]);
    expect(empty.events).toEqual([
      { phase: "validation", issueCount: 1 },
      { phase: "authorize", audience: "foreign-api", nonce: "valid-nonce" },
    ]);
    const schema = await owner.$fetch<any>("/open-api/generate-schema", { method: "GET" });
    expect(schema.error).toBeNull();
    const request = schema.data.paths["/device/code"].post;
    expect(request.responses["422"].description).toBe("Application audience rejected");
    expect(request.requestBody.content["application/json"].schema.properties).toHaveProperty(
      "audience",
    );
    const verification =
      schema.data.paths["/device"].get.responses["200"].content["application/json"].schema
        .properties;
    expect(verification).toHaveProperty("audience");
    expect(verification).toHaveProperty("nonce");
    return ctx.snapshot({
      missing,
      denied,
      empty,
      requestFields: Object.keys(
        request.requestBody.content["application/json"].schema.properties,
      ).sort(),
      verificationFields: Object.keys(verification).sort(),
    });
  },
  ["POST /device/code", "GET /open-api/generate-schema"],
);
compatScenario(
  "device grant fields survive owner review and atomic application redemption with replay denial",
  async (ctx) => {
    const owner = actor(ctx);
    const signup = await owner.signUp.email({
      email: ctx.uniqueEmail("grant-owner"),
      password: "password123",
      name: "Grant owner",
    });
    expect(signup.error).toBeNull();
    const nonce = "application-owned-nonce";
    const issued = await issue(ctx, owner, nonce);
    const code = issued.data.device_code;
    const guest = actor(ctx, "guest");
    const guestView = await guest.$fetch<any>("/device", {
      method: "GET",
      query: { user_code: issued.data.user_code },
    });
    expect(guestView.data).not.toHaveProperty("audience");
    const review = await owner.$fetch<any>("/device", {
      method: "GET",
      query: { user_code: issued.data.user_code },
    });
    expect(review.data).toMatchObject({ audience: "application-api", nonce });
    const approve = await owner.$fetch<any>("/device/approve", {
      method: "POST",
      body: { userCode: issued.data.user_code },
    });
    expect(approve.error).toBeNull();
    const standalone = await owner.$fetch<any>("/device/token", {
      method: "POST",
      body: {
        grant_type: "urn:ietf:params:oauth:grant-type:device_code",
        device_code: code,
        client_id: "application-client",
      },
    });
    expect(standalone.error).toMatchObject({ status: 400, error: "invalid_grant" });
    expect((await state(ctx, code)).rows).toHaveLength(1);
    const completed = await owner.$fetch<any>("/device/application-token", {
      method: "POST",
      body: { device_code: code, claimNonce: nonce },
    });
    expect(completed.data).toEqual({
      userId: signup.data!.user.id,
      audience: "application-api",
      nonce,
    });
    const after = await state(ctx, code);
    expect(after.rows).toEqual([]);
    expect(after.receipts).toHaveLength(1);
    expect(after.receipts[0]).toMatchObject({
      userId: signup.data!.user.id,
      audience: "application-api",
    });
    const replay = await owner.$fetch<any>("/device/application-token", {
      method: "POST",
      body: { device_code: code, claimNonce: nonce },
    });
    expect(replay.error).toMatchObject({ status: 400, error: "invalid_grant" });
    expect((await state(ctx, code)).receipts).toEqual(after.receipts);
    expect(after.events.map((event: any) => event.phase)).toEqual([
      "authorize",
      "verification",
      "session-redemption",
      "redemption-authorize",
      "prepare",
      "completed",
    ]);
    return ctx.snapshot({
      signup,
      issued,
      guestView,
      review,
      approve,
      standalone,
      completed,
      after,
      replay,
    });
  },
  ["POST /device/code", "GET /device", "POST /device/approve", "POST /device/token"],
);
compatScenario(
  "device grant preparation rejection, nil claim and expiry never emit completion receipts",
  async (ctx) => {
    const owner = actor(ctx);
    expect(
      (
        await owner.signUp.email({
          email: ctx.uniqueEmail("grant-denied"),
          password: "password123",
          name: "Grant control",
        })
      ).error,
    ).toBeNull();
    const nonce = "application-denial-nonce";
    const issued = await issue(ctx, owner, nonce);
    const code = issued.data.device_code;
    await owner.$fetch("/device", { method: "GET", query: { user_code: issued.data.user_code } });
    expect(
      (
        await owner.$fetch("/device/approve", {
          method: "POST",
          body: { userCode: issued.data.user_code },
        })
      ).error,
    ).toBeNull();
    const prepare = await owner.$fetch<any>("/device/application-token", {
      method: "POST",
      body: { device_code: code, claimNonce: nonce, prepareFailure: true },
    });
    expect(prepare.error).toMatchObject({ status: 403, code: "APPLICATION_PREPARE_REJECTED" });
    expect((await state(ctx, code)).rows).toHaveLength(1);
    const nilClaim = await owner.$fetch<any>("/device/application-token", {
      method: "POST",
      body: { device_code: code, claimNonce: "different-owner-nonce" },
    });
    expect(nilClaim.error).toMatchObject({ status: 400, error: "invalid_grant" });
    expect((await state(ctx, code)).rows).toHaveLength(1);
    expect((await state(ctx, code)).receipts).toEqual([]);
    const expiredAt = new Date(Date.now() - 60000).toISOString();
    const expire = await ctx.rawRequest({
      path: `/__test/device-grant/control?deviceCode=${encodeURIComponent(code)}`,
      method: "POST",
      json: { deviceCode: code, expiresAt: expiredAt },
    });
    expect(expire.status).toBe(200);
    const expired = await owner.$fetch<any>("/device/application-token", {
      method: "POST",
      body: { device_code: code, claimNonce: nonce },
    });
    expect(expired.error).toMatchObject({ status: 400, error: "expired_token" });
    const after = await state(ctx, code);
    expect(after.rows).toEqual([]);
    expect(after.receipts).toEqual([]);
    return ctx.snapshot({ issued, prepare, nilClaim, expired, after });
  },
  ["POST /device/code", "POST /device/approve"],
);
