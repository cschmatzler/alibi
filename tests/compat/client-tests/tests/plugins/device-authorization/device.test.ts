import { expect } from "bun:test";

import { createAuthClient } from "better-auth/client";
import { deviceAuthorizationClient } from "better-auth/client/plugins";
import { z } from "zod";

import type { FixtureProfile } from "../../../support/profiles";
import { compatScenario } from "../../../support/scenario";

const DEVICE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:device_code";

type Context = Parameters<Parameters<typeof compatScenario>[1]>[0];

const deviceState = z.object({
  id: z.string(),
  deviceCode: z.string(),
  userCode: z.string(),
  userId: z.string().nullable(),
  status: z.string(),
  clientId: z.string().nullable(),
  scope: z.string().nullable(),
  expiresAt: z.string(),
  lastPolledAt: z.string().nullable(),
  pollingInterval: z.number().nullable(),
});

function deviceActor(ctx: Context, name = "primary", profile?: FixtureProfile) {
  return createAuthClient({
    baseURL: ctx.baseURL,
    plugins: [deviceAuthorizationClient()],
    fetchOptions: { customFetchImpl: ctx.actor(name, profile).fetch },
  });
}

async function requestCode(ctx: Context, scope?: string) {
  const result = await deviceActor(ctx, "device").device.code({
    client_id: "compat-device-client",
    ...(scope === undefined ? {} : { scope }),
  });
  expect(result.error).toBeNull();

  if (!result.data) {
    throw new Error("device issuance must return codes");
  }

  return result.data;
}

async function signUpOwner(ctx: Context, prefix: string) {
  const owner = deviceActor(ctx, "owner");
  const signup = await owner.signUp.email({
    email: ctx.uniqueEmail(prefix),
    password: "password123",
    name: "Device Owner",
  });
  expect(signup.error).toBeNull();

  if (!signup.data) {
    throw new Error("device owner must have a session");
  }

  return { owner, signup, userId: signup.data.user.id };
}

function tokenRequest(deviceCode: string, clientId = "compat-device-client") {
  return { grant_type: DEVICE_GRANT_TYPE, device_code: deviceCode, client_id: clientId } as const;
}

compatScenario("device code request returns oauth device response fields", async (ctx) => {
  const code = await requestCode(ctx, "openid profile");
  expect(code.device_code).toHaveLength(40);
  expect(code.user_code).toMatch(/^[ABCDEFGHJKLMNPQRSTUVWXYZ23456789]{8}$/);
  expect(code.expires_in).toBe(1800);
  expect(code.interval).toBe(5);
  expect(new URL(code.verification_uri).pathname).toBe("/device");
  expect(new URL(code.verification_uri_complete).searchParams.get("user_code")).toBe(
    code.user_code,
  );

  return { code: ctx.snapshot(code) };
});

compatScenario(
  "device token returns authorization_pending while request is pending",
  async (ctx) => {
    const code = await requestCode(ctx);
    const token = await deviceActor(ctx, "device").device.token(tokenRequest(code.device_code));
    expect(token.data).toBeNull();
    expect(token.error).toMatchObject({ status: 400, error: "authorization_pending" });

    return { code: ctx.snapshot(code), token: ctx.snapshot(token) };
  },
);

compatScenario("device token returns invalid_grant for an unknown device code", async (ctx) => {
  const token = await deviceActor(ctx, "device").device.token(tokenRequest("unknown-device-code"));
  expect(token.error).toMatchObject({ status: 400, error: "invalid_grant" });
  return { token: ctx.snapshot(token) };
});

compatScenario("device verify accepts a hyphenated user code", async (ctx) => {
  const code = await requestCode(ctx);
  const formatted = `${code.user_code.slice(0, 4)}-${code.user_code.slice(4)}`;
  const verify = await deviceActor(ctx, "device").device({ query: { user_code: formatted } });
  expect(verify.error).toBeNull();
  expect(verify.data).toEqual({ user_code: formatted, status: "pending" });

  return { code: ctx.snapshot(code), verify: ctx.snapshot(verify) };
});

compatScenario(
  "device approve flow returns a bearer token",
  async (ctx) => {
    const { owner, signup, userId } = await signUpOwner(ctx, "device-authorization-device-approve");
    const code = await requestCode(ctx, "read write");
    const unclaimedState = deviceState.parse(
      await ctx.readDeviceState({ deviceCode: code.device_code }),
    );
    expect(unclaimedState.userId).toBeNull();

    const verify = await owner.device({ query: { user_code: code.user_code } });
    expect(verify.data).toEqual({
      user_code: code.user_code,
      status: "pending",
      client_id: "compat-device-client",
      scope: "read write",
    });

    const approve = await owner.device.approve({ userCode: code.user_code });
    expect(approve.data).toEqual({ success: true });

    const approvedState = await owner.device({ query: { user_code: code.user_code } });
    expect(approvedState.data?.status).toBe("approved");

    const persistedApproval = deviceState.parse(
      await ctx.readDeviceState({ deviceCode: code.device_code }),
    );
    expect(persistedApproval.userId).toBe(userId);
    expect(persistedApproval.status).toBe("approved");

    const device = deviceActor(ctx, "device");
    const redemptionStartedAt = Date.now();
    let tokenResponse: Response | undefined;
    const token = await device.device.token(tokenRequest(code.device_code), {
      onResponse(context) {
        tokenResponse = context.response.clone();
      },
    });
    const redemptionCompletedAt = Date.now();
    expect(token.error).toBeNull();

    if (!token.data) {
      throw new Error("approved code must issue a session token");
    }

    if (!tokenResponse) {
      throw new Error("Successful token redemption must expose its actual HTTP response");
    }
    expect(tokenResponse.status).toBe(200);
    expect(tokenResponse.headers.get("cache-control")).toBe("no-store");
    expect(tokenResponse.headers.get("pragma")).toBe("no-cache");
    expect(await tokenResponse.json()).toEqual(token.data);
    const tokenPolicy = {
      status: tokenResponse.status,
      cacheControl: tokenResponse.headers.get("cache-control"),
      pragma: tokenResponse.headers.get("pragma"),
    };
    expect(token.data.token_type).toBe("Bearer");
    expect(token.data.scope).toBe("read write");
    expect(token.data.expires_in).toBeGreaterThanOrEqual(604799);
    expect(token.data.expires_in).toBeLessThanOrEqual(604800);

    const sessions = await owner.listSessions();
    expect(sessions.data).toHaveLength(2);

    const issuedSession = sessions.data?.find(
      (session) => session.token === token.data?.access_token,
    );
    expect(issuedSession?.userId).toBe(userId);
    expect(issuedSession?.token).not.toBe(signup.data?.token);

    if (!issuedSession) {
      throw new Error("device token must identify its persisted session");
    }

    const absoluteExpiry = new Date(issuedSession.expiresAt).getTime();
    expect(token.data.expires_in).toBeGreaterThanOrEqual(
      Math.floor((absoluteExpiry - redemptionCompletedAt) / 1000),
    );
    expect(token.data.expires_in).toBeLessThanOrEqual(
      Math.floor((absoluteExpiry - redemptionStartedAt) / 1000),
    );

    const deviceCookieSession = await device.getSession();
    expect(deviceCookieSession.data).toBeNull();
    const bearer = await ctx.rawRequest({
      actor: "bearer-device",
      path: "/__test/profiles/bearer-default/api/auth/get-session",
      headers: { authorization: `Bearer ${token.data.access_token}` },
    });
    expect(bearer.status).toBe(200);
    expect((bearer.body as any).user.id).toBe(userId);
    expect((bearer.body as any).session.token).toBe(token.data.access_token);

    const replay = await device.device.token(tokenRequest(code.device_code));
    expect(replay.error).toMatchObject({ status: 400, error: "invalid_grant" });

    const consumed = await owner.device({ query: { user_code: code.user_code } });
    expect(consumed.error).toMatchObject({ status: 400, error: "invalid_request" });
    expect(await ctx.readDeviceState({ deviceCode: code.device_code })).toBeNull();

    return {
      signup: ctx.snapshot(signup),
      code: ctx.snapshot(code),
      verify: ctx.snapshot(verify),
      approve: ctx.snapshot(approve),
      approvedState: ctx.snapshot(approvedState),
      token: ctx.snapshot(token),
      sessions: ctx.snapshot(sessions),
      deviceCookieSession: ctx.snapshot(deviceCookieSession),
      tokenPolicy,
      bearer: ctx.snapshot(bearer),
      replay: ctx.snapshot(replay),
      consumed: ctx.snapshot(consumed),
      unclaimedState,
      persistedApproval,
    };
  },
  ["GET /device", "POST /device/approve", "POST /device/token"],
);

compatScenario(
  "device deny flow returns access_denied",
  async (ctx) => {
    const { owner, signup } = await signUpOwner(ctx, "device-authorization-device-deny");
    const code = await requestCode(ctx);
    const claim = await owner.device({ query: { user_code: code.user_code } });
    expect(claim.error).toBeNull();

    const deny = await owner.device.deny({ userCode: code.user_code });
    expect(deny.data).toEqual({ success: true });

    const repeatDeny = await owner.device.deny({ userCode: code.user_code });
    expect(repeatDeny.error).toMatchObject({
      status: 400,
      error: "invalid_request",
      error_description: "Device code already processed",
    });

    const deniedState = await owner.device({ query: { user_code: code.user_code } });
    expect(deniedState.data?.status).toBe("denied");

    const device = deviceActor(ctx, "device");
    const token = await device.device.token(tokenRequest(code.device_code));
    expect(token.error).toMatchObject({ status: 400, error: "access_denied" });

    const replay = await device.device.token(tokenRequest(code.device_code));
    expect(replay.error).toMatchObject({ status: 400, error: "invalid_grant" });

    const sessions = await owner.listSessions();
    expect(sessions.data).toHaveLength(1);

    return {
      signup: ctx.snapshot(signup),
      code: ctx.snapshot(code),
      claim: ctx.snapshot(claim),
      deny: ctx.snapshot(deny),
      repeatDeny: ctx.snapshot(repeatDeny),
      deniedState: ctx.snapshot(deniedState),
      token: ctx.snapshot(token),
      replay: ctx.snapshot(replay),
      sessions: ctx.snapshot(sessions),
    };
  },
  ["POST /device/deny", "POST /device/token"],
);

compatScenario(
  "device approve blocks already-processed codes",
  async (ctx) => {
    const { owner } = await signUpOwner(ctx, "device-authorization-device-double-approve");
    const code = await requestCode(ctx);
    await owner.device({ query: { user_code: code.user_code } });
    const firstApprove = await owner.device.approve({ userCode: code.user_code });
    expect(firstApprove.data).toEqual({ success: true });

    const secondApprove = await owner.device.approve({ userCode: code.user_code });
    expect(secondApprove.error).toMatchObject({
      status: 400,
      error: "invalid_request",
      error_description: "Device code already processed",
    });

    const denyApproved = await owner.device.deny({ userCode: code.user_code });
    expect(denyApproved.error).toMatchObject({
      status: 400,
      error: "invalid_request",
      error_description: "Device code already processed",
    });

    const state = await owner.device({ query: { user_code: code.user_code } });
    expect(state.data?.status).toBe("approved");

    return {
      firstApprove: ctx.snapshot(firstApprove),
      secondApprove: ctx.snapshot(secondApprove),
      denyApproved: ctx.snapshot(denyApproved),
      state: ctx.snapshot(state),
    };
  },
  ["POST /device/approve"],
);

compatScenario("device token rejects a mismatched client id", async (ctx) => {
  const code = await requestCode(ctx);
  const token = await deviceActor(ctx, "device").device.token(
    tokenRequest(code.device_code, "another-device-client"),
  );
  expect(token.error).toMatchObject({
    status: 400,
    error: "invalid_grant",
    error_description: "Client ID mismatch",
  });

  const state = await deviceActor(ctx, "device").device({ query: { user_code: code.user_code } });
  expect(state.data?.status).toBe("pending");

  return { token: ctx.snapshot(token), state: ctx.snapshot(state) };
});

compatScenario(
  "device decisions require the claiming user and redact other actors",
  async (ctx) => {
    const { owner } = await signUpOwner(ctx, "device-authorization-claim-owner");
    const other = deviceActor(ctx, "other");
    await other.signUp.email({
      email: ctx.uniqueEmail("device-authorization-claim-other"),
      password: "password123",
      name: "Other User",
    });
    const device = deviceActor(ctx, "device");
    const code = await requestCode(ctx, "private scope");
    const unauthenticatedApprove = await device.device.approve({ userCode: code.user_code });
    const unauthenticatedDeny = await device.device.deny({ userCode: code.user_code });
    expect(unauthenticatedApprove.error).toMatchObject({ status: 401, error: "unauthorized" });
    expect(unauthenticatedDeny.error).toMatchObject({ status: 401, error: "unauthorized" });

    const unclaimedApprove = await owner.device.approve({ userCode: code.user_code });
    const unclaimedDeny = await owner.device.deny({ userCode: code.user_code });
    expect(unclaimedApprove.error).toMatchObject({ status: 400, error: "invalid_request" });
    expect(unclaimedDeny.error).toMatchObject({ status: 400, error: "invalid_request" });

    const claim = await owner.device({ query: { user_code: code.user_code } });
    expect(claim.data?.client_id).toBe("compat-device-client");
    expect(claim.data?.scope).toBe("private scope");

    const otherReview = await other.device({ query: { user_code: code.user_code } });
    const publicReview = await device.device({ query: { user_code: code.user_code } });
    expect(otherReview.data).toEqual({ user_code: code.user_code, status: "pending" });
    expect(publicReview.data).toEqual(otherReview.data);

    const otherApprove = await other.device.approve({ userCode: code.user_code });
    const otherDeny = await other.device.deny({ userCode: code.user_code });
    expect(otherApprove.error).toMatchObject({ status: 403, error: "access_denied" });
    expect(otherDeny.error).toMatchObject({ status: 403, error: "access_denied" });

    const ownerApprove = await owner.device.approve({ userCode: code.user_code });
    expect(ownerApprove.data).toEqual({ success: true });

    return {
      unauthenticatedApprove: ctx.snapshot(unauthenticatedApprove),
      unauthenticatedDeny: ctx.snapshot(unauthenticatedDeny),
      unclaimedApprove: ctx.snapshot(unclaimedApprove),
      unclaimedDeny: ctx.snapshot(unclaimedDeny),
      claim: ctx.snapshot(claim),
      otherReview: ctx.snapshot(otherReview),
      publicReview: ctx.snapshot(publicReview),
      otherApprove: ctx.snapshot(otherApprove),
      otherDeny: ctx.snapshot(otherDeny),
      ownerApprove: ctx.snapshot(ownerApprove),
    };
  },
  ["GET /device", "POST /device/approve"],
);

compatScenario(
  "device verification normalizes punctuation and case in default user codes",
  async (ctx) => {
    const { owner } = await signUpOwner(ctx, "device-authorization-device-normalize");
    const code = await requestCode(ctx, "normalized");
    const formatted = `${code.user_code.slice(0, 4).toLowerCase()} . ${code.user_code.slice(4).toLowerCase()}`;
    const claim = await owner.device({ query: { user_code: formatted } });
    expect(claim.data?.user_code).toBe(formatted);
    expect(claim.data?.client_id).toBe("compat-device-client");

    const approve = await owner.device.approve({ userCode: formatted });
    expect(approve.data).toEqual({ success: true });

    return { code: ctx.snapshot(code), claim: ctx.snapshot(claim), approve: ctx.snapshot(approve) };
  },
  ["GET /device", "POST /device/approve"],
);

compatScenario(
  "device requests pre-bound to a user cannot be claimed by another user",
  async (ctx) => {
    const { owner, userId } = await signUpOwner(ctx, "device-authorization-device-prebound");
    const other = deviceActor(ctx, "other");
    await other.signUp.email({
      email: ctx.uniqueEmail("device-authorization-device-prebound-other"),
      password: "password123",
      name: "Other User",
    });
    const code = await deviceActor(ctx, "device").device.code({
      client_id: "compat-device-client",
      user_id: userId,
      scope: "prebound scope",
    });
    expect(code.error).toBeNull();

    if (!code.data) {
      throw new Error("device issuance must return codes");
    }

    const otherReview = await other.device({ query: { user_code: code.data.user_code } });
    expect(otherReview.data).toEqual({ user_code: code.data.user_code, status: "pending" });

    const otherApprove = await other.device.approve({ userCode: code.data.user_code });
    expect(otherApprove.error).toMatchObject({ status: 403, error: "access_denied" });

    const ownerApprove = await owner.device.approve({ userCode: code.data.user_code });
    expect(ownerApprove.data).toEqual({ success: true });

    const state = await owner.device({ query: { user_code: code.data.user_code } });
    expect(state.data?.status).toBe("approved");
    expect(state.data?.scope).toBe("prebound scope");

    return {
      code: ctx.snapshot(code),
      otherReview: ctx.snapshot(otherReview),
      otherApprove: ctx.snapshot(otherApprove),
      ownerApprove: ctx.snapshot(ownerApprove),
      state: ctx.snapshot(state),
    };
  },
  ["POST /device/code", "POST /device/approve"],
);

compatScenario(
  "device polling enforces its interval without consuming a pending request",
  async (ctx) => {
    const code = await requestCode(ctx);
    const device = deviceActor(ctx, "device");
    const initial = deviceState.parse(await ctx.readDeviceState({ deviceCode: code.device_code }));
    expect(initial.lastPolledAt).toBeNull();

    const firstPoll = await device.device.token(tokenRequest(code.device_code));
    expect(firstPoll.error).toMatchObject({ status: 400, error: "authorization_pending" });

    const afterFirst = deviceState.parse(
      await ctx.readDeviceState({ deviceCode: code.device_code }),
    );
    expect(afterFirst.lastPolledAt).not.toBeNull();

    const repeatedPoll = await device.device.token(tokenRequest(code.device_code));
    expect(repeatedPoll.error).toMatchObject({ status: 400, error: "slow_down" });

    const afterRepeated = deviceState.parse(
      await ctx.readDeviceState({ deviceCode: code.device_code }),
    );
    expect(afterRepeated).toEqual(afterFirst);
    expect(afterRepeated.status).toBe("pending");

    return {
      initial,
      firstPoll: ctx.snapshot(firstPoll),
      afterFirst,
      repeatedPoll: ctx.snapshot(repeatedPoll),
      afterRepeated,
    };
  },
  ["POST /device/token"],
);

compatScenario(
  "expired device requests reject decisions and are deleted on redemption",
  async (ctx) => {
    const { owner } = await signUpOwner(ctx, "device-authorization-device-expiry");
    const code = await requestCode(ctx);
    await owner.device({ query: { user_code: code.user_code } });
    await ctx.expireDevice({ deviceCode: code.device_code, expiresAt: "2000-01-01T00:00:00.000Z" });
    const approve = await owner.device.approve({ userCode: code.user_code });
    const deny = await owner.device.deny({ userCode: code.user_code });
    const review = await owner.device({ query: { user_code: code.user_code } });
    expect(approve.error).toMatchObject({ status: 400, error: "expired_token" });
    expect(deny.error).toMatchObject({ status: 400, error: "expired_token" });
    expect(review.error).toMatchObject({ status: 400, error: "expired_token" });

    const beforeRedemption = deviceState.parse(
      await ctx.readDeviceState({ deviceCode: code.device_code }),
    );
    expect(beforeRedemption.status).toBe("pending");

    const token = await deviceActor(ctx, "device").device.token(tokenRequest(code.device_code));
    expect(token.error).toMatchObject({ status: 400, error: "expired_token" });
    expect(await ctx.readDeviceState({ deviceCode: code.device_code })).toBeNull();

    const replay = await deviceActor(ctx, "device").device.token(tokenRequest(code.device_code));
    expect(replay.error).toMatchObject({ status: 400, error: "invalid_grant" });

    const sessions = await owner.listSessions();
    expect(sessions.data).toHaveLength(1);

    return {
      approve: ctx.snapshot(approve),
      deny: ctx.snapshot(deny),
      review: ctx.snapshot(review),
      beforeRedemption,
      token: ctx.snapshot(token),
      replay: ctx.snapshot(replay),
      sessions: ctx.snapshot(sessions),
    };
  },
  ["POST /device/token"],
);

compatScenario(
  "device issuance preserves unknown user prebinding and normalizes empty optional parameters",
  async (ctx) => {
    const device = deviceActor(ctx, "device");
    const unknownUser = ctx.uniqueToken("device-authorization-unknown-owner");
    const code = await device.device.code({
      client_id: "compat-device-client",
      user_id: unknownUser,
      scope: "",
    });
    expect(code.error).toBeNull();

    if (!code.data) {
      throw new Error("prebound device code must be issued");
    }

    const persisted = deviceState.parse(
      await ctx.readDeviceState({ deviceCode: code.data.device_code }),
    );
    expect(persisted.userId).toBe(unknownUser);
    expect(persisted.scope).toBeNull();

    const { owner } = await signUpOwner(ctx, "device-authorization-prebound-unrelated");
    const review = await owner.device({ query: { user_code: code.data.user_code } });
    expect(review.data).toEqual({ user_code: code.data.user_code, status: "pending" });

    const approve = await owner.device.approve({ userCode: code.data.user_code });
    expect(approve.error).toMatchObject({ status: 403, error: "access_denied" });

    const afterRejection = deviceState.parse(
      await ctx.readDeviceState({ deviceCode: code.data.device_code }),
    );
    expect(afterRejection.userId).toBe(unknownUser);
    expect(afterRejection.status).toBe("pending");

    const emptyUser = await device.device.code({
      client_id: "compat-device-client",
      user_id: "",
      scope: "",
    });
    expect(emptyUser.error).toBeNull();

    if (!emptyUser.data) {
      throw new Error("empty optional parameters must be accepted");
    }

    const emptyPersisted = deviceState.parse(
      await ctx.readDeviceState({ deviceCode: emptyUser.data.device_code }),
    );
    expect(emptyPersisted.userId).toBeNull();
    expect(emptyPersisted.scope).toBeNull();

    const emptyClient = await device.device.code({ client_id: "" });
    expect(emptyClient.error).toMatchObject({
      status: 400,
      error: "invalid_request",
      error_description: "client_id is required",
    });

    return {
      code: ctx.snapshot(code),
      persisted,
      review: ctx.snapshot(review),
      approve: ctx.snapshot(approve),
      afterRejection,
      emptyUser: ctx.snapshot(emptyUser),
      emptyPersisted,
      emptyClient: ctx.snapshot(emptyClient),
    };
  },
);

compatScenario(
  "device issuance accepts OAuth form parameters and rejects repeated effective values",
  async (ctx) => {
    const body = new URLSearchParams({ client_id: "form-client", scope: "" });
    body.append("client_id", "");
    body.append("scope", "form scope");
    body.append("user_id", "");
    const issuedResponse = await ctx.actor("device").fetch(`${ctx.baseURL}/api/auth/device/code`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body,
    });
    expect(issuedResponse.status).toBe(200);

    const issued = z
      .object({
        device_code: z.string(),
        user_code: z.string(),
        verification_uri: z.string(),
        verification_uri_complete: z.string(),
        expires_in: z.number(),
        interval: z.number(),
      })
      .parse(await issuedResponse.json());
    const headers = {
      cacheControl: issuedResponse.headers.get("cache-control"),
      pragma: issuedResponse.headers.get("pragma"),
    };
    expect(headers).toEqual({ cacheControl: "no-store", pragma: "no-cache" });

    const stored = deviceState.parse(await ctx.readDeviceState({ deviceCode: issued.device_code }));
    expect(stored.clientId).toBe("form-client");
    expect(stored.scope).toBe("form scope");
    expect(stored.userId).toBeNull();

    const repeated = [];

    for (const parameter of ["client_id", "user_id", "scope"]) {
      const parameters = new URLSearchParams({ client_id: "form-client" });

      if (parameter !== "client_id") {
        parameters.append(parameter, "one");
      }

      parameters.append(parameter, "two");
      const response = await ctx.rawRequest({
        actor: "device",
        path: "/api/auth/device/code",
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: parameters,
      });
      expect(response).toMatchObject({
        status: 400,
        body: { error: "invalid_request", error_description: `${parameter} must not be repeated` },
      });

      repeated.push(response);
    }

    return { issued, headers, stored, repeated };
  },
  ["POST /device/code"],
);

compatScenario(
  "device endpoint schemas preserve OAuth validation and media type errors",
  async (ctx) => {
    const missingClient = await ctx.rawRequest({
      path: "/api/auth/device/code",
      method: "POST",
      json: {},
    });
    expect(missingClient).toMatchObject({
      status: 400,
      body: {
        error: "invalid_request",
        error_description: "[body.client_id] Invalid input: expected string, received undefined",
      },
    });

    const invalidTypes = await ctx.rawRequest({
      path: "/api/auth/device/code",
      method: "POST",
      json: { client_id: 2, user_id: null, scope: true },
    });
    expect(invalidTypes).toMatchObject({
      status: 400,
      body: {
        error: "invalid_request",
        error_description:
          "[body.client_id] Invalid input: expected string, received number; [body.user_id] Invalid input: expected string, received null; [body.scope] Invalid input: expected string, received boolean",
      },
    });

    const wrongGrant = await ctx.rawRequest({
      path: "/api/auth/device/token",
      method: "POST",
      json: { grant_type: "invalid-grant", client_id: "form-client", device_code: "unused" },
    });
    expect(wrongGrant).toMatchObject({
      status: 400,
      body: {
        code: "VALIDATION_ERROR",
        message: `[body.grant_type] Invalid input: expected "${DEVICE_GRANT_TYPE}"`,
      },
    });

    const tokenForm = await ctx.rawRequest({
      path: "/api/auth/device/token",
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams(tokenRequest("unused")),
    });
    expect(tokenForm).toMatchObject({
      status: 415,
      body: {
        code: "UNSUPPORTED_MEDIA_TYPE",
        message:
          'Content-Type "application/x-www-form-urlencoded" is not allowed. Allowed types: application/json',
      },
    });

    const codeText = await ctx.rawRequest({
      path: "/api/auth/device/code",
      method: "POST",
      headers: { "content-type": "text/plain" },
      body: '{"client_id":"form-client"}',
    });
    expect(codeText).toMatchObject({
      status: 415,
      body: {
        code: "UNSUPPORTED_MEDIA_TYPE",
        message:
          'Content-Type "text/plain" is not allowed. Allowed types: application/json, application/x-www-form-urlencoded',
      },
    });

    const signup = await ctx.actor("validation-owner").client.signUp.email({
      email: ctx.uniqueEmail("device-validation"),
      password: "password123",
      name: "Validation Owner",
    });
    expect(signup.error).toBeNull();

    const decisions = [];

    for (const route of ["approve", "deny"]) {
      const path = `/api/auth/device/${route}`;
      const malformed = await ctx.rawRequest({
        path,
        method: "POST",
        headers: { "content-type": "application/json" },
        body: "{",
        actor: "validation-guest",
      });
      expect(malformed.status).toBe(400);

      const missing = await ctx.rawRequest({
        path,
        method: "POST",
        json: {},
        actor: "validation-guest",
      });
      expect(missing).toMatchObject({ status: 400, body: { code: "VALIDATION_ERROR" } });

      const wrongType = await ctx.rawRequest({
        path,
        method: "POST",
        json: { userCode: 7 },
        actor: "validation-guest",
      });
      expect(wrongType).toMatchObject({ status: 400, body: { code: "VALIDATION_ERROR" } });

      for (const actor of ["validation-guest", "validation-owner"]) {
        const media = await ctx.rawRequest({
          path,
          method: "POST",
          headers: { "content-type": "text/plain" },
          body: '{"userCode":"unused"}',
          actor,
        });
        expect(media).toMatchObject({ status: 415, body: { code: "UNSUPPORTED_MEDIA_TYPE" } });
        decisions.push(media);
      }

      const missingMedia = await ctx.rawRequest({
        path,
        method: "POST",
        headers: { "content-type": "" },
        body: '{"userCode":"unused"}',
        actor: "validation-guest",
      });
      expect(missingMedia).toMatchObject({
        status: 415,
        body: {
          code: "UNSUPPORTED_MEDIA_TYPE",
          message: "Content-Type is required. Allowed types: application/json",
        },
      });

      decisions.push(malformed, missing, wrongType, missingMedia);
    }

    return {
      missingClient,
      invalidTypes,
      wrongGrant,
      tokenForm,
      codeText,
      signup: ctx.snapshot(signup),
      decisions,
    };
  },
);

compatScenario(
  "device custom asynchronous generators preserve exact codes and reject normalized aliases",
  async (ctx) => {
    const client = deviceActor(ctx, "custom", "device-custom");
    const code = await client.device.code({ client_id: "custom-client" });
    expect(code.error).toBeNull();

    if (!code.data) {
      throw new Error("custom device issuance failed");
    }

    expect(code.data.device_code).toBe("custom-device-🔐");
    expect(code.data.user_code).toBe(" café-Code! ");

    const signup = await client.signUp.email({
      email: ctx.uniqueEmail("device-custom"),
      password: "password123",
      name: "Custom Owner",
    });
    expect(signup.error).toBeNull();

    const alias = await client.device({ query: { user_code: "CAFCODE" } });
    expect(alias.error).toMatchObject({ status: 400, error: "invalid_request" });

    const exact = await client.device({ query: { user_code: code.data.user_code } });
    expect(ctx.snapshot(exact.data)).toEqual({
      user_code: code.data.user_code,
      status: "pending",
      client_id: "custom-client",
      scope: null,
    });

    const approved = await client.device.approve({ userCode: code.data.user_code });
    expect(approved.data).toEqual({ success: true });

    const consumed = await client.device.token(
      tokenRequest(code.data.device_code, "custom-client"),
    );
    expect(consumed.error).toBeNull();

    const sessions = await client.listSessions();
    expect(
      sessions.data?.find((session) => session.token === consumed.data?.access_token)?.userId,
    ).toBe(signup.data?.user.id);
    expect(await ctx.readDeviceState({ deviceCode: code.data.device_code })).toBeNull();

    const replay = await client.device.token(tokenRequest(code.data.device_code, "custom-client"));
    expect(replay.error).toMatchObject({ status: 400, error: "invalid_grant" });

    return {
      code: ctx.snapshot(code),
      signup: ctx.snapshot(signup),
      alias: ctx.snapshot(alias),
      exact: ctx.snapshot(exact),
      approved: ctx.snapshot(approved),
      consumed: ctx.snapshot(consumed),
      sessions: ctx.snapshot(sessions),
      replay: ctx.snapshot(replay),
    };
  },
  ["GET /device", "POST /device/approve", "POST /device/token"],
);

compatScenario(
  "device configuration controls client validation lifetime polling and verification URL parameters",
  async (ctx) => {
    const client = deviceActor(ctx, "configured", "device-configured");
    const rejected = await client.device.code({ client_id: "wrong-client" });
    expect(rejected.error).toMatchObject({ status: 400, error: "invalid_client" });

    const startedAt = Date.now();
    const issued = await client.device.code({ client_id: "allowed-client", scope: "custom scope" });
    const finishedAt = Date.now();
    expect(issued.error).toBeNull();

    if (!issued.data) {
      throw new Error("configured issuance failed");
    }

    expect(issued.data.expires_in).toBe(120);
    expect(issued.data.interval).toBe(2);

    const uri = new URL(issued.data.verification_uri_complete);
    expect(uri.origin).toBe("https://verification.fixture");
    expect(uri.searchParams.getAll("user_code")).toEqual([issued.data.user_code]);
    expect(uri.searchParams.getAll("keep")).toEqual(["a", "b"]);
    expect(uri.hash).toBe("#fragment");

    const persisted = deviceState.parse(
      await ctx.readDeviceState({ deviceCode: issued.data.device_code }),
    );
    expect(persisted.pollingInterval).toBe(2000);
    expect(new Date(persisted.expiresAt).getTime()).toBeGreaterThanOrEqual(startedAt + 120000);
    expect(new Date(persisted.expiresAt).getTime()).toBeLessThanOrEqual(finishedAt + 120000);

    const pending = await client.device.token(
      tokenRequest(issued.data.device_code, "allowed-client"),
    );
    expect(pending.error).toMatchObject({ status: 400, error: "authorization_pending" });

    const slow = await client.device.token(tokenRequest(issued.data.device_code, "allowed-client"));
    expect(slow.error).toMatchObject({ status: 400, error: "slow_down" });

    return {
      rejected: ctx.snapshot(rejected),
      issued: ctx.snapshot(issued),
      persisted,
      pending: ctx.snapshot(pending),
      slow: ctx.snapshot(slow),
    };
  },
  ["POST /device/code", "POST /device/token"],
);

compatScenario(
  "device generators count Unicode characters and reject oversized codes before persistence",
  async (ctx) => {
    const boundary = await deviceActor(ctx, "boundary", "device-unicode").device.code({
      client_id: "boundary-client",
    });
    expect(boundary.error).toBeNull();

    if (!boundary.data) {
      throw new Error("Unicode boundary must issue");
    }

    expect([...boundary.data.device_code]).toHaveLength(191);

    const persisted = deviceState.parse(
      await ctx.readDeviceState({ deviceCode: boundary.data.device_code }),
    );
    expect(persisted.deviceCode).toBe(boundary.data.device_code);

    const rejected = await deviceActor(ctx, "oversized", "device-too-long").device.code({
      client_id: "boundary-client",
    });
    expect(rejected.error).toMatchObject({
      status: 400,
      error: "invalid_request",
      error_description: "Generated device code must be at most 191 characters",
    });
    expect(await ctx.readDeviceState({ deviceCode: "😀".repeat(192) })).toBeNull();

    return { boundary: ctx.snapshot(boundary), persisted, rejected: ctx.snapshot(rejected) };
  },
);

compatScenario(
  "device empty generators persist usable codes and preserve client binding through consumption",
  async (ctx) => {
    const client = deviceActor(ctx, "empty", "device-empty");
    const issued = await client.device.code({ client_id: "empty-client" });
    expect(issued.error).toBeNull();
    expect(issued.data?.device_code).toBe("");
    expect(issued.data?.user_code).toBe("");
    const persisted = deviceState.parse(await ctx.readDeviceState({ deviceCode: "" }));
    expect(persisted).toMatchObject({
      deviceCode: "",
      userCode: "",
      status: "pending",
      userId: null,
      clientId: "empty-client",
      scope: null,
      lastPolledAt: null,
      pollingInterval: 5000,
    });
    const wrongClient = await client.device.token(tokenRequest("", "foreign-client"));
    expect(wrongClient.error).toMatchObject({
      status: 400,
      error: "invalid_grant",
      error_description: "Client ID mismatch",
    });
    expect(await ctx.readDeviceState({ deviceCode: "" })).toEqual(persisted);
    const signup = await client.signUp.email({
      email: ctx.uniqueEmail("empty-code-owner"),
      password: "password123",
      name: "Empty Code Owner",
    });
    expect(signup.error).toBeNull();
    const verify = await client.device({ query: { user_code: "" } });
    expect(verify.error).toBeNull();
    expect(verify.data?.status).toBe("pending");
    const approve = await client.device.approve({ userCode: "" });
    expect(approve.data).toEqual({ success: true });
    const approved = deviceState.parse(await ctx.readDeviceState({ deviceCode: "" }));
    expect(approved.status).toBe("approved");
    expect(approved.userId).toBe(signup.data?.user.id ?? "missing-owner");
    const token = await client.device.token(tokenRequest("", "empty-client"));
    expect(token.error).toBeNull();
    const sessions = await client.listSessions();
    expect(sessions.data).toHaveLength(2);
    expect(
      sessions.data?.find((session) => session.token === token.data?.access_token)?.userId,
    ).toBe(signup.data?.user.id ?? "missing-owner");
    const consumed = await ctx.readDeviceState({ deviceCode: "" });
    expect(consumed).toBeNull();
    const replay = await client.device.token(tokenRequest("", "empty-client"));
    expect(replay.error).toMatchObject({ status: 400, error: "invalid_grant" });
    return {
      issued: ctx.snapshot(issued),
      persisted,
      wrongClient: ctx.snapshot(wrongClient),
      signup: ctx.snapshot(signup),
      verify: ctx.snapshot(verify),
      approve: ctx.snapshot(approve),
      approved,
      token: ctx.snapshot(token),
      sessions: ctx.snapshot(sessions),
      consumed,
      replay: ctx.snapshot(replay),
    };
  },
  ["POST /device/code", "GET /device", "POST /device/approve", "POST /device/token"],
);

compatScenario(
  "device signed fractional durations floor responses and preserve millisecond state",
  async (ctx) => {
    const observations = [];
    for (const [profile, lifetime, interval, seconds, pollSeconds, path] of [
      ["device-fractional", 1750, 250, 1, 0, "/verify-relative"],
      ["device-negative", -1250, -250, -2, -1, "/device"],
      ["device-negative-interval", 120000, -250, 120, -1, "/device"],
    ] as const) {
      const client = deviceActor(ctx, profile, profile);
      const started = Date.now();
      const issued = await client.device.code({ client_id: profile });
      const finished = Date.now();
      expect(issued.error).toBeNull();
      if (!issued.data) throw new Error("duration profile must issue");
      expect(issued.data.expires_in).toBe(seconds);
      expect(issued.data.interval).toBe(pollSeconds);
      expect(new URL(issued.data.verification_uri).pathname).toBe(path);
      expect(new URL(issued.data.verification_uri_complete).searchParams.get("user_code")).toBe(
        issued.data.user_code,
      );
      const persisted = deviceState.parse(
        await ctx.readDeviceState({ deviceCode: issued.data.device_code }),
      );
      expect(persisted).toMatchObject({
        pollingInterval: interval,
        status: "pending",
        userId: null,
        clientId: profile,
        scope: null,
        lastPolledAt: null,
      });
      expect(new Date(persisted.expiresAt).getTime()).toBeGreaterThanOrEqual(started + lifetime);
      expect(new Date(persisted.expiresAt).getTime()).toBeLessThanOrEqual(finished + lifetime);
      const token = await client.device.token(tokenRequest(issued.data.device_code, profile));
      expect(token.error).toMatchObject({
        status: 400,
        error: lifetime < 0 ? "expired_token" : "authorization_pending",
      });
      const after = await ctx.readDeviceState({ deviceCode: issued.data.device_code });
      if (lifetime < 0) expect(after).toBeNull();
      else expect(deviceState.parse(after).lastPolledAt).not.toBeNull();
      const repeat = await client.device.token(tokenRequest(issued.data.device_code, profile));
      expect(repeat.error).toMatchObject({
        status: 400,
        error:
          lifetime < 0 ? "invalid_grant" : interval < 0 ? "authorization_pending" : "slow_down",
      });
      observations.push({
        repeat: ctx.snapshot(repeat),
        issued: ctx.snapshot(issued),
        persisted,
        token: ctx.snapshot(token),
        after,
      });
    }
    return { observations };
  },
  ["POST /device/code", "POST /device/token"],
);

compatScenario(
  "device generator validation and request callback errors preserve bodies without persistence",
  async (ctx) => {
    const observations = [];
    for (const profile of [
      "device-generator-error",
      "device-user-generator-error",
      "device-validation-error",
      "device-request-error",
    ] as const) {
      const client = deviceActor(ctx, profile, profile);
      const rejected = await client.device.code({ client_id: profile, scope: "callback scope" });
      expect(rejected.error).toMatchObject({
        status: 400,
        code: "DEVICE_CALLBACK_FAILED",
        message: "Configured device callback failed",
      });
      const persisted = await ctx.readDeviceState({ deviceCode: `${profile}-code` });
      expect(persisted).toBeNull();
      const token = await client.device.token(tokenRequest(`${profile}-code`, profile));
      expect(token.error).toMatchObject(
        profile === "device-validation-error"
          ? { status: 400, code: "DEVICE_CALLBACK_FAILED" }
          : { status: 400, error: "invalid_grant" },
      );
      observations.push({
        rejected: ctx.snapshot(rejected),
        persisted,
        token: ctx.snapshot(token),
      });
    }
    for (const profile of [
      "device-generator-throw",
      "device-user-generator-throw",
      "device-validation-throw",
      "device-request-throw",
    ] as const) {
      const rejected = await ctx.rawRequest({
        actor: profile,
        path: `/__test/profiles/${profile}/api/auth/device/code`,
        method: "POST",
        json: { client_id: profile, scope: "callback scope" },
      });
      expect(rejected).toMatchObject({ status: 500, body: null });
      const persisted = await ctx.readDeviceState({ deviceCode: `${profile}-code` });
      expect(persisted).toBeNull();
      const token = await ctx.rawRequest({
        actor: profile,
        path: `/__test/profiles/${profile}/api/auth/device/token`,
        method: "POST",
        json: tokenRequest(`${profile}-code`, profile),
      });
      expect(token).toMatchObject(
        profile === "device-validation-throw"
          ? { status: 500, body: null }
          : { status: 400, body: { error: "invalid_grant" } },
      );
      observations.push({ rejected, persisted, token });
    }
    return { observations };
  },
  ["POST /device/code", "POST /device/token"],
);

compatScenario(
  "approved device redemption retains its grant when the persisted owner is missing",
  async (ctx) => {
    const { owner, signup, userId } = await signUpOwner(ctx, "missing-device-owner");
    const foreign = ctx.actor("foreign-device-owner");
    const other = await foreign.client.signUp.email({
      email: ctx.uniqueEmail("foreign-device"),
      password: "password123",
      name: "Foreign Device",
    });
    expect(other.error).toBeNull();
    const foreignBefore = await ctx.readUserState({ userId: other.data!.user.id });
    const code = await requestCode(ctx);
    expect((await owner.device({ query: { user_code: code.user_code } })).error).toBeNull();
    expect((await owner.device.approve({ userCode: code.user_code })).error).toBeNull();
    const approved = deviceState.parse(await ctx.readDeviceState({ deviceCode: code.device_code }));
    expect(approved).toMatchObject({ status: "approved", userId });
    async function setOwner(id: string) {
      const result = await ctx.rawRequest({
        path: "/__test/device-owner",
        method: "POST",
        json: { deviceCode: code.device_code, userId: id },
      });
      expect(result.status).toBe(200);
      expect(result.body).toEqual({ changed: true });
      return result;
    }
    const orphanId = "11111111-1111-4111-8111-111111111111";
    const altered = await setOwner(orphanId);
    const before = deviceState.parse(await ctx.readDeviceState({ deviceCode: code.device_code }));
    expect(before.userId).toBe(orphanId);
    expect(before.status).toBe("approved");
    const ownerBefore = await ctx.readUserState({ userId });
    const failed = await deviceActor(ctx, "device").device.token(tokenRequest(code.device_code));
    expect(failed.data).toBeNull();
    const retained = deviceState.parse(await ctx.readDeviceState({ deviceCode: code.device_code }));
    expect({ ...retained, lastPolledAt: before.lastPolledAt }).toEqual(before);
    expect(retained.lastPolledAt).not.toBeNull();
    expect(Number.isFinite(Date.parse(retained.lastPolledAt!))).toBe(true);
    expect(await ctx.readUserState({ userId })).toEqual(ownerBefore);
    expect(await ctx.readUserState({ userId: other.data!.user.id })).toEqual(foreignBefore);
    const repaired = await setOwner(userId);
    await Bun.sleep(Math.max(code.interval * 1000, retained.pollingInterval ?? 0) + 30);
    const restored = await deviceActor(ctx, "device").device.token(tokenRequest(code.device_code));
    expect(restored.error).toBeNull();
    expect(restored.data?.access_token).toBeTruthy();
    expect(await ctx.readDeviceState({ deviceCode: code.device_code })).toBeNull();
    const sessions = await owner.listSessions();
    expect(sessions.error).toBeNull();
    expect(sessions.data).toHaveLength(2);
    expect(sessions.data).toContainEqual(
      expect.objectContaining({ token: restored.data!.access_token, userId }),
    );
    const bearer = await ctx.rawRequest({
      actor: "repaired-device-bearer",
      path: "/__test/profiles/bearer-default/api/auth/get-session",
      headers: { authorization: `Bearer ${restored.data!.access_token}` },
    });
    expect(bearer.status).toBe(200);
    expect((bearer.body as { user: { id: string } }).user.id).toBe(userId);
    expect(await ctx.readUserState({ userId: other.data!.user.id })).toEqual(foreignBefore);
    const replay = await deviceActor(ctx, "device").device.token(tokenRequest(code.device_code));
    expect(replay.error).toMatchObject({ status: 400, error: "invalid_grant" });
    expect(failed.error).toMatchObject({
      status: 500,
      error: "server_error",
      error_description: "User not found",
    });
    return ctx.snapshot({
      signup,
      other,
      code,
      altered,
      failed,
      retained,
      repaired,
      restored,
      sessions,
      bearer,
      replay,
    });
  },
  ["POST /device/token"],
);

compatScenario(
  "device generators retry both unique collisions and bound exhaustion without replacing grants",
  async (ctx) => {
    const observations = [];
    for (const mode of ["retry", "exhaustion"] as const) {
      const profile = `device-collision-${mode}` as const;
      const client = deviceActor(ctx, profile, profile);
      const generatorState = async () => {
        const response = await fetch(
          `${ctx.baseURL}/__test/device-generator-state?clientId=${profile}`,
        );
        expect(response.status).toBe(200);
        return (await response.json()) as {
          events: { kind: string; value: string }[];
          grants: {
            deviceCode: string;
            userCode: string;
            userId: string | null;
            status: string;
            clientId: string;
            scope: string | null;
          }[];
        };
      };
      await generatorState();
      const signup = await client.signUp.email({
        email: ctx.uniqueEmail(profile),
        password: "password123",
        name: "Collision Owner",
      });
      expect(signup.error).toBeNull();
      const first = await client.device.code({ client_id: profile, scope: "original-scope" });
      expect(first.error).toBeNull();
      expect(first.data).not.toBeNull();
      const original = deviceState.parse(
        await ctx.readDeviceState({ deviceCode: first.data!.device_code }),
      );
      const second = await client.device.code({ client_id: profile, scope: "later-scope" });
      const third =
        mode === "retry"
          ? await client.device.code({ client_id: profile, scope: "third-scope" })
          : null;
      expect(await ctx.readDeviceState({ deviceCode: first.data!.device_code })).toEqual(original);
      const state = await generatorState();
      const expectedPairs: [string, string][] =
        mode === "retry"
          ? [
              ["retry-device-original", "retry-user-original"],
              ["retry-device-later", "retry-user-later"],
              ["retry-device-third", "retry-user-third"],
            ]
          : [["constant-device", "constant-user"]];
      const attemptedPairs: [string, string][] =
        mode === "retry"
          ? [
              expectedPairs[0]!,
              ["retry-device-original", "retry-user-device-collision"],
              ["retry-device-user-collision", "retry-user-original"],
              expectedPairs[1]!,
              expectedPairs[2]!,
            ]
          : Array.from({ length: 4 }, () => expectedPairs[0]!);
      expect(state.events).toEqual(
        attemptedPairs.flatMap(([device, user]) => [
          { kind: "device", value: device },
          { kind: "user", value: user },
        ]),
      );
      expect(state.grants).toEqual(
        expectedPairs
          .map(([deviceCode, userCode], index) => ({
            deviceCode,
            userCode,
            userId: null,
            status: "pending",
            clientId: profile,
            scope: ["original-scope", "later-scope", "third-scope"][index]!,
          }))
          .sort((a, b) => a.deviceCode!.localeCompare(b.deviceCode!)),
      );
      if (mode === "retry") {
        expect(second.error).toBeNull();
        expect(second.data).toMatchObject({
          device_code: expectedPairs[1]![0],
          user_code: expectedPairs[1]![1],
        });
        expect(third?.error).toBeNull();
        expect(third?.data).toMatchObject({
          device_code: expectedPairs[2]![0],
          user_code: expectedPairs[2]![1],
        });
        expect(await ctx.readDeviceState({ deviceCode: "retry-device-user-collision" })).toBeNull();
      } else {
        expect(second.data).toBeNull();
        expect(second.error).toMatchObject({
          status: 500,
          error: "server_error",
          error_description: "Failed to generate a unique device code",
        });
      }
      const redemptions = [];
      for (const [deviceCode, userCode] of expectedPairs) {
        const reviewed = await client.device({ query: { user_code: userCode! } });
        expect(reviewed.error).toBeNull();
        const approved = await client.device.approve({ userCode: userCode! });
        expect(approved.data).toEqual({ success: true });
        const redeemed = await client.device.token(tokenRequest(deviceCode!, profile));
        expect(redeemed.error).toBeNull();
        expect(redeemed.data?.access_token).toBeString();
        expect(await ctx.readDeviceState({ deviceCode: deviceCode! })).toBeNull();
        const bearer = await ctx
          .actor(`${profile}-${deviceCode}`, "bearer-default")
          .client.getSession({
            fetchOptions: { headers: { authorization: `Bearer ${redeemed.data!.access_token}` } },
          });
        expect(bearer.data?.user.id).toBe(signup.data!.user.id);
        expect(bearer.data?.session.token).toBe(redeemed.data!.access_token);
        const replay = await client.device.token(tokenRequest(deviceCode!, profile));
        expect(replay.error).toMatchObject({ status: 400, error: "invalid_grant" });
        redemptions.push({ reviewed, approved, redeemed, bearer, replay });
      }
      const sessions = await client.listSessions();
      expect(sessions.data).toHaveLength(expectedPairs.length + 1);
      expect(sessions.data?.every((session) => session.userId === signup.data!.user.id)).toBe(true);
      const consumed = await generatorState();
      expect(consumed).toEqual({ events: [], grants: [] });
      observations.push({
        signup,
        first,
        original,
        second,
        third,
        state,
        redemptions,
        sessions,
        consumed,
      });
    }
    return ctx.snapshot(observations);
  },
  ["POST /device/code", "GET /device", "POST /device/approve", "POST /device/token"],
);
