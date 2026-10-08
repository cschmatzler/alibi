import { expect } from "bun:test";

import { createAuthClient } from "better-auth/client";
import { deviceAuthorizationClient } from "better-auth/client/plugins";
import { z } from "zod";

import { authProfilePath } from "../../../support/profiles";
import { compatScenario } from "../../../support/scenario";
import { readUserState } from "../../../support/verification";

compatScenario(
  "overlapping device reviews preserve the first claimant and redact the losing owner",
  async (ctx) => {
    const profile = "session-adapter-failure";
    const actor = (name: string) =>
      createAuthClient({
        baseURL: ctx.baseURL + authProfilePath(profile),
        plugins: [deviceAuthorizationClient()],
        fetchOptions: { customFetchImpl: ctx.actor(name, profile).fetch },
      });
    const first = actor("first-device-reviewer");
    const second = actor("second-device-reviewer");
    const signupA = await first.signUp.email({
      email: ctx.uniqueEmail("first-device-reviewer"),
      password: "password123",
      name: "First Reviewer",
    });
    const signupB = await second.signUp.email({
      email: ctx.uniqueEmail("second-device-reviewer"),
      password: "password123",
      name: "Second Reviewer",
    });
    expect(signupA.error).toBeNull();
    expect(signupB.error).toBeNull();
    const beforeA = await readUserState(ctx, signupA.data!.user.id);
    const beforeB = await readUserState(ctx, signupB.data!.user.id);
    const issued = await first.device.code({
      client_id: "claim-device-client",
      scope: "openid private-scope",
    });
    expect(issued.error).toBeNull();
    const code = issued.data!;
    const initial = z
      .object({ id: z.string(), userId: z.null(), status: z.literal("pending") })
      .passthrough()
      .parse(await ctx.readDeviceState({ deviceCode: code.device_code }));
    const control = async (operation: string) => {
      const response = await fetch(`${ctx.baseURL}/__test/session-adapter-failure`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ operation, gate: "review", id: initial.id }),
      });
      expect(response.status).toBe(200);
      return (await response.json()) as {
        events: { operation: string; ordinal: number; id: string; userId: string | null }[];
      };
    };
    const waitFor = async (count: number) => {
      const deadline = Date.now() + 5000;
      let state = await control("read");
      while (state.events.length < count && Date.now() < deadline) {
        await Bun.sleep(10);
        state = await control("read");
      }
      expect(state.events).toHaveLength(count);
      return state;
    };
    await control("arm");
    let settledA = false,
      settledB = false;
    const pendingA = first.device({ query: { user_code: code.user_code } }).then((result) => {
      settledA = true;
      return result;
    });
    await waitFor(1);
    const pendingB = second.device({ query: { user_code: code.user_code } }).then((result) => {
      settledB = true;
      return result;
    });
    const readReceipts = await waitFor(2);
    expect(readReceipts.events).toEqual(
      [1, 2].map((ordinal) => ({ operation: "review", ordinal, id: initial.id, userId: null })),
    );
    expect(settledA).toBe(false);
    expect(settledB).toBe(false);
    expect(await ctx.readDeviceState({ deviceCode: code.device_code })).toEqual(initial);
    await control("release-first");
    const reviewedA = await pendingA;
    expect(reviewedA.error).toBeNull();
    expect(reviewedA.data).toEqual({
      user_code: code.user_code,
      status: "pending",
      client_id: "claim-device-client",
      scope: "openid private-scope",
    });
    expect(settledB).toBe(false);
    const claimed = await ctx.readDeviceState({ deviceCode: code.device_code });
    expect(claimed).toEqual({ ...initial, userId: signupA.data!.user.id });
    await control("release-second");
    const reviewedB = await pendingB;
    expect(reviewedB.error).toBeNull();
    expect(ctx.snapshot(reviewedB.data)).toEqual({
      user_code: code.user_code,
      status: "pending",
    });
    expect(await ctx.readDeviceState({ deviceCode: code.device_code })).toEqual(claimed);
    const denied = [];
    for (const decision of ["approve", "deny"] as const) {
      const result =
        decision === "approve"
          ? await second.device.approve({ userCode: code.user_code })
          : await second.device.deny({ userCode: code.user_code });
      expect(result.error).toMatchObject({ status: 403, error: "access_denied" });
      expect(await ctx.readDeviceState({ deviceCode: code.device_code })).toEqual(claimed);
      denied.push(result);
    }
    expect(await readUserState(ctx, signupA.data!.user.id)).toEqual(beforeA);
    expect(await readUserState(ctx, signupB.data!.user.id)).toEqual(beforeB);
    const approved = await first.device.approve({ userCode: code.user_code });
    expect(approved.data).toEqual({ success: true });
    expect(await ctx.readDeviceState({ deviceCode: code.device_code })).toMatchObject({
      userId: signupA.data!.user.id,
      status: "approved",
    });
    const redeemed = await first.device.token({
      grant_type: "urn:ietf:params:oauth:grant-type:device_code",
      device_code: code.device_code,
      client_id: "claim-device-client",
    });
    expect(redeemed.error).toBeNull();
    expect(await ctx.readDeviceState({ deviceCode: code.device_code })).toBeNull();
    const after = await readUserState(ctx, signupA.data!.user.id);
    expect(after.sessions).toHaveLength(beforeA.sessions.length + 1);
    expect(
      after.sessions.find((session) => session.token === redeemed.data!.access_token)?.userId,
    ).toBe(signupA.data!.user.id);
    const authenticated = await ctx
      .actor("claimed-device-bearer", "bearer-default")
      .client.getSession({
        fetchOptions: { headers: { authorization: `Bearer ${redeemed.data!.access_token}` } },
      });
    expect(authenticated.data?.user.id).toBe(signupA.data!.user.id);
    expect(authenticated.data?.session.token).toBe(redeemed.data!.access_token);
    expect(await readUserState(ctx, signupB.data!.user.id)).toEqual(beforeB);
    expect((await second.getSession()).data?.user.id).toBe(signupB.data!.user.id);
    await control("restore");
    return ctx.snapshot({
      signupA,
      signupB,
      issued,
      initial,
      readReceipts,
      reviewedA,
      claimed,
      reviewedB,
      denied,
      approved,
      redeemed,
      after,
      authenticated,
    });
  },
  ["GET /device", "POST /device/approve", "POST /device/deny", "POST /device/token"],
);
