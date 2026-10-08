import { expect } from "bun:test";

import { createAuthClient } from "better-auth/client";
import { deviceAuthorizationClient } from "better-auth/client/plugins";
import { z } from "zod";

import { authProfilePath } from "../../../support/profiles";
import { compatScenario } from "../../../support/scenario";
import { createTracingFetch, type TraceEntry } from "../../../support/trace";
import { readUserState } from "../../../support/verification";

compatScenario(
  "overlapping approved device polls atomically consume one grant and create exactly one session",
  async (ctx) => {
    const profile = "session-adapter-failure";
    const actor = ctx.actor("device-atomic-owner", profile);
    const client = createAuthClient({
      baseURL: ctx.baseURL + authProfilePath(profile),
      plugins: [deviceAuthorizationClient()],
      fetchOptions: { customFetchImpl: actor.fetch },
    });
    const foreign = await ctx
      .actor("device-atomic-foreign")
      .client.signUp.email({
        email: ctx.uniqueEmail("device-atomic-foreign"),
        password: "password123",
        name: "Foreign Device Owner",
      });
    expect(foreign.error).toBeNull();
    const foreignBefore = await ctx.readUserState({ userId: foreign.data!.user.id });
    const signup = await client.signUp.email({
      email: ctx.uniqueEmail("device-atomic-owner"),
      password: "password123",
      name: "Atomic Device Owner",
    });
    expect(signup.error).toBeNull();
    const code = await client.device.code({ client_id: "atomic-device-client", scope: "openid" });
    expect(code.error).toBeNull();
    expect(code.data?.interval).toBe(0);
    const review = await client.device({ query: { user_code: code.data!.user_code } });
    expect(review.error).toBeNull();
    const approved = await client.device.approve({ userCode: code.data!.user_code });
    expect(approved.data).toEqual({ success: true });
    const grant = z
      .object({ id: z.string(), status: z.literal("approved"), userId: z.string() })
      .passthrough()
      .parse(await ctx.readDeviceState({ deviceCode: code.data!.device_code }));
    expect(grant.userId).toBe(signup.data!.user.id);
    const before = await readUserState(ctx, signup.data!.user.id);
    const control = async (operation: string) => {
      const response = await fetch(`${ctx.baseURL}/__test/session-adapter-failure`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ operation, id: grant.id, gate: "consume" }),
      });
      expect(response.status).toBe(200);
      return (await response.json()) as { events: { operation: string; id: string }[] };
    };
    await control("arm");
    const entries: TraceEntry[] = [];
    const poller = createAuthClient({
      baseURL: ctx.baseURL + authProfilePath(profile),
      plugins: [deviceAuthorizationClient()],
      fetchOptions: {
        customFetchImpl: createTracingFetch(ctx.baseURL, "device-overlapping-poller", entries),
      },
    });
    const body = {
      grant_type: "urn:ietf:params:oauth:grant-type:device_code",
      device_code: code.data!.device_code,
      client_id: "atomic-device-client",
    } as const;
    let finished = 0;
    const pending = Promise.all(
      Array.from({ length: 2 }, () =>
        poller.device.token(body).then((result) => {
          finished++;
          return result;
        }),
      ),
    );
    const deadline = Date.now() + 5000;
    let receipt = await control("read");
    while (receipt.events.length < 2 && Date.now() < deadline) {
      await Bun.sleep(10);
      receipt = await control("read");
    }
    expect(receipt.events).toEqual([
      { operation: "consume", id: grant.id },
      { operation: "consume", id: grant.id },
    ]);
    expect(finished).toBe(0);
    expect((await readUserState(ctx, signup.data!.user.id)).sessions).toEqual(before.sessions);
    await control("release-first");
    const results = await Promise.race([
      pending,
      Bun.sleep(5000).then(() => {
        throw new Error("Overlapping actual device polls did not finish after adapter release");
      }),
    ]);
    const winners = results.filter((row) => row.error === null);
    const losers = results.filter((row) => row.error !== null);
    expect(winners).toHaveLength(1);
    expect(losers).toHaveLength(1);
    expect(losers[0]!.error).toMatchObject({
      status: 400,
      error: "invalid_grant",
      error_description: "Invalid device code",
    });
    expect(winners[0]!.data).toMatchObject({ token_type: "Bearer", scope: "openid" });
    expect(winners[0]!.data?.access_token).toBeString();
    ctx.recordTransport(entries.sort((a, b) => a.responseStatus - b.responseStatus));
    const token = winners[0]!.data!.access_token;
    const after = await readUserState(ctx, signup.data!.user.id);
    expect(after.user).toEqual(before.user);
    expect(after.accounts).toEqual(before.accounts);
    expect(after.sessions).toHaveLength(before.sessions.length + 1);
    expect(after.sessions.find((row) => row.token === token)?.userId).toBe(signup.data!.user.id);
    expect(after.sessions.filter((row) => row.token !== token)).toEqual(before.sessions);
    expect(await ctx.readDeviceState({ deviceCode: code.data!.device_code })).toBeNull();
    const third = await client.device.token(body);
    expect(third.error).toMatchObject({ status: 400, error: "invalid_grant" });
    expect((await readUserState(ctx, signup.data!.user.id)).sessions).toEqual(after.sessions);
    const authenticated = await ctx
      .actor("device-atomic-bearer", "bearer-default")
      .client.getSession({ fetchOptions: { headers: { authorization: `Bearer ${token}` } } });
    expect(authenticated.data?.user.id).toBe(signup.data!.user.id);
    expect(authenticated.data?.session.token).toBe(token);
    expect(await ctx.readUserState({ userId: foreign.data!.user.id })).toEqual(foreignBefore);
    expect((await ctx.actor("device-atomic-foreign").client.getSession()).data?.user.id).toBe(
      foreign.data!.user.id,
    );
    await control("restore");
    return ctx.snapshot({
      foreign,
      signup,
      code,
      review,
      approved,
      grant,
      receipt,
      results: [...losers, ...winners],
      after,
      third,
      authenticated,
    });
  },
  ["POST /device/token"],
);
