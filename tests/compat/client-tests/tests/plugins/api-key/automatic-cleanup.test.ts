import { expect } from "bun:test";

import { compatScenario } from "../../../support/scenario";
import {
  client,
  control,
  counts,
  force,
  observation,
  retained,
  setup,
  state,
  verify,
} from "./automatic-cleanup-shared";

// The runtime's real module-global throttle is ten seconds. Only these owners
// receive 30s for both actual windows, preserving all other default deadlines.
compatScenario(
  "api-key automatic creation starts hot global cleanup before a rejecting generator and ignores the optional observer",
  async (ctx) => {
    const ready = await setup(ctx, "api-key-automatic");
    await control(ctx, { action: "window" });
    await control(ctx, { action: "configure", hold: true, generator: "throw" });
    const rejected = await ready.owner.apiKey.create({ name: "generator-rejected" });
    expect(rejected.error?.status).toBe(500);

    const paused = await control(ctx, { action: "wait", kind: "cleanup-enter", count: 1 });
    expect(paused.slice(-2)).toMatchObject([
      { kind: "cleanup-enter", profile: "api-key-automatic", serial: 2 },
      { kind: "generator" },
    ]);
    expect(counts(paused, "cleanup-complete")).toHaveLength(1);
    expect(counts(paused, "background-register")).toHaveLength(0);
    expect(await state(ctx)).toEqual(ready.baseline);

    const guest = client(ctx, "generator-guest", "api-key-automatic");
    const guestRejected = await guest.apiKey.create({ name: "guest-generator-rejected" });
    expect(guestRejected.error).toMatchObject({
      status: 401,
      code: "UNAUTHORIZED_SESSION",
      message: "Unauthorized or invalid session",
    });
    expect(await control(ctx, { action: "wait", kind: "cleanup-enter", count: 1 })).toEqual(paused);
    expect(await state(ctx)).toEqual(ready.baseline);

    await retained(ctx, ready);
    const session = await ready.owner.getSession({
      fetchOptions: { headers: { "x-api-key": ready.liveOwner.key } },
    });
    expect(session.error).toBeNull();
    expect(session.data?.user.id).toBe(ready.created.data!.user.id);

    const defaultVerification = await verify(ctx, "api-key-automatic", ready.liveOwner.key);
    const otherSession = await ready.other.getSession({
      fetchOptions: { headers: { "x-api-key": ready.liveForeign.key } },
    });
    expect(otherSession.error).toBeNull();
    expect(otherSession.data?.user.id).toBe(ready.foreignCreated.data!.user.id);

    const shared = await control(ctx, { action: "wait", kind: "background-complete", count: 1 });
    expect(counts(shared, "cleanup-enter")).toHaveLength(2);
    expect(counts(shared, "background-register")).toHaveLength(1);

    const during = await state(ctx);
    expect(during).toHaveLength(4);
    expect(during.find((row) => row.id === ready.liveOwner.id)?.remaining).toBe(9);
    expect(during.find((row) => row.id === ready.liveForeign.id)?.remaining).toBe(10);

    await control(ctx, { action: "release" });
    const finished = await control(ctx, { action: "wait", kind: "cleanup-complete", count: 2 });
    const after = await state(ctx);
    expect(after.map((row) => row.name)).toEqual(["c-live-owner", "d-live-foreign"]);
    expect(after).toEqual(during.filter((row) => row.expiresAt === null));

    await retained(ctx, ready);
    await control(ctx, { action: "configure" });
    const forcedAgain = await force(ctx, "api-key-automatic-other");
    const final = await control(ctx, { action: "wait", kind: "cleanup-complete", count: 3 });
    expect(counts(final, "cleanup-enter").at(-1)).toMatchObject({
      profile: "api-key-automatic-other",
      serial: 3,
    });
    expect(await state(ctx)).toEqual(after);

    return ctx.snapshot({
      ...observation(ready),
      rejected,
      guestRejected,
      paused,
      session,
      defaultVerification,
      otherSession,
      shared,
      during,
      finished,
      after,
      forcedAgain,
      final,
    });
  },
  ["POST /api-key/create", "GET /get-session"],
  30_000,
);
