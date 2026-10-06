import { expect } from "bun:test";

import { compatScenario } from "../../../support/scenario";
import {
  control,
  counts,
  force,
  observation,
  retained,
  setup,
  state,
  verify,
} from "./automatic-cleanup-shared";

compatScenario(
  "api-key trusted deferred verification catches actual cleanup errors and forced retry bypasses the shared throttle",
  async (ctx) => {
    const ready = await setup(ctx, "api-key-automatic-deferred");
    const defaultVerification = await verify(ctx, "api-key-automatic", ready.liveOwner.key);
    const beforeWindow = await control(ctx, { action: "wait", kind: "cleanup-complete", count: 1 });
    expect(counts(beforeWindow, "background-register")).toHaveLength(0);

    await control(ctx, { action: "window" });
    await control(ctx, { action: "veto" });
    await control(ctx, { action: "configure", hold: true, observer: "observe" });
    const verified = await verify(ctx, "api-key-automatic-deferred", ready.liveOwner.key);
    const paused = await control(ctx, { action: "wait", kind: "cleanup-enter", count: 1 });
    expect(counts(paused, "background-register")).toHaveLength(1);

    const during = await state(ctx);
    expect(during).toHaveLength(4);
    expect(during.find((row) => row.id === ready.liveOwner.id)?.remaining).toBe(9);

    await control(ctx, { action: "release" });
    const failed = await control(ctx, { action: "wait", kind: "background-complete", count: 1 });
    expect(counts(failed, "cleanup-complete").at(-1)).toEqual({
      kind: "cleanup-complete",
      serial: 2,
      success: false,
    });
    expect(counts(failed, "background-complete")).toEqual([
      { kind: "background-complete", fulfilled: true },
    ]);
    expect(await state(ctx)).toEqual(during);

    const throttled = await ready.other.getSession({
      fetchOptions: { headers: { "x-api-key": ready.liveForeign.key } },
    });
    expect(throttled.error).toBeNull();
    expect(throttled.data?.user.id).toBe(ready.foreignCreated.data!.user.id);

    const suppressed = await control(ctx, {
      action: "wait",
      kind: "background-complete",
      count: 2,
    });
    expect(counts(suppressed, "cleanup-enter")).toHaveLength(2);

    const beforeRetry = await state(ctx);
    expect(beforeRetry).toHaveLength(4);

    await control(ctx, { action: "restore" });
    await control(ctx, { action: "configure" });
    const forcedRetry = await force(ctx, "api-key-automatic-other");
    const final = await control(ctx, { action: "wait", kind: "cleanup-complete", count: 3 });
    expect(counts(final, "cleanup-complete").at(-1)).toEqual({
      kind: "cleanup-complete",
      serial: 3,
      success: true,
    });

    const after = await state(ctx);
    expect(after).toEqual(beforeRetry.filter((row) => row.expiresAt === null));

    await retained(ctx, ready);
    return ctx.snapshot({
      ...observation(ready),
      defaultVerification,
      beforeWindow,
      verified,
      paused,
      during,
      failed,
      throttled,
      suppressed,
      beforeRetry,
      forcedRetry,
      final,
      after,
    });
  },
  ["GET /get-session"],
  30_000,
);
