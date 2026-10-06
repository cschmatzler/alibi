import { expect } from "bun:test";

import { compatScenario } from "../../../support/scenario";
import { control, counts, observation, retained, setup, state } from "./automatic-cleanup-shared";

compatScenario(
  "api-key background handler failures preserve consumed usage running cleanup and genuine application 403",
  async (ctx) => {
    const ready = await setup(ctx, "api-key-automatic-deferred");
    await control(ctx, { action: "window" });
    await control(ctx, { action: "configure", hold: true, observer: "throw" });
    const rejected = await ready.owner.getSession({
      fetchOptions: { headers: { "x-api-key": ready.liveOwner.key } },
    });
    expect(rejected.error?.status).toBe(500);

    const paused = await control(ctx, { action: "wait", kind: "cleanup-enter", count: 1 });
    expect(counts(paused, "background-register")).toHaveLength(1);
    expect(counts(paused, "cleanup-complete")).toHaveLength(1);

    await control(ctx, { action: "configure", hold: true, observer: "api" });
    const application = await ready.foreign.getSession({
      fetchOptions: { headers: { "x-api-key": ready.liveForeign.key } },
    });
    expect(application.error).toMatchObject({
      status: 403,
      code: "BACKGROUND_TASK_DENIED",
      message: "Application background observer denied",
    });

    const observed = await control(ctx, { action: "wait", kind: "background-register", count: 2 });
    expect(counts(observed, "cleanup-enter")).toHaveLength(2);

    const during = await state(ctx);
    expect(during).toHaveLength(4);
    expect(during.filter((row) => row.expiresAt === null).map((row) => row.remaining)).toEqual([
      10, 10,
    ]);

    await retained(ctx, ready);
    await control(ctx, { action: "release" });
    const finished = await control(ctx, { action: "wait", kind: "cleanup-complete", count: 2 });
    expect(counts(finished, "background-complete")).toHaveLength(0);

    const after = await state(ctx);
    expect(after).toEqual(during.filter((row) => row.expiresAt === null));

    await retained(ctx, ready);
    return ctx.snapshot({
      ...observation(ready),
      rejected,
      application,
      paused,
      observed,
      during,
      finished,
      after,
    });
  },
  ["GET /get-session"],
  30_000,
);
