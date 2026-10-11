import { expect } from "bun:test";

import { z } from "zod";

import { compatScenario } from "../../../support/scenario";
import { issueSession, revocationObservation } from "../../../support/server-session-revocation";
import { readUserState } from "../../../support/verification";

compatScenario(
  "server ok ignores input and credentials without reading or changing authentication state",
  async (ctx) => {
    const owner = await issueSession(
      ctx,
      "logical-health-owner",
      ctx.uniqueEmail("logical-health-owner"),
    );
    const before = await readUserState(ctx, owner.result.data!.user.id);
    const schema = revocationObservation
      .extend({
        result: revocationObservation.shape.result.extend({
          value: revocationObservation.shape.result.shape.value
            .unwrap()
            .extend({ response: z.object({ ok: z.boolean() }).passthrough() })
            .passthrough()
            .optional(),
        }),
      })
      .passthrough();
    const observations = [];
    for (const input of [
      {},
      { body: null, query: 7, headers: owner.headers },
      {
        body: { userId: owner.result.data!.user.id, ok: false },
        query: ["ignored"],
        headers: { authorization: "Bearer invalid.signature" },
      },
    ]) {
      const response = await ctx.rawRequest({
        path: "/__test/server-dispatch-cache/call",
        method: "POST",
        json: { operation: "ok", ...input },
      });
      expect(response.status).toBe(200);
      const observed = schema.parse(response.body);
      expect(observed.result.ok).toBe(true);
      expect(observed.result.value!.response).toEqual({ ok: true });
      expect(observed.result.value!.headers["set-cookie"]).toBeUndefined();
      const after = observed.events.find((event) => event.stage === "user-after")!;
      expect(after.path).toBe("/ok");
      expect(after.request).toBeNull();
      expect(after.session).toBeNull();
      expect(await readUserState(ctx, owner.result.data!.user.id)).toEqual(before);
      observations.push(observed);
    }
    return ctx.snapshot({
      owner,
      before,
      observations,
      after: await readUserState(ctx, owner.result.data!.user.id),
    });
  },
  [],
  30_000,
);
