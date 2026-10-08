import { expect } from "bun:test";

import { compatScenario } from "../../../support/scenario";
import { readMagicLink } from "./helpers";
compatScenario(
  "magic-link generator rejection precedes every proof delivery and identity write and supports recovery",
  async (ctx) => {
    const control = async (json: unknown = {}) => {
      const r = await ctx.rawRequest({
        path: "/__test/magic-link/generator-control",
        method: "POST",
        json,
      });
      expect(r.status).toBe(200);
      return r.body as any;
    };
    const before = await control({ mode: "coded", clear: true });
    expect(before).toMatchObject({ receipts: [], proofCount: 0, userCount: 0, sessionCount: 0 });
    const actor = ctx.actor("owner", "magic-link-generator-reject");
    const email = ctx.uniqueEmail("generator-owner");
    const denied = await actor.client.signIn.magicLink({ email });
    expect(denied.error).toMatchObject({
      status: 403,
      code: "MAGIC_GENERATOR_REJECTED",
      message: "Application generator rejected",
    });
    const rejectedState = await control();
    expect(rejectedState).toMatchObject({
      receipts: [email],
      proofCount: 0,
      userCount: 0,
      sessionCount: 0,
    });
    expect(
      (await ctx.rawRequest({ path: `/__test/magic-link?email=${encodeURIComponent(email)}` }))
        .body,
    ).toBeNull();
    expect((await actor.client.getSession()).data).toBeNull();
    await control({ mode: "success" });
    const issued = await actor.client.signIn.magicLink({ email });
    expect(issued.error).toBeNull();
    const delivery = await readMagicLink(ctx, email);
    expect(delivery.token).toBe(`controlled-link-${email}`);
    const pending = await control();
    expect(pending).toMatchObject({
      receipts: [email, email],
      proofCount: 1,
      userCount: 0,
      sessionCount: 0,
    });
    const verified = await actor.client.magicLink.verify({ query: { token: delivery.token } });
    expect(verified.error).toBeNull();
    expect(verified.data!.user.email).toBe(email);
    const after = await control();
    expect(after).toMatchObject({ proofCount: 0, userCount: 1, sessionCount: 1 });
    const replay = await actor.client.magicLink.verify({ query: { token: delivery.token } });
    expect(replay.error).not.toBeNull();
    return ctx.snapshot({
      before,
      denied,
      rejectedState,
      issued,
      delivery,
      pending,
      verified,
      after,
      replay,
    });
  },
  ["POST /sign-in/magic-link"],
);
