import { expect } from "bun:test";

import { compatScenario } from "../../../support/scenario";
import { readMagicLink } from "./helpers";

compatScenario(
  "magic-link configured plugin quota stops delivery and resets after its window",
  async (ctx) => {
    const actor = ctx.actor("limited", "magic-link-rate-policy");
    const email = ctx.uniqueEmail("magic-rate");
    const send = () =>
      actor.client.signIn.magicLink({
        email,
        fetchOptions: { headers: { "x-forwarded-for": "198.51.100.219" } },
      });
    const first = await send();
    const second = await send();
    expect(first.error).toBeNull();
    expect(second.error).toBeNull();
    const delivered = await readMagicLink(ctx, email);
    const identifier = `magic-link:${delivered.token}`;
    const before = (await ctx.readVerificationState({ identifier })) as any[];
    expect(before).toHaveLength(1);
    const denied = await send();
    expect(denied.error).toMatchObject({
      status: 429,
      message: "Too many requests. Please try again later.",
    });
    expect(await readMagicLink(ctx, email)).toEqual(delivered);
    expect(await ctx.readVerificationState({ identifier })).toEqual(before);
    await Bun.sleep(1200);
    const reset = await send();
    expect(reset.error).toBeNull();
    const latest = await readMagicLink(ctx, email);
    const after = (await ctx.readVerificationState({
      identifier: `magic-link:${latest.token}`,
    })) as any[];
    expect(after).toHaveLength(1);
    const project = (rows: unknown[]) =>
      rows.map((row: any) => ({ ...row, identifier: { token: row.identifier } }));
    return ctx.snapshot({
      first,
      second,
      denied,
      reset,
      delivered,
      latest,
      before: project(before),
      after: project(after),
    });
  },
  ["POST /sign-in/magic-link"],
);
