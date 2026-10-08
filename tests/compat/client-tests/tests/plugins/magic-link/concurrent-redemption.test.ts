import { expect } from "bun:test";

import { raceOneTimeProof } from "../../../support/one-time-race";
import { compatScenario } from "../../../support/scenario";
import { magicLinkClient, readMagicLink } from "./helpers";
compatScenario(
  "overlapping magic-link redemption creates exactly one session and authenticates only the winning browser",
  async (ctx) => {
    const owner = magicLinkClient(ctx, "owner");
    const email = ctx.uniqueEmail("race-owner");
    expect((await owner.signIn.magicLink({ email, name: "Verified owner" })).error).toBeNull();
    const initial = await readMagicLink(ctx, email);
    const created = await owner.magicLink.verify({ query: { token: initial.token } });
    expect(created.error).toBeNull();
    const userId = created.data!.user.id;
    const foreign = await ctx
      .actor("foreign")
      .client.signUp.email({
        email: ctx.uniqueEmail("race-foreign"),
        name: "Foreign owner",
        password: "password123",
      });
    expect(foreign.error).toBeNull();
    const before = (await ctx.readUserState({ userId })) as any;
    const foreignBefore = await ctx.readUserState({ userId: foreign.data!.user.id });
    expect(before.sessions).toHaveLength(1);
    const issued = await owner.signIn.magicLink({ email });
    expect(issued.error).toBeNull();
    const delivered = await readMagicLink(ctx, email);
    const path = `/api/auth/magic-link/verify?token=${encodeURIComponent(delivered.token)}`;
    const responses = await raceOneTimeProof(ctx, path);
    expect(responses.map((r) => r.status)).toEqual([200, 302]);
    const [winner, loser] = responses;
    expect(winner!.body.user.id).toBe(userId);
    expect(winner!.session.user.id).toBe(userId);
    expect(winner!.session.session.token).toBe(winner!.body.token);
    expect(loser!.session).toBeNull();
    expect(loser!.cookies).toEqual([]);
    expect(new URL(loser!.headers.location!, ctx.baseURL).searchParams.get("error")).toBe(
      "INVALID_TOKEN",
    );
    const after = (await ctx.readUserState({ userId })) as any;
    expect(after.user).toEqual(before.user);
    expect(after.accounts).toEqual(before.accounts);
    expect(after.sessions).toHaveLength(2);
    expect(after.sessions).toContainEqual(before.sessions[0]);
    expect(await ctx.readUserState({ userId: foreign.data!.user.id })).toEqual(foreignBefore);
    expect(
      await ctx.readVerificationState({ identifier: `magic-link:${delivered.token}` }),
    ).toEqual([]);
    const replay = await ctx.rawRequest({ path, redirect: "manual" });
    expect(replay.status).toBe(302);
    expect(new URL(replay.location!, ctx.baseURL).searchParams.get("error")).toBe("INVALID_TOKEN");
    expect(await ctx.readUserState({ userId })).toEqual(after);
    return ctx.snapshot({
      created,
      before,
      foreignBefore,
      issued,
      delivered,
      responses,
      after,
      replay,
    });
  },
  ["GET /magic-link/verify"],
);
