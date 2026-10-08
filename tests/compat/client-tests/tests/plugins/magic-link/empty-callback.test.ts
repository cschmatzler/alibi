import { expect } from "bun:test";

import { compatScenario } from "../../../support/scenario";
import { magicLinkClient, readMagicLink } from "./helpers";
compatScenario(
  "magic-link explicit empty callback returns authenticated JSON before new-user redirect selection",
  async (ctx) => {
    const client = magicLinkClient(ctx);
    const email = ctx.uniqueEmail("empty-callback");
    const issue = await client.signIn.magicLink({ email, name: "JSON owner" });
    expect(issue.error).toBeNull();
    const delivery = await readMagicLink(ctx, email);
    const identifier = `magic-link:${delivery.token}`;
    expect(await ctx.readVerificationState({ identifier })).toHaveLength(1);
    const path = `/api/auth/magic-link/verify?token=${encodeURIComponent(delivery.token)}&callbackURL=&newUserCallbackURL=/welcome`;
    const response = await ctx.rawRequest({ path, redirect: "manual" });
    expect(response.status).toBe(200);
    expect(response.location).toBeNull();
    const body = response.body as any;
    expect(body.token).toBeString();
    expect(body.user).toMatchObject({ email, name: "JSON owner", emailVerified: true });
    const session = await client.getSession();
    expect(session.error).toBeNull();
    expect(session.data!.user.id).toBe(body.user.id);
    expect(session.data!.session.token).toBe(body.token);
    const state = await ctx.readUserState({ userId: body.user.id });
    expect((state as any).sessions).toHaveLength(1);
    expect(await ctx.readVerificationState({ identifier })).toEqual([]);
    const replay = await ctx.rawRequest({ path, redirect: "manual" });
    expect(replay.status).toBe(302);
    expect(new URL(replay.location!, ctx.baseURL).searchParams.get("error")).toBe("INVALID_TOKEN");
    expect(await ctx.readUserState({ userId: body.user.id })).toEqual(state);
    return ctx.snapshot({ issue, delivery, response, session, state, replay });
  },
  ["GET /magic-link/verify"],
);
