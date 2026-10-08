import { expect } from "bun:test";

import { authProfilePath } from "../../../support/profiles";
import { compatScenario } from "../../../support/scenario";
compatScenario(
  "IdP initiated callback bounces to fresh state-bound authorization before accepting a real grant",
  async (ctx) => {
    const profile = "generic-token-idp-initiated";
    const actor = ctx.actor("owner", profile);
    const email = ctx.uniqueEmail("idp-owner");
    await ctx.rawRequest({
      path: "/__test/generic-token/control",
      method: "POST",
      json: { profile: { id: "idp-subject", email, name: "IdP owner", email_verified: true } },
    });
    const state = async () =>
      (await ctx.rawRequest({ path: "/__test/social-provider/state" })).body as any;
    const before = await state();
    const callback = async (query: string) => {
      const r = await actor.fetch(
        ctx.baseURL + authProfilePath(profile) + "/callback/generic?" + query,
        { redirect: "manual" },
      );
      return { status: r.status, location: r.headers.get("location")! };
    };
    const bounced = await callback("code=idp-unsolicited");
    expect(bounced.status).toBe(302);
    const authorization = new URL(bounced.location);
    expect(authorization.origin).toBe("https://generic.example.invalid");
    expect(authorization.pathname).toBe("/authorize");
    const freshState = authorization.searchParams.get("state")!;
    expect(freshState.length).toBeGreaterThan(20);
    expect(authorization.searchParams.get("code_challenge")).toBeString();
    expect(await state()).toEqual(before);
    expect((await ctx.rawRequest({ path: "/__test/generic-token/receipts" })).body).toEqual([]);
    const wrong = await callback("code=wrong-state&state=unissued-state");
    expect(new URL(wrong.location, ctx.baseURL).searchParams.get("error")).toBe("state_mismatch");
    expect(await state()).toEqual(before);
    const accepted = await callback(`code=real-grant&state=${encodeURIComponent(freshState)}`);
    expect(accepted.status).toBe(302);
    expect(new URL(accepted.location, ctx.baseURL).pathname).toBe("/");
    const session = await actor.client.getSession();
    expect(session.data!.user.email).toBe(email);
    const after = await state();
    expect(after.users).toHaveLength(1);
    expect(after.accounts).toHaveLength(1);
    expect(after.sessions).toHaveLength(1);
    expect(after.accounts[0]).toMatchObject({
      providerId: "generic",
      accountId: "idp-subject",
      userId: session.data!.user.id,
    });
    const receipts = (await ctx.rawRequest({ path: "/__test/generic-token/receipts" }))
      .body as any[];
    expect(receipts.filter((r) => r.path === "/token")).toHaveLength(1);
    const replay = await callback(`code=replay&state=${encodeURIComponent(freshState)}`);
    expect(new URL(replay.location, ctx.baseURL).searchParams.get("error")).toBe("state_mismatch");
    expect(await state()).toEqual(after);
    return ctx.snapshot({ before, bounced, wrong, accepted, session, after, replay });
  },
  ["GET /callback/{}"],
);
