import { expect } from "bun:test";

import { authProfilePath } from "../../../support/profiles";
import { compatScenario } from "../../../support/scenario";
import { events, ip, principals } from "./middleware-shared";

compatScenario(
  "CAPTCHA verifier timeout ends at response headers and slow successful bodies still admit the real principal",
  async (ctx) => {
    const s = await principals(ctx);
    const before = await ctx.readUserState({ userId: s.signup.data!.user.id });
    const started = Date.now();
    const result = await ctx.rawRequest({
      actor: "slow-body",
      path: authProfilePath("captcha-turnstile") + "/sign-in/email",
      method: "POST",
      json: { email: s.signup.data!.user.email, password: "password123" },
      headers: { ...ip, "x-captcha-response": "slow-body" },
    });
    expect(result.status).toBe(200);
    expect(result.body).toMatchObject({ user: { id: s.signup.data!.user.id } });
    expect(Date.now() - started).toBeGreaterThanOrEqual(10_500);

    const receipts = await events(ctx);
    expect(receipts.map((event) => event.kind)).toEqual([
      "early-a",
      "provider",
      "early-b",
      "before",
    ]);

    const authenticated = await ctx.actor("slow-body").client.getSession();
    expect(authenticated.error).toBeNull();
    expect(authenticated.data!.user.id).toBe(s.signup.data!.user.id);

    const body = result.body;

    if (
      body === null ||
      typeof body !== "object" ||
      !("token" in body) ||
      typeof body.token !== "string"
    ) {
      throw new Error("Admitted sign-in must issue a real session token");
    }

    expect(authenticated.data!.session.token).toBe(body.token);

    const authenticatedReceipts = await events(ctx);
    const after = await ctx.readUserState({ userId: s.signup.data!.user.id });
    expect(after).not.toEqual(before);
    expect(await ctx.readUserState({ userId: s.other.data!.user.id })).toEqual(s.foreignBefore);

    return {
      authenticated: ctx.snapshot(authenticated),
      authenticatedReceipts,
      initial: ctx.snapshot(s.signup),
      foreign: ctx.snapshot(s.other),
      foreignBefore: s.foreignBefore,
      before,
      result,
      receipts,
      after,
      foreignAfter: await ctx.readUserState({ userId: s.other.data!.user.id }),
    };
  },
  ["POST /sign-in/email"],
  35_000,
);
