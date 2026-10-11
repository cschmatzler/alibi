import { expect } from "bun:test";

import { z } from "zod";

import { compatScenario } from "../../../support/scenario";
import { issueSession, revocationObservation } from "../../../support/server-session-revocation";
import { readUserState } from "../../../support/verification";

compatScenario(
  "server sendVerificationEmail delivers owned proofs for guest and logical session callers",
  async (ctx) => {
    const email = ctx.uniqueEmail("logical-send-owner");
    const missingEmail = ctx.uniqueEmail("logical-send-missing");
    const owner = await issueSession(ctx, "logical-send-owner", email);
    const foreign = await issueSession(
      ctx,
      "logical-send-foreign",
      ctx.uniqueEmail("logical-send-foreign"),
    );
    const schema = revocationObservation.passthrough();
    async function invoke(body: unknown, headers?: Record<string, string>) {
      const response = await ctx.rawRequest({
        path: "/__test/server-dispatch-cache/call",
        method: "POST",
        json: { operation: "sendVerificationEmail", body, headers },
      });
      expect(response.status).toBe(200);
      return schema.parse(response.body);
    }
    async function state() {
      return {
        owner: await readUserState(ctx, owner.result.data!.user.id),
        foreign: await readUserState(ctx, foreign.result.data!.user.id),
      };
    }
    async function delivery(mailbox: string) {
      return ctx.rawRequest({
        path: `/__test/verification-email?email=${encodeURIComponent(mailbox)}`,
      });
    }
    expect((await delivery(email)).status).toBe(404);
    const before = await state();
    const malformed = [];
    for (const body of [
      null,
      {},
      { email: 7 },
      { email: "invalid" },
      { email, callbackURL: null },
      { email, callbackURL: 7 },
    ]) {
      const rejected = await invoke(body, owner.headers);
      expect(rejected.result.status).toBe(400);
      expect(rejected.result.body).toMatchObject({ code: "VALIDATION_ERROR" });
      malformed.push(rejected);
    }
    const unknown = await invoke({ email: missingEmail });
    expect(unknown.result.value!.response).toEqual({ status: true });
    expect((await delivery(missingEmail)).status).toBe(404);
    const callback = "https://external.example/finish?kept=1#verified";
    const guest = await invoke({
      email,
      callbackURL: callback,
      userId: foreign.result.data!.user.id,
    });
    expect(guest.result.value!.response).toEqual({ status: true });
    expect(guest.result.value!.headers["set-cookie"]).toBeUndefined();
    expect(guest.events.find((e) => e.stage === "user-after")!.session).toBeNull();
    const guestDelivery = await delivery(email);
    expect(guestDelivery.status).toBe(200);
    const proof = z.object({ token: z.string(), url: z.string() }).parse(guestDelivery.body);
    const guestURL = new URL(proof.url);
    expect(guestURL.pathname).toBe("/__test/profiles/server-dispatch-cache/api/auth/verify-email");
    expect(guestURL.searchParams.get("token")).toBe(proof.token);
    expect(guestURL.searchParams.get("callbackURL")).toBe(callback);
    const authenticated = await invoke(
      { email: foreign.result.data!.user.email.toUpperCase(), callbackURL: "" },
      foreign.headers,
    );
    expect(authenticated.result.value!.response).toEqual({ status: true });
    expect(authenticated.result.value!.headers["set-cookie"]).toBeUndefined();
    const hook = authenticated.events.find((e) => e.stage === "user-after")!;
    expect(hook.path).toBe("/send-verification-email");
    expect(hook.request).toBeNull();
    expect(hook.session!.user.id).toBe(foreign.result.data!.user.id);
    const authenticatedDelivery = await delivery(foreign.result.data!.user.email);
    const secondProof = z
      .object({ token: z.string(), url: z.string() })
      .parse(authenticatedDelivery.body);
    expect(new URL(secondProof.url).searchParams.get("callbackURL")).toBe("/");
    const mismatch = await invoke({ email: foreign.result.data!.user.email }, owner.headers);
    expect(mismatch.result.status).toBe(400);
    expect(mismatch.result.body).toEqual({ code: "EMAIL_MISMATCH", message: "Email mismatch" });
    expect(await state()).toEqual(before);
    const redeemed = await ctx.rawRequest({
      path: "/__test/server-dispatch-cache/call",
      method: "POST",
      json: { operation: "verifyEmail", query: { token: proof.token } },
    });
    expect(redeemed.status).toBe(200);
    expect(
      z
        .object({
          result: z.object({ ok: z.literal(true), value: z.object({ response: z.unknown() }) }),
        })
        .parse(redeemed.body).result.value.response,
    ).toEqual({ status: true, user: null });
    const after = await state();
    expect(after.owner.user!.emailVerified).toBe(true);
    expect({
      ...after.owner.user!,
      emailVerified: false,
      updatedAt: before.owner.user!.updatedAt,
    }).toEqual({ ...before.owner.user!, updatedAt: before.owner.user!.updatedAt });
    expect(after.owner.accounts).toEqual(before.owner.accounts);
    expect(after.owner.sessions).toEqual(before.owner.sessions);
    expect(after.foreign).toEqual(before.foreign);
    return ctx.snapshot({
      owner,
      foreign,
      before,
      malformed,
      unknown,
      guest,
      guestDelivery,
      authenticated,
      authenticatedDelivery,
      mismatch,
      redeemed,
      after,
    });
  },
  [],
  30_000,
);
