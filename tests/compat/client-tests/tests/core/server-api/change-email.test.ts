import { splitSetCookieHeader } from "better-auth/cookies";
import { expect } from "vitest";
import { z } from "zod";

import { cacheReceipt } from "../../../support/compact-cache-receipt";
import { compatScenario } from "../../../support/scenario";
import { issueSession, revocationObservation } from "../../../support/server-session-revocation";
import { readUserState } from "../../../support/verification";

compatScenario(
  "server changeEmail delivers and redeems only its authenticated owner's mailbox challenge",
  async (ctx) => {
    const old = ctx.uniqueEmail("logical-mailbox-owner");
    const next = ctx.uniqueEmail("logical-mailbox-next");
    const owner = await issueSession(ctx, "logical-mailbox-owner", old);
    const foreign = await issueSession(
      ctx,
      "logical-mailbox-foreign",
      ctx.uniqueEmail("logical-mailbox-foreign"),
    );
    async function state() {
      return {
        owner: await readUserState(ctx, owner.result.data!.user.id),
        foreign: await readUserState(ctx, foreign.result.data!.user.id),
      };
    }
    const schema = revocationObservation
      .extend({
        result: revocationObservation.shape.result.extend({
          headers: z.record(z.string(), z.string()).nullable().optional(),
          value: revocationObservation.shape.result.shape.value
            .unwrap()
            .extend({ response: z.unknown() })
            .passthrough()
            .optional(),
        }),
      })
      .passthrough();
    async function invoke(
      operation: string,
      body: unknown,
      headers?: Record<string, string>,
      query?: unknown,
    ) {
      const response = await ctx.rawRequest({
        path: "/__test/server-dispatch-cache/call",
        method: "POST",
        json: { operation, body, query, headers },
      });
      expect(response.status).toBe(200);
      const observed = schema.parse(response.body);
      const raw =
        observed.result.headers?.["set-cookie"] ?? observed.result.value?.headers["set-cookie"];
      let publication;
      if (
        raw &&
        splitSetCookieHeader(raw).some(
          (c) => c.startsWith("better-auth.session_data=") && !c.includes("Max-Age=0"),
        )
      ) {
        const actual = new Headers();
        for (const cookie of splitSetCookieHeader(raw)) actual.append("set-cookie", cookie);
        publication = await cacheReceipt(actual);
      }
      return { ...observed, ...(publication ? { publication } : {}) };
    }
    const before = await state();
    expect(before.owner.user!.emailVerified).toBe(false);
    const malformed = [];
    for (const body of [
      null,
      {},
      { newEmail: 7 },
      { newEmail: "invalid" },
      { newEmail: next, callbackURL: null },
      { newEmail: next, callbackURL: 7 },
    ]) {
      const rejected = await invoke("changeEmail", body, owner.headers);
      expect(rejected.result.status).toBe(400);
      expect(rejected.result.body).toMatchObject({ code: "VALIDATION_ERROR" });
      malformed.push(rejected);
    }
    const guest = await invoke("changeEmail", { newEmail: next });
    expect(guest.result.status).toBe(401);
    const same = await invoke("changeEmail", { newEmail: old.toUpperCase() }, owner.headers);
    expect(same.result.status).toBe(400);
    expect(same.result.body).toEqual({ message: "Email is the same" });
    const existing = await invoke(
      "changeEmail",
      { newEmail: foreign.result.data!.user.email.toUpperCase() },
      owner.headers,
    );
    expect(existing.result.ok).toBe(true);
    expect(existing.result.value!.response).toEqual({ status: true });
    expect(
      (
        await ctx.rawRequest({
          path: `/__test/verification-email?email=${encodeURIComponent(foreign.result.data!.user.email)}`,
        })
      ).status,
    ).toBe(404);
    const callback = "https://external.example/mailbox?kept=1#verified";
    const requested = await invoke(
      "changeEmail",
      { newEmail: next.toUpperCase(), callbackURL: callback, userId: foreign.result.data!.user.id },
      owner.headers,
    );
    expect(requested.result.ok).toBe(true);
    expect(requested.result.value!.response).toEqual({ status: true });
    const hook = requested.events.find((e) => e.stage === "user-after")!;
    expect(hook.path).toBe("/change-email");
    expect(hook.request).toBeNull();
    expect(hook.session!.user.id).toBe(owner.result.data!.user.id);
    expect(await state()).toEqual(before);
    const delivered = await ctx.rawRequest({
      path: `/__test/verification-email?email=${encodeURIComponent(next)}`,
    });
    expect(delivered.status).toBe(200);
    const proof = z.object({ url: z.string(), token: z.string() }).parse(delivered.body);
    const url = new URL(proof.url);
    expect(url.pathname).toBe("/__test/profiles/server-dispatch-cache/api/auth/verify-email");
    expect(url.searchParams.get("callbackURL")).toBe(callback);
    expect(url.searchParams.get("token")).toBe(proof.token);
    const verified = await invoke("verifyEmail", undefined, owner.headers, { token: proof.token });
    expect(verified.result.ok).toBe(true);
    expect(verified.result.value!.response).toMatchObject({
      status: true,
      user: { id: owner.result.data!.user.id, email: next, emailVerified: true },
    });
    const after = await state();
    expect(after.owner.user!.email).toBe(next);
    expect(after.owner.user!.emailVerified).toBe(true);
    expect({
      ...after.owner.user!,
      email: old,
      emailVerified: false,
      updatedAt: before.owner.user!.updatedAt,
    }).toEqual({ ...before.owner.user!, updatedAt: before.owner.user!.updatedAt });
    expect(after.owner.accounts).toEqual(before.owner.accounts);
    expect(after.owner.sessions).toEqual(before.owner.sessions);
    expect(after.foreign).toEqual(before.foreign);
    const replay = await invoke("verifyEmail", undefined, owner.headers, { token: proof.token });
    expect(replay.result.status).toBe(401);
    expect(replay.result.body).toEqual({ code: "USER_NOT_FOUND", message: "User not found" });
    expect(await state()).toEqual(after);
    const signin = await ctx
      .actor("logical-mailbox-restored", "server-dispatch-cache")
      .client.signIn.email({ email: next, password: "Correct-Horse-Password-205" });
    expect(signin.error).toBeNull();
    expect(signin.data!.user.id).toBe(owner.result.data!.user.id);
    return ctx.snapshot({
      owner,
      foreign,
      before,
      malformed,
      guest,
      same,
      existing,
      requested,
      delivered,
      verified,
      after,
      replay,
      signin,
    });
  },
  [],
  30_000,
);
