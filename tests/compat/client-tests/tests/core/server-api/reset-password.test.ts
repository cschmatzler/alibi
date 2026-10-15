import { expect } from "vitest";
import { z } from "zod";

import { compatScenario } from "../../../support/scenario";
import { issueSession, revocationObservation } from "../../../support/server-session-revocation";
import { readUserState, storedVerification } from "../../../support/verification";

compatScenario(
  "server resetPassword validates and consumes owned proofs without session admission",
  async (ctx) => {
    await ctx.setResetPasswordMode("capture");
    const ownerEmail = ctx.uniqueEmail("logical-reset-owner");
    const foreignEmail = ctx.uniqueEmail("logical-reset-foreign");
    const owner = await issueSession(ctx, "logical-reset-owner", ownerEmail);
    const foreign = await issueSession(ctx, "logical-reset-foreign", foreignEmail);
    async function delivered(email: string) {
      const request = await ctx.actor("reset-delivery").client.requestPasswordReset({ email });
      expect(request.error).toBeNull();
      const response = await ctx.rawRequest({
        path: `/__test/reset-password-token?email=${encodeURIComponent(email)}`,
      });
      expect(response.status).toBe(200);
      return {
        request,
        ...z.object({ token: z.string().min(1), url: z.string() }).parse(response.body),
      };
    }
    const ownerProof = await delivered(ownerEmail);
    const foreignProof = await delivered(foreignEmail);
    async function state() {
      return {
        owner: await readUserState(ctx, owner.result.data!.user.id),
        foreign: await readUserState(ctx, foreign.result.data!.user.id),
        ownerProof: await storedVerification(ctx, `reset-password:${ownerProof.token}`),
        foreignProof: await storedVerification(ctx, `reset-password:${foreignProof.token}`),
      };
    }
    async function invoke(body: unknown, query?: unknown) {
      const result = await ctx.rawRequest({
        path: "/__test/server-dispatch-cache/call",
        method: "POST",
        json: { operation: "resetPassword", body, ...(query === undefined ? {} : { query }) },
      });
      expect(result.status).toBe(200);
      return revocationObservation
        .extend({
          result: revocationObservation.shape.result.extend({
            value: revocationObservation.shape.result.shape.value.unwrap().passthrough().optional(),
          }),
        })
        .passthrough()
        .parse(result.body);
    }
    const before = await state();
    const malformed = [];
    for (const [body, query] of [
      [{}, {}],
      [{ newPassword: null }, {}],
      [{ newPassword: "logical-replacement-205", token: null }, {}],
      [{ newPassword: "logical-replacement-205", token: ownerProof.token }, { token: 7 }],
      [{ newPassword: "logical-replacement-205" }, null],
    ]) {
      const result = await invoke(body, query);
      expect(result.result.status).toBe(400);
      expect(result.result.body!.code).toBe("VALIDATION_ERROR");
      malformed.push(result);
    }
    const missing = await invoke({ newPassword: "logical-replacement-205" });
    expect(missing.result.status).toBe(400);
    expect(missing.result.body!.code).toBe("INVALID_TOKEN");
    const short = await invoke({ newPassword: "short", token: ownerProof.token });
    expect(short.result.status).toBe(400);
    expect(short.result.body!.code).toBe("PASSWORD_TOO_SHORT");
    expect(await state()).toEqual(before);
    const reset = await invoke(
      {
        newPassword: "logical-replacement-205",
        token: ownerProof.token,
        userId: foreign.result.data!.user.id,
      },
      { token: foreignProof.token },
    );
    expect(reset.result.ok).toBe(true);
    expect(reset.result.value!.response).toEqual({ status: true });
    expect(reset.result.value!.headers["set-cookie"]).toBeUndefined();
    const hook = reset.events.find((e) => e.stage === "user-after")!;
    expect(hook.path).toBe("/reset-password");
    expect(hook.request).toBeNull();
    expect(hook.session).toBeNull();
    expect(hook.body).toEqual({
      newPassword: "logical-replacement-205",
      token: ownerProof.token,
      userId: foreign.result.data!.user.id,
    });
    const after = await state();
    expect(after.owner.user).toEqual(before.owner.user);
    expect(after.owner.sessions).toEqual(before.owner.sessions);
    expect(after.foreign).toEqual(before.foreign);
    expect(after.foreignProof).toEqual(before.foreignProof);
    expect(after.ownerProof).toEqual([]);
    const replay = await invoke({ newPassword: "another-password-205", token: ownerProof.token });
    expect(replay.result.status).toBe(400);
    expect(replay.result.body!.code).toBe("INVALID_TOKEN");
    expect(await state()).toEqual(after);
    const oldLogin = await ctx
      .actor("logical-reset-old-login", "server-dispatch-cache")
      .client.signIn.email({ email: ownerEmail, password: "Correct-Horse-Password-205" });
    expect(oldLogin.error?.status).toBe(401);
    const newLogin = await ctx
      .actor("logical-reset-new-login", "server-dispatch-cache")
      .client.signIn.email({ email: ownerEmail, password: "logical-replacement-205" });
    expect(newLogin.error).toBeNull();
    expect(newLogin.data!.user.id).toBe(owner.result.data!.user.id);
    const fallback = await invoke(
      { newPassword: "foreign-replacement-205", token: "" },
      { token: foreignProof.token },
    );
    expect(fallback.result.ok).toBe(true);
    expect(fallback.result.value!.response).toEqual({ status: true });
    expect(await storedVerification(ctx, `reset-password:${foreignProof.token}`)).toEqual([]);
    // Keep full rows, representing only independently issued identifiers by their namespace.
    function proofRows(rows: typeof before.ownerProof) {
      return rows.map((row) => ({
        ...row,
        identifier: {
          namespace: "reset-password:",
          token: row.identifier.slice("reset-password:".length),
        },
        value: { userId: row.value },
      }));
    }
    return ctx.snapshot({
      owner,
      foreign,
      ownerProof,
      foreignProof,
      before: {
        ...before,
        ownerProof: proofRows(before.ownerProof),
        foreignProof: proofRows(before.foreignProof),
      },
      malformed,
      missing,
      short,
      reset,
      after: { ...after, foreignProof: proofRows(after.foreignProof) },
      replay,
      oldLogin,
      newLogin,
      fallback,
    });
  },
  [],
  30_000,
);
