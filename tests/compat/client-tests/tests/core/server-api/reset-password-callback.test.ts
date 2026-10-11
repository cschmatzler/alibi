import { expect } from "bun:test";

import { z } from "zod";

import { compatScenario } from "../../../support/scenario";
import { issueSession } from "../../../support/server-session-revocation";
import { readUserState, storedVerification } from "../../../support/verification";

compatScenario(
  "server requestPasswordResetCallback retains logical params, redirect errors and redeemable proof",
  async (ctx) => {
    await ctx.setResetPasswordMode("capture");
    const email = ctx.uniqueEmail("callback-owner");
    const owner = await issueSession(ctx, "callback-owner", email);
    const foreign = await issueSession(
      ctx,
      "callback-foreign",
      ctx.uniqueEmail("callback-foreign"),
    );
    const requested = await ctx
      .actor("callback-delivery", "server-dispatch-cache")
      .client.requestPasswordReset({ email });
    expect(requested.error).toBeNull();
    const delivered = await ctx.rawRequest({
      path: `/__test/reset-password-token?email=${encodeURIComponent(email)}`,
    });
    expect(delivered.status).toBe(200);
    const proof = z.object({ token: z.string().length(24), url: z.string() }).parse(delivered.body);
    async function state() {
      return {
        owner: await readUserState(ctx, owner.result.data!.user.id),
        foreign: await readUserState(ctx, foreign.result.data!.user.id),
        proof: await storedVerification(ctx, `reset-password:${proof.token}`),
      };
    }
    const schema = z
      .object({
        result: z
          .object({
            ok: z.boolean(),
            status: z.number().nullable().optional(),
            body: z.unknown().optional(),
            message: z.string().optional(),
            headers: z.record(z.string(), z.string()).nullable().optional(),
          })
          .passthrough(),
        events: z.array(
          z
            .object({
              stage: z.string(),
              path: z.string().nullable(),
              params: z.unknown().optional(),
              request: z.unknown(),
              session: z.unknown(),
            })
            .passthrough(),
        ),
      })
      .passthrough();
    async function invoke(token: string, query: unknown, patched = false) {
      const response = await ctx.rawRequest({
        path: "/__test/server-dispatch-cache/call",
        method: "POST",
        json: {
          operation: "requestPasswordResetCallback",
          params: { token },
          query,
          ...(patched ? { mode: "callback-params", body: { token: proof.token } } : {}),
        },
      });
      expect(response.status).toBe(200);
      const observed = schema.parse(response.body);
      for (const event of observed.events.filter((e) => e.stage.endsWith("-after"))) {
        expect(event.params).toEqual({ token: patched ? proof.token : token });
      }
      return observed;
    }
    const before = await state();
    const malformed = [];
    for (const query of [{}, null, { callbackURL: null }, { callbackURL: 7 }]) {
      const denied = await invoke(proof.token, query);
      expect(denied.result.status).toBe(400);
      expect(denied.result.body).toMatchObject({ code: "VALIDATION_ERROR" });
      malformed.push(denied);
    }
    const redirects = [];
    for (const [token, callbackURL, key, value] of [
      ["missing-proof", "/reset?application=retained#step", "error", "INVALID_TOKEN"],
      [proof.token, "/reset?application=retained#step", "token", proof.token],
      [
        proof.token,
        "https://external.example/reset?application=retained#step",
        "token",
        proof.token,
      ],
      [proof.token, "", "error", "INVALID_TOKEN"],
    ] as const) {
      const observed = await invoke(token, { callbackURL });
      expect(observed.result.ok).toBe(false);
      expect(observed.result.status).toBe(302);
      expect(observed.result.body).toBeNull();
      expect(observed.result.message).toBe("");
      const expected = new URL(
        callbackURL || "/__test/profiles/server-dispatch-cache/api/auth/error",
        ctx.baseURL,
      );
      expected.searchParams.set(key, value);
      expect(observed.result.headers!.location).toBe(expected.href);
      const hook = observed.events.find((e) => e.stage === "user-after")!;
      expect(hook.path).toBe("/reset-password/:token");
      expect(hook.request).toBeNull();
      expect(hook.session).toBeNull();
      expect(hook.returned).toEqual({ api: true, status: 302 });
      expect(await state()).toEqual(before);
      redirects.push(observed);
    }
    const patched = await invoke("missing-proof", { callbackURL: "/patched" }, true);
    expect(patched.result.status).toBe(302);
    expect(new URL(patched.result.headers!.location!).searchParams.get("token")).toBe(proof.token);
    expect(await state()).toEqual(before);
    const reset = await ctx
      .actor("callback-reset", "server-dispatch-cache")
      .client.resetPassword({ token: proof.token, newPassword: "callback-replacement-205" });
    expect(reset.error).toBeNull();
    expect(await storedVerification(ctx, `reset-password:${proof.token}`)).toEqual([]);
    const login = await ctx
      .actor("callback-login", "server-dispatch-cache")
      .client.signIn.email({ email, password: "callback-replacement-205" });
    expect(login.error).toBeNull();
    expect(login.data!.user.id).toBe(owner.result.data!.user.id);
    expect(await readUserState(ctx, foreign.result.data!.user.id)).toEqual(before.foreign);
    return ctx.snapshot({
      owner,
      foreign,
      requested,
      delivered,
      before: {
        ...before,
        proof: before.proof.map((row) => ({
          ...row,
          identifier: {
            namespace: "reset-password:",
            token: row.identifier.slice("reset-password:".length),
          },
          value: { userId: row.value },
        })),
      },
      malformed,
      redirects,
      patched,
      reset,
      login,
    });
  },
  [],
  30_000,
);
