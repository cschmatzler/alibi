import { splitSetCookieHeader } from "better-auth/cookies";
import { expect } from "vitest";
import { z } from "zod";

import { cacheReceipt } from "../../../support/compact-cache-receipt";
import { compatScenario } from "../../../support/scenario";
import { issueSession, revocationObservation } from "../../../support/server-session-revocation";
import { readUserState, storedVerification } from "../../../support/verification";

compatScenario(
  "server deleteUserCallback consumes delivered proofs before ownership rejection and deletes only each owner",
  async (ctx) => {
    const owner = await issueSession(
      ctx,
      "logical-callback-owner",
      ctx.uniqueEmail("logical-callback-owner"),
    );
    const foreign = await issueSession(
      ctx,
      "logical-callback-foreign",
      ctx.uniqueEmail("logical-callback-foreign"),
    );
    const bystander = await issueSession(
      ctx,
      "logical-callback-bystander",
      ctx.uniqueEmail("logical-callback-bystander"),
    );
    async function state() {
      return {
        owner: await readUserState(ctx, owner.result.data!.user.id),
        foreign: await readUserState(ctx, foreign.result.data!.user.id),
        bystander: await readUserState(ctx, bystander.result.data!.user.id),
      };
    }
    async function delivered(headers: Record<string, string>, userId: string) {
      const response = await ctx
        .actor("callback-proof-delivery")
        .fetch(ctx.baseURL + "/__test/profiles/user-lifecycle-delete-mail/api/auth/delete-user", {
          method: "POST",
          headers: { ...headers, "content-type": "application/json" },
          body: JSON.stringify({}),
        });
      expect(response.status).toBe(200);
      expect(await response.json()).toEqual({ success: true, message: "Verification email sent" });
      const control = await ctx.rawRequest({
        path: "/__test/user-lifecycle/control",
        method: "POST",
        json: { profile: "delete-mail", action: "state" },
      });
      expect(control.status).toBe(200);
      const events = z
        .object({
          events: z.array(
            z
              .object({
                stage: z.string(),
                user: z.object({ id: z.string() }).passthrough(),
                token: z.string().optional(),
              })
              .passthrough(),
          ),
        })
        .parse(control.body).events;
      const mail = events.findLast((e) => e.stage === "deletion-mail")!;
      expect(mail.user.id).toBe(userId);
      const token = z.string().parse(mail.token);
      const rows = await storedVerification(ctx, `delete-account-${token}`);
      expect(rows).toHaveLength(1);
      expect(rows[0]!.value).toBe(userId);
      expect(rows[0]!.identifier).toBe(`delete-account-${token}`);
      return { mail, token, rows };
    }
    function proofEvidence(proof: Awaited<ReturnType<typeof delivered>>) {
      return {
        ...proof,
        rows: proof.rows.map((row) => ({
          ...row,
          identifier: {
            prefix: "delete-account-",
            token: row.identifier.slice("delete-account-".length),
          },
          value: { userId: row.value },
        })),
      };
    }
    const schema = revocationObservation
      .extend({
        result: revocationObservation.shape.result.extend({
          body: z.unknown().optional(),
          headers: z.record(z.string(), z.string()).nullable().optional(),
          value: revocationObservation.shape.result.shape.value
            .unwrap()
            .extend({
              response: z.object({ success: z.boolean(), message: z.string() }).passthrough(),
            })
            .passthrough()
            .optional(),
        }),
      })
      .passthrough();
    async function invoke(query: unknown, headers?: Record<string, string>) {
      const response = await ctx.rawRequest({
        path: "/__test/server-dispatch-cache/call",
        method: "POST",
        json: { operation: "deleteUserCallback", query, headers },
      });
      expect(response.status).toBe(200);
      const observed = schema.parse(response.body);
      const raw =
        observed.result.headers?.["set-cookie"] ?? observed.result.value?.headers["set-cookie"];
      let publication;
      if (raw) {
        const cookies = splitSetCookieHeader(raw);
        if (
          cookies.some((c) => c.startsWith("better-auth.session_data=") && !c.includes("Max-Age=0"))
        ) {
          const actual = new Headers();
          for (const cookie of cookies) actual.append("set-cookie", cookie);
          publication = await cacheReceipt(actual);
        }
      }
      return { ...observed, ...(publication ? { publication } : {}) };
    }
    const before = await state();
    const first = await delivered(owner.headers, owner.result.data!.user.id);
    const malformed = [];
    for (const query of [
      {},
      null,
      { token: null },
      { token: 7 },
      { token: first.token, callbackURL: null },
      { token: first.token, callbackURL: 7 },
    ]) {
      const rejected = await invoke(query, owner.headers);
      expect(rejected.result.status).toBe(400);
      expect(rejected.result.body).toMatchObject({ code: "VALIDATION_ERROR" });
      malformed.push(rejected);
    }
    const guest = await invoke({ token: first.token });
    expect(guest.result.status).toBe(404);
    expect(guest.result.body).toEqual({
      code: "FAILED_TO_GET_USER_INFO",
      message: "Failed to get user info",
    });
    expect(await storedVerification(ctx, `delete-account-${first.token}`)).toEqual(first.rows);
    expect(await state()).toEqual(before);
    const wrong = await invoke({ token: first.token }, foreign.headers);
    expect(wrong.result.status).toBe(404);
    expect(wrong.result.body).toEqual({ code: "INVALID_TOKEN", message: "Invalid token" });
    expect(await storedVerification(ctx, `delete-account-${first.token}`)).toEqual([]);
    expect(await state()).toEqual(before);
    expect(wrong.events.find((e) => e.stage === "user-after")!.session!.user.id).toBe(
      foreign.result.data!.user.id,
    );
    const spent = await invoke({ token: first.token }, owner.headers);
    expect(spent.result.status).toBe(404);
    expect(spent.result.body).toEqual({ code: "INVALID_TOKEN", message: "Invalid token" });
    expect(await state()).toEqual(before);
    const completions = [];
    for (const [target, callback] of [
      [owner, ""],
      [foreign, "https://external.example/done?kept=1#deleted"],
    ] as const) {
      const deliveredProof = await delivered(target.headers, target.result.data!.user.id);
      const prior = await state();
      const completed = await invoke(
        {
          token: deliveredProof.token,
          callbackURL: callback,
          userId: bystander.result.data!.user.id,
        },
        target.headers,
      );
      if (callback) {
        expect(completed.result.status).toBe(302);
        expect(completed.result.body).toBeNull();
        expect(completed.result.headers!.location).toBe(callback);
      } else {
        expect(completed.result.ok).toBe(true);
        expect(completed.result.value!.response).toEqual({
          success: true,
          message: "User deleted",
        });
      }
      const raw =
        completed.result.headers?.["set-cookie"] ?? completed.result.value!.headers["set-cookie"]!;
      const cookies = splitSetCookieHeader(raw);
      for (const name of ["session_token", "session_data", "dont_remember"]) {
        expect(
          cookies.some((c) => c.startsWith(`better-auth.${name}=`) && c.includes("Max-Age=0")),
        ).toBe(true);
      }
      expect(
        cookies
          .filter((c) => c.startsWith("better-auth.session_data="))
          .every((c) => c.includes("Max-Age=0")),
      ).toBe(true);
      expect(completed.events.find((e) => e.stage === "user-after")!.session!.user.id).toBe(
        target.result.data!.user.id,
      );
      const after = await state();
      const selected = target === owner ? "owner" : "foreign";
      expect(after[selected].user).toBeNull();
      expect(after[selected].accounts).toEqual([]);
      expect(after[selected].sessions).toEqual([]);
      expect(after.bystander).toEqual(prior.bystander);
      expect(after[target === owner ? "foreign" : "owner"]).toEqual(
        prior[target === owner ? "foreign" : "owner"],
      );
      expect(await storedVerification(ctx, `delete-account-${deliveredProof.token}`)).toEqual([]);
      const replay = await invoke({ token: deliveredProof.token }, target.headers);
      expect(replay.result.status).toBe(404);
      expect(replay.result.body).toEqual({
        code: "FAILED_TO_GET_USER_INFO",
        message: "Failed to get user info",
      });
      expect(await state()).toEqual(after);
      completions.push({ deliveredProof, prior, completed, after, replay });
    }
    return ctx.snapshot({
      owner,
      foreign,
      bystander,
      before,
      first: proofEvidence(first),
      malformed,
      guest,
      wrong,
      spent,
      completions: completions.map((completion) => ({
        ...completion,
        deliveredProof: proofEvidence(completion.deliveredProof),
      })),
    });
  },
  [],
  30_000,
);
