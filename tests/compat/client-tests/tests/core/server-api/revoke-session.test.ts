import { expect } from "bun:test";

import { z } from "zod";

import { cacheReceipt } from "../../../support/compact-cache-receipt";
import { compatScenario } from "../../../support/scenario";
import { readUserState } from "../../../support/verification";

const observation = z.object({
  result: z
    .object({
      ok: z.boolean(),
      status: z.number().optional(),
      body: z
        .object({ code: z.string().optional(), message: z.string().optional() })
        .passthrough()
        .optional(),
      value: z
        .object({
          response: z.object({ status: z.boolean() }),
          headers: z.record(z.string(), z.string()),
        })
        .optional(),
    })
    .passthrough(),
  events: z.array(
    z
      .object({
        stage: z.string(),
        path: z.string().nullable(),
        request: z.unknown(),
        session: z
          .object({ user: z.object({ id: z.string() }) })
          .passthrough()
          .nullable(),
      })
      .passthrough(),
  ),
});
compatScenario(
  "logical revokeSession scopes deletion and rejects revoked cached authority",
  async (ctx) => {
    const profile = "server-dispatch-cache";
    const ownerEmail = ctx.uniqueEmail("logical-revoke-owner");
    async function issue(name: string, email: string, signIn = false) {
      let headers = new Headers();
      const actor = ctx.actor(name, profile);
      const fetchOptions = {
        onSuccess({ response }: { response: Response }) {
          headers = new Headers(response.headers);
        },
      };
      const result = signIn
        ? await actor.client.signIn.email({
            email,
            password: "Correct-Horse-Password-205",
            fetchOptions,
          })
        : await actor.client.signUp.email({
            name,
            email,
            password: "Correct-Horse-Password-205",
            fetchOptions,
          });
      expect(result.error).toBeNull();
      const cookie = headers
        .getSetCookie()
        .map((raw) => raw.split(";")[0])
        .join("; ");
      expect(cookie).toContain("better-auth.session_data=");
      return {
        result,
        headers: { cookie },
        publication: {
          body: result.data,
          headers: Object.fromEntries(
            [...headers].filter(([name]) => !["date", "content-length"].includes(name)),
          ),
          ...(await cacheReceipt(headers)),
        },
      };
    }
    const owner = await issue("logical-revoke-owner", ownerEmail);
    const other = await issue("logical-revoke-other", ownerEmail, true);
    const foreign = await issue(
      "logical-revoke-foreign",
      ctx.uniqueEmail("logical-revoke-foreign"),
    );
    async function state() {
      return {
        owner: await readUserState(ctx, owner.result.data!.user.id),
        foreign: await readUserState(ctx, foreign.result.data!.user.id),
      };
    }
    async function invoke(body: unknown, headers?: Record<string, string>) {
      const result = await ctx.rawRequest({
        path: `/__test/${profile}/call`,
        method: "POST",
        json: {
          operation: "revokeSession",
          body,
          query: { disableRefresh: true },
          ...(headers === undefined ? {} : { headers }),
        },
      });
      expect(result.status).toBe(200);
      return observation.parse(result.body);
    }
    const before = await state();
    const malformed = [];
    for (const body of [{}, { token: null }, { token: 7 }]) {
      const denied = await invoke(body);
      expect(denied.result.status).toBe(400);
      expect(denied.result.body!.code).toBe("VALIDATION_ERROR");
      expect(denied.result.body!.message).toContain("[body.token]");
      malformed.push(denied);
    }
    const missingHeaders = await invoke({ token: other.result.data!.token });
    expect(missingHeaders.result.status).toBe(400);
    expect(missingHeaders.result.body!.message).toBe("Headers is required");
    const guest = await invoke({ token: other.result.data!.token }, {});
    expect(guest.result.status).toBe(401);
    expect(guest.result.body!.code).toBe("UNAUTHORIZED");
    const noops = [];
    for (const token of [foreign.result.data!.token, "missing-session", ""]) {
      const noop = await invoke({ token }, owner.headers);
      expect(noop.result.value!.response).toEqual({ status: true });
      expect(noop.result.value!.headers["set-cookie"]).toBeUndefined();
      noops.push(noop);
    }
    expect(await state()).toEqual(before);
    const revoked = await invoke({ token: other.result.data!.token }, owner.headers);
    expect(revoked.result.value!.response).toEqual({ status: true });
    expect(revoked.result.value!.headers["set-cookie"]).toBeUndefined();
    const current = await state();
    expect(current.foreign).toEqual(before.foreign);
    expect(current.owner.user).toEqual(before.owner.user);
    expect(current.owner.accounts).toEqual(before.owner.accounts);
    expect(current.owner.sessions).toEqual(
      before.owner.sessions.filter((session) => session.token !== other.result.data!.token),
    );
    const after = revoked.events.find((event) => event.stage === "user-after")!;
    expect(after.path).toBe("/revoke-session");
    expect(after.request).toBeNull();
    expect(after.session!.user.id).toBe(owner.result.data!.user.id);
    const staleOther = await invoke({ token: foreign.result.data!.token }, other.headers);
    expect(staleOther.result.status).toBe(401);
    expect(staleOther.result.body!.code).toBe("UNAUTHORIZED");
    expect(await state()).toEqual(current);
    const selfRevoke = await invoke({ token: owner.result.data!.token }, owner.headers);
    expect(selfRevoke.result.value!.response).toEqual({ status: true });
    expect(selfRevoke.result.value!.headers["set-cookie"]).toBeUndefined();
    const final = await state();
    expect(final.owner.sessions).toEqual([]);
    expect(final.owner.user).toEqual(before.owner.user);
    expect(final.owner.accounts).toEqual(before.owner.accounts);
    expect(final.foreign).toEqual(before.foreign);
    const staleOwner = await invoke({ token: foreign.result.data!.token }, owner.headers);
    expect(staleOwner.result.status).toBe(401);
    expect(await state()).toEqual(final);
    return {
      owner,
      other,
      foreign,
      before,
      malformed,
      missingHeaders,
      guest,
      noops,
      revoked,
      current,
      staleOther,
      selfRevoke,
      final,
      staleOwner,
    };
  },
);
