import { expect } from "vitest";
import { z } from "zod";

import { authProfilePath } from "../../../support/profiles";
import { compatScenario } from "../../../support/scenario";
import { readUserState } from "../../../support/verification";

const observation = z.object({
  result: z
    .object({
      ok: z.boolean(),
      status: z.number().optional(),
      body: z.object({ code: z.string().optional() }).passthrough().optional(),
      value: z
        .object({
          response: z.object({ status: z.boolean() }),
          headers: z.record(z.string(), z.string()),
          cookies: z.array(z.string()),
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
  "server unlinkAccount validates before admission and requires fresh actual owner authority for selected row deletion",
  async (ctx) => {
    const profile = "server-dispatch";
    async function signup(name: string) {
      let cookie = "";
      const email = ctx.uniqueEmail(name);
      const { client } = ctx.actor(name, profile);
      const result = await client.signUp.email({
        name,
        email,
        password: "Correct-Horse-Password-205",
        fetchOptions: {
          onSuccess({ response }) {
            cookie = response.headers
              .getSetCookie()
              .map((raw) => raw.split(";")[0])
              .join("; ");
          },
        },
      });
      expect(result.error).toBeNull();
      expect(result.data).not.toBeNull();
      const selected = await ctx.seedOAuthAccount({
        email,
        providerId: "google",
        accountId: `remote-${name}`,
      });
      return { client, email, result, selected, cookie };
    }
    const owner = await signup("logical-unlink-owner");
    const foreign = await signup("logical-unlink-foreign");
    async function state() {
      return {
        owner: await readUserState(ctx, owner.result.data!.user.id),
        foreign: await readUserState(ctx, foreign.result.data!.user.id),
      };
    }
    async function invoke(body: unknown, cookie?: string) {
      const response = await ctx.rawRequest({
        path: "/__test/server-dispatch/call",
        method: "POST",
        json: {
          operation: "unlinkAccount",
          mode: "account-list-headers",
          body,
          ...(cookie === undefined ? {} : { headers: { cookie } }),
        },
      });
      expect(response.status).toBe(200);
      return observation.parse(response.body);
    }
    const before = await state();
    const malformed = [];
    for (const body of [{}, { accountId: 5 }]) {
      const result = await invoke(body);
      expect(result.result.ok).toBe(false);
      expect(result.result.status).toBe(400);
      expect(result.result.body!.code).toBe("VALIDATION_ERROR");
      malformed.push(result);
    }
    const physicalMalformed = [];
    for (const body of [{}, { accountId: 5 }]) {
      const response = await ctx
        .actor("unlink-malformed-http-probe")
        .fetch(`${ctx.baseURL}${authProfilePath(profile)}/unlink-account`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(body),
        });
      const result = { status: response.status, body: await response.json() };
      expect(result.status).toBe(400);
      expect(result.body).toMatchObject({ code: "VALIDATION_ERROR" });
      physicalMalformed.push(result);
    }
    const guest = await invoke({ accountId: owner.selected });
    expect(guest.result.status).toBe(401);
    expect(guest.result.body!.code).toBe("UNAUTHORIZED");
    const wrongOwner = await invoke({ accountId: foreign.selected }, owner.cookie);
    expect(wrongOwner.result.status).toBe(400);
    expect(wrongOwner.result.body!.code).toBe("ACCOUNT_NOT_FOUND");
    expect(await state()).toEqual(before);
    const session = before.owner.sessions.find((row) => row.token === owner.result.data!.token)!;
    const live = await owner.client.getSession();
    expect(live.error).toBeNull();
    expect(live.data!.session.token).toBe(session.token);
    const oldCreatedAt = new Date(live.data!.session.createdAt).toISOString();
    const aged = await ctx.rawRequest({
      path: "/__test/expire-session",
      method: "POST",
      json: {
        token: session.token,
        expiresAt: session.expiresAt,
        createdAt: "2020-01-01T00:00:00.000Z",
      },
    });
    expect(aged.status).toBe(200);
    const stale = await state();
    const logicalStale = await invoke({ accountId: owner.selected }, owner.cookie);
    expect(logicalStale.result.status).toBe(403);
    expect(logicalStale.result.body!.code).toBe("SESSION_NOT_FRESH");
    const physicalResponse = await ctx
      .actor("unlink-http-probe")
      .fetch(`${ctx.baseURL}${authProfilePath(profile)}/unlink-account`, {
        method: "POST",
        headers: { cookie: owner.cookie, "content-type": "application/json" },
        body: JSON.stringify({ accountId: owner.selected }),
      });
    const physicalStale = { status: physicalResponse.status, body: await physicalResponse.json() };
    expect(physicalStale.status).toBe(403);
    expect(physicalStale.body).toMatchObject({ code: "SESSION_NOT_FRESH" });
    expect(await state()).toEqual(stale);
    expect(
      (
        await ctx.rawRequest({
          path: "/__test/expire-session",
          method: "POST",
          json: {
            token: session.token,
            expiresAt: session.expiresAt,
            createdAt: oldCreatedAt,
          },
        })
      ).status,
    ).toBe(200);
    const restored = await state();
    const removed = await invoke({ accountId: owner.selected }, owner.cookie);
    expect(removed.result.ok).toBe(true);
    expect(removed.result.value!.response).toEqual({ status: true });
    expect(removed.result.value!.headers["x-account-list"]).toBe("logical");
    const { splitSetCookieHeader } = await import("better-auth/cookies");
    expect(splitSetCookieHeader(removed.result.value!.headers["set-cookie"]!)).toEqual([
      "account-first=owned; Path=/; HttpOnly",
      "account-second=owned; Path=/; HttpOnly",
    ]);
    expect(removed.result.value!.cookies).toEqual([
      "account-first=owned; Path=/; HttpOnly",
      "account-second=owned; Path=/; HttpOnly",
    ]);
    const afterEvent = removed.events.find((event) => event.stage === "user-after")!;
    expect(afterEvent.path).toBe("/unlink-account");
    expect(afterEvent.request).toBeNull();
    expect(afterEvent.session!.user.id).toBe(owner.result.data!.user.id);
    const after = await state();
    expect(after.owner.accounts).toEqual(
      restored.owner.accounts.filter((row) => row.id !== owner.selected),
    );
    expect(after.owner.user).toEqual(restored.owner.user);
    expect(after.owner.sessions).toEqual(restored.owner.sessions);
    expect(after.foreign).toEqual(restored.foreign);
    const credential = after.owner.accounts.find((row) => row.providerId === "credential")!;
    const replay = await invoke({ accountId: owner.selected }, owner.cookie);
    const last = await invoke({ accountId: credential.id }, owner.cookie);
    for (const denial of [replay, last]) {
      expect(denial.result.status).toBe(400);
      expect(denial.result.body!.code).toBe("FAILED_TO_UNLINK_LAST_ACCOUNT");
    }
    expect(await state()).toEqual(after);
    expect((await owner.client.getSession()).data!.user.id).toBe(owner.result.data!.user.id);
    expect((await foreign.client.getSession()).data!.user.id).toBe(foreign.result.data!.user.id);
    return {
      owner: {
        result: owner.result,
        selectedAccount: { id: owner.selected },
        headers: { cookie: owner.cookie },
      },
      foreign: {
        result: foreign.result,
        selectedAccount: { id: foreign.selected },
        headers: { cookie: foreign.cookie },
      },
      before,
      malformed,
      physicalMalformed,
      guest,
      wrongOwner,
      stale,
      logicalStale,
      physicalStale,
      restored,
      removed,
      after,
      replay,
      last,
    };
  },
);
