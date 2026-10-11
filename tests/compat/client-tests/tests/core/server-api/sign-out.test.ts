import { expect } from "bun:test";

import { Cookie } from "tough-cookie";
import { z } from "zod";

import { compatScenario } from "../../../support/scenario";
import { issueSession } from "../../../support/server-session-revocation";
import { readUserState } from "../../../support/verification";
const observation = z
  .object({
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
            response: z
              .object({
                success: z.boolean(),
                url: z.string().optional(),
                redirect: z.boolean().optional(),
              })
              .passthrough(),
            headers: z.record(z.string(), z.string()),
            cookies: z.array(z.string()),
          })
          .passthrough()
          .optional(),
      })
      .passthrough(),
    events: z.array(
      z
        .object({
          stage: z.string(),
          path: z.string().nullable(),
          request: z.unknown(),
          session: z.unknown(),
        })
        .passthrough(),
    ),
  })
  .passthrough();
compatScenario(
  "logical signOut clears cookies for guests and only retires signed-token authority",
  async (ctx) => {
    const email = ctx.uniqueEmail("logical-signout-owner");
    const owner = await issueSession(ctx, "owner", email);
    const other = await issueSession(ctx, "other", email, true);
    const foreign = await issueSession(ctx, "foreign", ctx.uniqueEmail("logical-signout-foreign"));
    const ownerToken = z.string().parse(owner.result.data!.token);
    const foreignToken = z.string().parse(foreign.result.data!.token);
    async function state() {
      return {
        owner: await readUserState(ctx, owner.result.data!.user.id),
        foreign: await readUserState(ctx, foreign.result.data!.user.id),
      };
    }
    async function invoke(headers?: Record<string, string>, body?: unknown) {
      const result = await ctx.rawRequest({
        path: "/__test/server-dispatch-cache/call",
        method: "POST",
        json: {
          operation: "signOut",
          ...(body === undefined ? {} : { body }),
          ...(headers === undefined ? {} : { headers }),
        },
      });
      expect(result.status).toBe(200);
      return observation.parse(result.body);
    }
    function cleared(value: ReturnType<typeof observation.parse>) {
      expect(value.result.value!.response).toEqual({ success: true });
      const names = value.result.value!.cookies.map((raw) => {
        const cookie = Cookie.parse(raw);
        expect(cookie).toBeDefined();
        expect(cookie!.value).toBe("");
        expect(cookie!.maxAge).toBe(0);
        expect(cookie!.path).toBe("/");
        expect(cookie!.httpOnly).toBe(true);
        expect(cookie!.sameSite).toBe("lax");
        return cookie!.key;
      });
      for (const name of [
        "better-auth.session_token",
        "better-auth.session_data",
        "better-auth.dont_remember",
      ]) {
        expect(names).toContain(name);
      }
    }
    const before = await state();
    expect(before.owner.sessions).toHaveLength(2);
    const malformed = [];
    for (const input of [
      null,
      [],
      { callbackURL: 7 },
      { disableRedirect: "false" },
      { state: 7 },
    ]) {
      const denied = await invoke(undefined, input);
      expect(denied.result.status).toBe(400);
      expect(denied.result.body!.code).toBe("VALIDATION_ERROR");
      expect(denied.result.body!.message).toContain("[body");
      malformed.push(denied);
    }
    const missingHeaders = await invoke();
    expect(missingHeaders.result.status).toBe(400);
    expect(missingHeaders.result.body!.message).toBe("Headers is required");
    const guest = await invoke({});
    cleared(guest);
    expect(await state()).toEqual(before);
    const cacheOnly = owner.headers.cookie
      .split("; ")
      .filter((raw) => !raw.startsWith("better-auth.session_token="))
      .join("; ");
    expect(cacheOnly).toContain("better-auth.session_data=");
    const detached = await invoke({ cookie: cacheOnly });
    cleared(detached);
    expect(await state()).toEqual(before);
    const clock = await ctx.rawRequest({
      path: "/__test/expire-session",
      method: "POST",
      json: { token: ownerToken, expiresAt: "2020-01-01T00:00:00.000Z" },
    });
    expect(clock.body).toEqual({ updated: 1 });
    const expired = await state();
    const retired = await invoke(owner.headers, {
      callbackURL: "/bye",
      disableRedirect: true,
      state: "client",
      token: foreignToken,
    });
    cleared(retired);
    const after = await state();
    expect(after.owner.sessions).toEqual(
      expired.owner.sessions.filter((row) => row.token !== ownerToken),
    );
    expect(after.owner.user).toEqual(expired.owner.user);
    expect(after.owner.accounts).toEqual(expired.owner.accounts);
    expect(after.foreign).toEqual(expired.foreign);
    const hook = retired.events.find((event) => event.stage === "user-after")!;
    expect(hook.path).toBe("/sign-out");
    expect(hook.request).toBeNull();
    expect(hook.session).toBeNull();
    const repeated = await invoke(owner.headers, {});
    cleared(repeated);
    expect(await state()).toEqual(after);
    return {
      owner,
      other,
      foreign,
      before,
      malformed,
      missingHeaders,
      guest,
      detached,
      clock,
      expired,
      retired,
      after,
      repeated,
    };
  },
);
