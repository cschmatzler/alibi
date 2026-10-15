import { expect } from "vitest";
import { z } from "zod";

import { cacheReceipt } from "../../../support/compact-cache-receipt";
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
          response: z.object({
            token: z.string().nullable(),
            user: z.object({ id: z.string(), email: z.string() }).passthrough(),
          }),
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
  "server changePassword preserves logical ownership and returns complete usable rotation authority",
  async (ctx) => {
    const profile = "server-dispatch-cache";
    const password = "Correct-Horse-Password-205";
    async function issue(name: string, email: string, existing = false) {
      let cookie = "";
      let issuedHeaders = new Headers();
      const actor = ctx.actor(name, profile);
      const fetchOptions = {
        onSuccess({ response }: { response: Response }) {
          issuedHeaders = new Headers(response.headers);
          cookie = response.headers
            .getSetCookie()
            .map((raw) => raw.split(";")[0])
            .join("; ");
        },
      };
      const result = existing
        ? await actor.client.signIn.email({ email, password, fetchOptions })
        : await actor.client.signUp.email({ name, email, password, fetchOptions });
      expect(result.error).toBeNull();
      expect(result.data).not.toBeNull();
      const publication = {
        body: result.data,
        headers: Object.fromEntries(
          [...issuedHeaders].filter(([name]) => !["date", "content-length"].includes(name)),
        ),
        ...(await cacheReceipt(issuedHeaders)),
      };
      return { actor, result, cookie, publication };
    }
    const email = ctx.uniqueEmail("logical-password-owner");
    const owner = await issue("logical-password-owner", email);
    const sibling = await issue("logical-password-sibling", email, true);
    const foreign = await issue(
      "logical-password-foreign",
      ctx.uniqueEmail("logical-password-foreign"),
    );
    expect(owner.cookie).toContain("better-auth.session_data=");
    async function state() {
      return {
        owner: await readUserState(ctx, owner.result.data!.user.id),
        foreign: await readUserState(ctx, foreign.result.data!.user.id),
      };
    }
    async function invoke(body: unknown, cookie?: string) {
      const response = await ctx.rawRequest({
        path: `/__test/${profile}/call`,
        method: "POST",
        json: {
          operation: "changePassword",
          query: { disableRefresh: true },
          mode: "change-password-headers",
          body,
          ...(cookie === undefined
            ? {}
            : {
                headers: {
                  cookie,
                  "user-agent": "Logical-password-agent",
                  "x-forwarded-for": "198.51.100.31",
                },
              }),
        },
      });
      expect(response.status).toBe(200);
      return observation.parse(response.body);
    }
    const before = await state();
    const malformed = [];
    for (const body of [
      { newPassword: "a-new-password-123" },
      { newPassword: "a-new-password-123", currentPassword: password, revokeOtherSessions: "true" },
    ]) {
      const rejected = await invoke(body);
      expect(rejected.result.status).toBe(400);
      expect(rejected.result.body!.code).toBe("VALIDATION_ERROR");
      malformed.push(rejected);
    }
    const guest = await invoke({
      newPassword: "a-new-password-123",
      currentPassword: "incorrect-password",
      revokeOtherSessions: false,
    });
    expect(guest.result.status).toBe(401);
    expect(guest.result.body!.code).toBe("UNAUTHORIZED");
    const wrong = await invoke(
      {
        newPassword: "a-new-password-123",
        currentPassword: "incorrect-password",
        revokeOtherSessions: false,
      },
      owner.cookie,
    );
    expect(wrong.result.status).toBe(400);
    expect(wrong.result.body!.code).toBe("INVALID_PASSWORD");
    expect(await state()).toEqual(before);
    const kept = await invoke(
      { newPassword: "a-kept-password-123", currentPassword: password },
      owner.cookie,
    );
    expect(kept.result.ok).toBe(true);
    expect(kept.result.value!.response.token).toBeNull();
    expect(kept.result.value!.response.user.id).toBe(owner.result.data!.user.id);
    const keptState = await state();
    expect(keptState.owner.user).toEqual(before.owner.user);
    expect(keptState.owner.sessions).toEqual(before.owner.sessions);
    expect(keptState.foreign).toEqual(before.foreign);
    const { splitSetCookieHeader } = await import("better-auth/cookies");
    expect(
      splitSetCookieHeader(kept.result.value!.headers["set-cookie"]!).some((raw) =>
        raw.startsWith("better-auth.session_token="),
      ),
    ).toBe(false);
    const explicitFalse = await invoke(
      {
        newPassword: "a-kept-password-123",
        currentPassword: "a-kept-password-123",
        revokeOtherSessions: false,
      },
      owner.cookie,
    );
    expect(explicitFalse.result.ok).toBe(true);
    expect(explicitFalse.result.value!.response.token).toBeNull();
    expect(
      splitSetCookieHeader(explicitFalse.result.value!.headers["set-cookie"]!).some((raw) =>
        raw.startsWith("better-auth.session_token="),
      ),
    ).toBe(false);
    expect((await state()).owner.sessions).toEqual(before.owner.sessions);
    const rotated = await invoke(
      {
        newPassword: "a-rotated-password-123",
        currentPassword: "a-kept-password-123",
        revokeOtherSessions: true,
      },
      owner.cookie,
    );
    expect(rotated.result.ok).toBe(true);
    const receipt = rotated.result.value!;
    const token = z.string().parse(receipt.response.token);
    expect(receipt.response.user).toEqual(kept.result.value!.response.user);
    expect(receipt.headers["x-password-result"]).toBe("logical");
    const cookies = splitSetCookieHeader(receipt.headers["set-cookie"]!);
    expect(cookies).toContain("password-first=owned; Path=/; HttpOnly");
    expect(cookies).toContain("password-second=owned; Path=/; HttpOnly");
    expect(cookies.some((raw) => raw.startsWith("better-auth.session_token="))).toBe(true);
    const rotationHeaders = new Headers();
    for (const raw of cookies) rotationHeaders.append("set-cookie", raw);
    const rotationPublication = await cacheReceipt(rotationHeaders);
    const actual = await state();
    expect(actual.owner.sessions).toHaveLength(1);
    expect(actual.owner.sessions[0]!.token).toBe(token);
    expect(actual.foreign).toEqual(keptState.foreign);
    const response = await ctx
      .actor("logical-password-restored", profile)
      .fetch(`${ctx.baseURL}${authProfilePath(profile)}/get-session`, {
        headers: { cookie: cookies.map((raw) => raw.split(";")[0]).join("; ") },
      });
    expect(response.status).toBe(200);
    const restored = z
      .object({
        user: z.object({ id: z.string() }),
        session: z.object({ token: z.string(), userAgent: z.string() }),
      })
      .parse(await response.json());
    expect(restored.user.id).toBe(owner.result.data!.user.id);
    expect(restored.session.token).toBe(token);
    expect(restored.session.userAgent).toBe("Logical-password-agent");
    const revoked = [];
    for (const actor of [owner, sibling]) {
      const denial = await invoke(
        {
          newPassword: "forbidden-stale-password",
          currentPassword: "a-rotated-password-123",
          revokeOtherSessions: false,
        },
        actor.cookie,
      );
      expect(denial.result.status).toBe(401);
      expect(denial.result.body!.code).toBe("UNAUTHORIZED");
      revoked.push(denial);
    }
    expect(await state()).toEqual(actual);
    for (const value of [kept, explicitFalse, rotated]) {
      const after = value.events.find((event) => event.stage === "user-after")!;
      expect(after.path).toBe("/change-password");
      expect(after.request).toBeNull();
      expect(after.session!.user.id).toBe(owner.result.data!.user.id);
    }
    expect((await foreign.actor.client.getSession()).data!.user.id).toBe(
      foreign.result.data!.user.id,
    );
    const signin = await ctx
      .actor("logical-password-final", profile)
      .client.signIn.email({ email, password: "a-rotated-password-123" });
    expect(signin.error).toBeNull();
    expect(signin.data!.user.id).toBe(owner.result.data!.user.id);
    return {
      owner: {
        result: owner.result,
        publication: owner.publication,
        headers: { cookie: owner.cookie },
      },
      sibling: {
        result: sibling.result,
        publication: sibling.publication,
        headers: { cookie: sibling.cookie },
      },
      foreign: {
        result: foreign.result,
        publication: foreign.publication,
        headers: { cookie: foreign.cookie },
      },
      rotationPublication,
      before,
      malformed,
      guest,
      wrong,
      kept,
      keptState,
      explicitFalse,
      rotated,
      actual,
      restored,
      revoked,
      signin,
    };
  },
);
