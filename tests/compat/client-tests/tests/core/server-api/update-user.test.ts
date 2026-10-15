import { expect } from "vitest";
import { z } from "zod";

import { cacheReceipt } from "../../../support/compact-cache-receipt";
import { authProfilePath } from "../../../support/profiles";
import { compatScenario } from "../../../support/scenario";
import { fixtureValue, readUserState } from "../../../support/verification";
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
  "builtin server updateUser persists only owned profile and publishes usable updated cookies",
  async (ctx) => {
    const profile = "server-dispatch-cache";
    async function issue(name: string) {
      let headers = new Headers();
      const actor = ctx.actor(name, profile);
      const result = await actor.client.signUp.email({
        name,
        email: ctx.uniqueEmail(name),
        password: "Correct-Horse-Password-205",
        fetchOptions: {
          onSuccess({ response }) {
            headers = new Headers(response.headers);
          },
        },
      });
      expect(result.error).toBeNull();
      const cookie = headers
        .getSetCookie()
        .map((raw) => raw.split(";")[0])
        .join("; ");
      expect(cookie).toContain("better-auth.session_data=");
      return {
        actor,
        result,
        cookie,
        publication: {
          body: result.data,
          headers: Object.fromEntries(
            [...headers].filter(([name]) => !["date", "content-length"].includes(name)),
          ),
          ...(await cacheReceipt(headers)),
        },
      };
    }
    const owner = await issue("logical-profile-owner");
    const foreign = await issue("logical-profile-foreign");
    async function state() {
      return {
        owner: await readUserState(ctx, owner.result.data!.user.id),
        foreign: await readUserState(ctx, foreign.result.data!.user.id),
      };
    }
    async function invoke(body: unknown, cookie?: string) {
      const result = await ctx.rawRequest({
        path: `/__test/${profile}/call`,
        method: "POST",
        json: {
          operation: "updateUser",
          mode: "profile-headers",
          body,
          query: { disableRefresh: true },
          ...(cookie === undefined ? {} : { headers: { cookie } }),
        },
      });
      expect(result.status).toBe(200);
      return observation.parse(result.body);
    }
    const before = await state();
    const malformed = [];
    for (const body of [[], null, "profile"]) {
      const denial = await invoke(body);
      expect(denial.result.status).toBe(400);
      expect(denial.result.body!.code).toBe("VALIDATION_ERROR");
      malformed.push(denial);
    }
    const guest = await invoke({ name: "Guest" });
    expect(guest.result.status).toBe(401);
    expect(guest.result.body!.code).toBe("UNAUTHORIZED");
    const denied = await invoke({ email: "foreign@example.test" }, owner.cookie);
    expect(denied.result.status).toBe(400);
    expect(denied.result.body!.code).toBe("EMAIL_CAN_NOT_BE_UPDATED");
    expect(await state()).toEqual(before);
    const updates = [];
    const { splitSetCookieHeader } = await import("better-auth/cookies");
    for (const [input, image] of [
      [
        { name: "Logical Profile", image: "https://example.test/avatar.png" },
        "https://example.test/avatar.png",
      ],
      [{ image: null }, null],
    ] as const) {
      const updated = await invoke(input, owner.cookie);
      expect(updated.result.ok).toBe(true);
      expect(updated.result.value!.response).toEqual({ status: true });
      const receipt = updated.result.value!;
      expect(receipt.headers["x-profile-result"]).toBe("logical");
      const cookies = splitSetCookieHeader(receipt.headers["set-cookie"]!);
      expect(cookies).toContain("profile-first=owned; Path=/; HttpOnly");
      expect(cookies).toContain("profile-second=owned; Path=/; HttpOnly");
      expect(cookies.some((raw) => raw.startsWith("better-auth.session_data="))).toBe(true);
      const headers = new Headers();
      for (const raw of cookies) headers.append("set-cookie", raw);
      const actual = await state();
      expect(actual.owner.sessions).toEqual(before.owner.sessions);
      expect(actual.owner.accounts).toEqual(before.owner.accounts);
      expect(actual.foreign).toEqual(before.foreign);
      const response = await ctx
        .actor(`profile-restored-${updates.length}`, profile)
        .fetch(`${ctx.baseURL}${authProfilePath(profile)}/get-session`, {
          headers: { cookie: cookies.map((raw) => raw.split(";")[0]).join("; ") },
        });
      expect(response.status).toBe(200);
      const restored = z
        .object({
          user: z.object({ id: z.string(), name: z.string(), image: z.string().nullable() }),
          session: z.object({ token: z.string() }),
        })
        .parse(await response.json());
      expect(restored.user.id).toBe(owner.result.data!.user.id);
      expect(restored.user.name).toBe("Logical Profile");
      expect(restored.user.image).toBe(image);
      expect(restored.session.token).toBe(before.owner.sessions[0]!.token);
      const after = updated.events.find((event) => event.stage === "user-after")!;
      expect(after.path).toBe("/update-user");
      expect(after.request).toBeNull();
      expect(after.session!.user.id).toBe(owner.result.data!.user.id);
      const stored = z
        .object({
          user: z
            .object({ id: z.string(), name: z.string(), image: z.string().nullable() })
            .passthrough(),
        })
        .parse(
          await fixtureValue(ctx, "/__test/user-state", {
            userId: owner.result.data!.user.id,
            includeProfile: "true",
          }),
        );
      expect(stored.user.id).toBe(owner.result.data!.user.id);
      expect(stored.user.name).toBe("Logical Profile");
      expect(stored.user.image).toBe(image);
      updates.push({ updated, actual, restored, stored, publication: await cacheReceipt(headers) });
    }
    return {
      owner: {
        result: owner.result,
        publication: owner.publication,
        headers: { cookie: owner.cookie },
      },
      foreign: {
        result: foreign.result,
        publication: foreign.publication,
        headers: { cookie: foreign.cookie },
      },
      before,
      malformed,
      guest,
      denied,
      updates,
    };
  },
);
