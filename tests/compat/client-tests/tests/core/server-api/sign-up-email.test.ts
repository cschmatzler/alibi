import { expect } from "vitest";
import { z } from "zod";

import { cacheReceipt } from "../../../support/compact-cache-receipt";
import { compatScenario } from "../../../support/scenario";
import { issueSession, revocationObservation } from "../../../support/server-session-revocation";
import { readUserState } from "../../../support/verification";

compatScenario(
  "server signUpEmail creates owned credentials and usable session cookies without an HTTP request",
  async (ctx) => {
    const profile = "server-dispatch-cache";
    const foreign = await issueSession(
      ctx,
      "logical-signup-foreign",
      ctx.uniqueEmail("logical-signup-foreign"),
    );
    const password = "Correct-Horse-Password-205";
    const shape = revocationObservation.extend({
      result: revocationObservation.shape.result.extend({
        value: revocationObservation.shape.result.shape.value
          .unwrap()
          .extend({
            response: z.object({
              token: z.string().nullable(),
              user: z
                .object({
                  id: z.string(),
                  email: z.string(),
                  name: z.string(),
                  emailVerified: z.boolean(),
                  image: z.string().nullable(),
                })
                .passthrough(),
            }),
            cookies: z.array(z.string()),
            status: z.number().optional(),
          })
          .optional(),
      }),
    });
    async function invoke(body: unknown, headers?: Record<string, string>) {
      const raw = await ctx.rawRequest({
        path: `/__test/${profile}/call`,
        method: "POST",
        json: { operation: "signUpEmail", body, ...(headers ? { headers } : {}) },
      });
      expect(raw.status).toBe(200);
      const output = shape.parse(raw.body);
      if (output.result.ok && output.result.value!.response.token) {
        const received = new Headers();
        for (const cookie of output.result.value!.cookies) {
          received.append("set-cookie", cookie);
        }
        return {
          ...output,
          ...(await cacheReceipt(
            received,
            (body as { rememberMe?: boolean }).rememberMe === false ? 60 : 300,
          )),
        };
      }
      return output;
    }
    const before = await readUserState(ctx, foreign.result.data!.user.id);
    const rejected = [];
    const email = ctx.uniqueEmail("logical-signup-validation");
    for (const body of [
      {},
      { name: "Owner", email: "invalid", password },
      { name: "Owner", email, password: "" },
      { name: "Owner", email, password, image: null },
      { name: "Owner", email, password, rememberMe: null },
      { name: "Owner", email, password: "short" },
    ]) {
      const denial = await invoke(body);
      expect(denial.result.ok).toBe(false);
      expect(denial.result.status).toBe(400);
      rejected.push(denial);
    }
    expect(rejected.slice(0, 5).map((result) => result.result.body!.code)).toEqual(
      Array(5).fill("VALIDATION_ERROR"),
    );
    expect(rejected[5]!.result.body!.code).toBe("PASSWORD_TOO_SHORT");
    expect(await readUserState(ctx, foreign.result.data!.user.id)).toEqual(before);
    const created = [];
    for (const [index, rememberMe] of [undefined, false, true].entries()) {
      const email = ctx.uniqueEmail(`logical-signup-owner-${index}`);
      const name = index === 0 ? "" : "New Owner";
      const body = {
        name,
        email: email.toUpperCase(),
        password,
        image: "image-is-a-string",
        callbackURL: "https://external.example.test/done",
        userId: foreign.result.data!.user.id,
        emailVerified: true,
        role: "admin",
        username: 7,
        displayUsername: false,
        ...(rememberMe === undefined ? {} : { rememberMe }),
      };
      const signup = await invoke(body, {
        cookie: foreign.headers.cookie,
        origin: "https://untrusted.example.test",
        "x-forwarded-for": "192.0.2.205",
        "user-agent": "logical-signup-agent",
      });
      expect(signup.result.ok).toBe(true);
      const value = signup.result.value!;
      const user = value.response.user;
      expect(user.id).not.toBe(foreign.result.data!.user.id);
      expect(user).toMatchObject({ name, email, emailVerified: false, image: "image-is-a-string" });
      expect(user.role).not.toBe("admin");
      expect(value.headers.location).toBeUndefined();
      const persisted = await ctx.readUserState({ userId: user.id, includeProfile: true });
      const state = await readUserState(ctx, user.id);
      expect(state.user).toMatchObject({ id: user.id, email, emailVerified: false });
      expect(state.accounts).toHaveLength(1);
      expect(state.accounts[0]).toMatchObject({
        providerId: "credential",
        userId: user.id,
        accountId: user.id,
      });
      expect(state.sessions).toHaveLength(1);
      expect(state.sessions[0]).toMatchObject({ userId: user.id, token: value.response.token });
      const physical = (
        (await ctx.rawRequest({ path: `/__test/${profile}/state` })).body as {
          session: Record<string, unknown>[];
        }
      ).session.find((row) => row.token === value.response.token)!;
      expect(physical).toMatchObject({
        userId: user.id,
        ipAddress: "192.0.2.205",
        userAgent: "logical-signup-agent",
      });
      expect(
        value.cookies
          .find((cookie) => cookie.startsWith("better-auth.session_token="))!
          .includes("Max-Age="),
      ).toBe(rememberMe !== false);
      expect(value.cookies.some((cookie) => cookie.startsWith("better-auth.session_data="))).toBe(
        true,
      );
      expect(value.cookies.some((cookie) => cookie.startsWith("better-auth.dont_remember="))).toBe(
        rememberMe === false,
      );
      const after = signup.events.find((e) => e.stage === "user-after")!;
      expect(after.path).toBe("/sign-up/email");
      expect(after.request).toBeNull();
      expect(after.session).toBeNull();
      const cookie = value.cookies.map((c) => c.split(";")[0]).join("; ");
      const read = await ctx.rawRequest({
        path: `/__test/profiles/${profile}/api/auth/get-session`,
        headers: { cookie },
      });
      expect(read.status).toBe(200);
      const session = (
        read.body as {
          session: { userId: string; token: string; createdAt: string; expiresAt: string };
        }
      ).session;
      expect(session).toMatchObject({ userId: user.id, token: value.response.token });
      const seconds =
        (new Date(session.expiresAt).getTime() - new Date(session.createdAt).getTime()) / 1000;
      if (rememberMe === false) {
        expect(seconds).toBeGreaterThan(86_395);
        expect(seconds).toBeLessThan(86_405);
      } else {
        expect(seconds).toBeGreaterThan(6 * 86_400);
      }
      const duplicate = await invoke(body);
      expect(duplicate.result.ok).toBe(false);
      expect(duplicate.result.status).toBe(422);
      expect(await readUserState(ctx, user.id)).toEqual(state);
      const login = await ctx
        .actor(`logical-signup-login-${index}`, profile)
        .client.signIn.email({ email, password });
      expect(login.error).toBeNull();
      expect(login.data!.user.id).toBe(user.id);
      expect(await readUserState(ctx, foreign.result.data!.user.id)).toEqual(before);
      created.push({ signup, persisted, state, read, duplicate, login });
    }
    return ctx.snapshot({ foreign, before, rejected, created });
  },
  [],
  30_000,
);
