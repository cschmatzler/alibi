import { setTimeout } from "node:timers/promises";

import { expect } from "vitest";
import { z } from "zod";

import { cacheReceipt } from "../../../support/compact-cache-receipt";
import { compatScenario } from "../../../support/scenario";
import { issueSession, revocationObservation } from "../../../support/server-session-revocation";
import { readUserState } from "../../../support/verification";

compatScenario(
  "server signInEmail owns credential admission and usable session publication without a request",
  async (ctx) => {
    const profile = "server-dispatch-cache";
    const owner = await issueSession(
      ctx,
      "logical-signin-owner",
      ctx.uniqueEmail("logical-signin-owner"),
    );
    const foreign = await issueSession(
      ctx,
      "logical-signin-foreign",
      ctx.uniqueEmail("logical-signin-foreign"),
    );
    const email = owner.result.data!.user.email;
    const password = "Correct-Horse-Password-205";
    async function state() {
      return {
        owner: await readUserState(ctx, owner.result.data!.user.id),
        foreign: await readUserState(ctx, foreign.result.data!.user.id),
      };
    }
    const schema = revocationObservation.extend({
      result: revocationObservation.shape.result.extend({
        value: revocationObservation.shape.result.shape.value
          .unwrap()
          .extend({
            response: z.record(z.string(), z.unknown()),
            cookies: z.array(z.string()),
            status: z.number().optional(),
          })
          .optional(),
      }),
    });
    async function invoke(
      body: unknown,
      headers?: Record<string, string>,
      physicalRequest = false,
    ) {
      const response = await ctx.rawRequest({
        path: `/__test/${profile}/call`,
        method: "POST",
        ...(physicalRequest
          ? {
              headers: {
                host: "logical-login.example.test",
                origin: "https://untrusted.example.test",
                "sec-fetch-site": "cross-site",
                "sec-fetch-mode": "navigate",
              },
            }
          : {}),
        json: {
          operation: "signInEmail",
          body,
          ...(headers ? { headers } : {}),
          ...(physicalRequest ? { physicalRequest: true } : {}),
        },
      });
      expect(response.status).toBe(200);
      const value = schema.parse(response.body);
      if (value.result.ok) {
        const actual = new Headers();
        for (const cookie of value.result.value!.cookies) {
          actual.append("set-cookie", cookie);
        }
        return {
          ...value,
          ...(await cacheReceipt(
            actual,
            (body as { rememberMe?: boolean }).rememberMe === false ? 60 : 300,
          )),
        };
      }
      return value;
    }
    const before = await state();
    const rejected = [];
    for (const [body, status] of [
      [{}, 400],
      [{ email: null, password }, 400],
      [{ email, password: 7 }, 400],
      [{ email, password, rememberMe: "no" }, 400],
      [{ email, password, callbackURL: null }, 400],
      [{ email: "not-an-email", password }, 400],
      [{ email, password: "wrong-password" }, 401],
      [{ email: ctx.uniqueEmail("missing-owner"), password }, 401],
      [{ email, password: "" }, 401],
    ] as const) {
      const result = await invoke(body);
      expect(result.result.ok).toBe(false);
      expect(result.result.status).toBe(status);
      rejected.push(result);
    }
    expect(rejected.slice(0, 5).map((row) => row.result.body!.code)).toEqual(
      Array(5).fill("VALIDATION_ERROR"),
    );
    expect(rejected[5]!.result.body!.code).toBe("INVALID_EMAIL");
    expect(rejected.slice(6).map((row) => row.result.body!.code)).toEqual(
      Array(3).fill("INVALID_EMAIL_OR_PASSWORD"),
    );
    const physicalDenial = await invoke({ email, password }, undefined, true);
    expect(physicalDenial.result.ok).toBe(false);
    expect(physicalDenial.result.status).toBe(403);
    expect(await state()).toEqual(before);
    const minted = [];
    const receipts = [];
    for (const [rememberMe, callbackURL] of [
      [undefined, undefined],
      [false, ""],
      [true, "https://external.example.test/done"],
    ] as const) {
      const login = await invoke(
        {
          email: email.toUpperCase(),
          password,
          userId: foreign.result.data!.user.id,
          ...(rememberMe === undefined ? {} : { rememberMe }),
          ...(callbackURL === undefined ? {} : { callbackURL }),
        },
        {
          cookie: foreign.headers.cookie,
          origin: "https://untrusted.example.test",
          "user-agent": "logical-login-agent",
          "x-forwarded-for": "192.0.2.205",
        },
      );
      expect(login.result.ok).toBe(true);
      const value = login.result.value!;
      expect(value.response.user).toEqual(JSON.parse(JSON.stringify(owner.result.data!.user)));
      expect(value.response.redirect).toBe(!!callbackURL);
      expect(value.response.url).toBe(callbackURL);
      expect(value.headers.location).toBe(callbackURL || undefined);
      const token = value.response.token as string;
      expect(minted).not.toContain(token);
      minted.push(token);
      const current = await state();
      const row = current.owner.sessions.find((row) => row.token === token)!;
      expect(row.userId).toBe(owner.result.data!.user.id);
      const storedRows = (
        (await ctx.rawRequest({ path: `/__test/${profile}/state` })).body as {
          session: {
            id: string;
            token: string;
            userId: string;
            ipAddress: string;
            userAgent: string;
          }[];
        }
      ).session;
      const stored = storedRows.find((session) => session.token === token)!;
      expect(stored).toMatchObject({
        id: row.id,
        userId: owner.result.data!.user.id,
        ipAddress: "192.0.2.205",
        userAgent: "logical-login-agent",
      });
      const authority = value.cookies.find((cookie) =>
        cookie.startsWith("better-auth.session_token="),
      )!;
      expect(authority.includes("Max-Age=")).toBe(rememberMe !== false);
      expect(value.cookies.some((cookie) => cookie.startsWith("better-auth.session_data="))).toBe(
        true,
      );
      expect(value.cookies.some((cookie) => cookie.startsWith("better-auth.dont_remember="))).toBe(
        rememberMe === false,
      );
      const after = login.events.find((event) => event.stage === "user-after")!;
      expect(after.path).toBe("/sign-in/email");
      expect(after.request).toBeNull();
      expect(after.session).toBeNull();
      const cookie = value.cookies.map((cookie) => cookie.split(";")[0]).join("; ");
      // JWT signatures are deterministic within one iat second. Separate these
      // publications so scheduling cannot change their repeated-token relationship.
      await setTimeout(1100);
      const read = await ctx.rawRequest({
        path: `/__test/profiles/${profile}/api/auth/get-session`,
        headers: { cookie },
      });
      expect(read.status).toBe(200);
      expect((read.body as { user: { id: string } }).user.id).toBe(owner.result.data!.user.id);
      const session = (
        read.body as { session: { createdAt: string; expiresAt: string; token: string } }
      ).session;
      expect(session.token).toBe(token);
      const seconds =
        (new Date(session.expiresAt).getTime() - new Date(session.createdAt).getTime()) / 1000;
      if (rememberMe === false) {
        expect(seconds).toBeGreaterThan(86_395);
        expect(seconds).toBeLessThan(86_405);
      } else {
        expect(seconds).toBeGreaterThan(6 * 86_400);
      }
      expect(current.owner.user).toEqual(before.owner.user);
      expect(current.owner.accounts).toEqual(before.owner.accounts);
      expect(current.foreign).toEqual(before.foreign);
      receipts.push({ login, current, read });
    }
    const final = await state();
    expect(final.owner.sessions).toHaveLength(before.owner.sessions.length + 3);
    for (const row of before.owner.sessions) {
      expect(final.owner.sessions).toContainEqual(row);
    }
    expect(final.foreign).toEqual(before.foreign);
    return ctx.snapshot({
      owner,
      foreign,
      before,
      rejected,
      physicalDenial,
      minted: minted.map((token) => ({ token })),
      receipts,
      final,
    });
  },
  [],
  30_000,
);
