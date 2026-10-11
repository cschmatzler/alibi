import { expect } from "bun:test";

import { splitSetCookieHeader } from "better-auth/cookies";

import { compatScenario } from "../../../support/scenario";
import { readUserState } from "../../../support/verification";

compatScenario(
  "server getAccessToken admits only explicit headerless owners or real session authority",
  async (ctx) => {
    const profile = "generic-token-none";
    async function signup(name: string) {
      const actor = ctx.actor(name, profile);
      let headers = new Headers();
      const result = await actor.client.signUp.email({
        name,
        email: ctx.uniqueEmail(name),
        password: "Password123!",
        fetchOptions: {
          onSuccess({ response }) {
            headers = new Headers(response.headers);
          },
        },
      });
      expect(result.error).toBeNull();
      return {
        result,
        headers: {
          cookie: headers
            .getSetCookie()
            .map((c) => c.split(";")[0])
            .join("; "),
        },
      };
    }
    const owner = await signup("logical-access-owner");
    const foreign = await signup("logical-access-foreign");
    const accountId = await ctx.seedOAuthAccount({
      email: owner.result.data!.user.email,
      providerId: "generic",
      accountId: ctx.uniqueToken("logical-access-subject"),
      accessToken: "current-access",
      refreshToken: "retained-refresh",
      idToken: "retained-id",
      accessTokenExpiresAt: "2039-01-01T00:00:00.000Z",
      scope: "read, write",
    });
    async function state() {
      return {
        owner: await readUserState(ctx, owner.result.data!.user.id),
        foreign: await readUserState(ctx, foreign.result.data!.user.id),
      };
    }
    async function invoke(input: Record<string, unknown>) {
      const response = await ctx
        .actor("access-control")
        .fetch(ctx.baseURL + "/__test/generic-token/server-api", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ operation: "get-access-token", accountId, ...input }),
        });
      const text = await response.text();
      return {
        status: response.status,
        body: text ? (JSON.parse(text) as unknown) : null,
        headers: {
          ...Object.fromEntries(
            [...response.headers].filter(
              ([name]) => !["date", "content-length", "set-cookie"].includes(name),
            ),
          ),
          ...(response.headers.getSetCookie().length
            ? { "set-cookie": response.headers.getSetCookie().join(", ") }
            : {}),
        },
      };
    }
    const before = await state();
    const trusted = await invoke({ userId: owner.result.data!.user.id });
    expect(trusted.status).toBe(200);
    expect(trusted.body).toEqual({
      accessToken: "current-access",
      accessTokenExpiresAt: "2039-01-01T00:00:00.000Z",
      idToken: "retained-id",
      scopes: ["read", "write"],
    });
    expect(splitSetCookieHeader(trusted.headers["set-cookie"]!)).toEqual([
      "application_a=first; Path=/; HttpOnly",
      "application_b=second; Path=/; HttpOnly",
    ]);
    const missing = await invoke({});
    expect(missing.status).toBe(400);
    expect(missing.body).toEqual({
      code: "USER_ID_OR_SESSION_REQUIRED",
      message: "Either userId or session is required",
    });
    const denials = [];
    for (const input of [
      { userId: owner.result.data!.user.id, logicalHeaders: {} },
      { userId: owner.result.data!.user.id, physicalRequest: true },
    ]) {
      const denied = await invoke(input);
      expect(denied.status).toBe(401);
      expect(denied.body).toBeNull();
      denials.push(denied);
    }
    const wrong = await invoke({
      userId: owner.result.data!.user.id,
      logicalHeaders: foreign.headers,
    });
    expect(wrong.status).toBe(400);
    expect(wrong.body).toEqual({ code: "ACCOUNT_NOT_FOUND", message: "Account not found" });
    const owned = await invoke({
      userId: foreign.result.data!.user.id,
      logicalHeaders: owner.headers,
    });
    expect(owned.status).toBe(200);
    expect(owned.body).toEqual(trusted.body);
    const malformed = [];
    for (const selection of [
      null,
      {},
      { accountId: 7, userId: owner.result.data!.user.id },
      { accountId, userId: owner.result.data!.user.id, extra: true },
    ]) {
      const rejected = await invoke({ selection });
      expect(rejected.status).toBe(400);
      expect(rejected.body).toMatchObject({ code: "VALIDATION_ERROR" });
      malformed.push(rejected);
    }
    const after = await state();
    expect(after).toEqual(before);
    return ctx.snapshot({
      owner,
      foreign,
      accountId,
      before,
      trusted,
      missing,
      denials,
      wrong,
      owned,
      malformed,
      after,
    });
  },
  [],
  30_000,
);
