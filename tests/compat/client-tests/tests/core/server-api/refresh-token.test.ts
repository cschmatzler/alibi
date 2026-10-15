import { splitSetCookieHeader } from "better-auth/cookies";
import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";
import { readUserState } from "../../../support/verification";

compatScenario(
  "server refreshToken enforces session authority and persists only the selected owner grant",
  async (ctx) => {
    async function signup(name: string) {
      const actor = ctx.actor(name, "generic-token-none");
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
    const owner = await signup("logical-refresh-owner");
    const foreign = await signup("logical-refresh-foreign");
    const accountId = await ctx.seedOAuthAccount({
      email: owner.result.data!.user.email,
      providerId: "generic",
      accountId: ctx.uniqueToken("logical-refresh-subject"),
      accessToken: "old-access",
      refreshToken: "initial-refresh",
      idToken: "retained-id",
      accessTokenExpiresAt: "2039-01-01T00:00:00.000Z",
      refreshTokenExpiresAt: "2040-01-01T00:00:00.000Z",
      scope: "original scope",
    });
    async function state() {
      return {
        owner: await readUserState(ctx, owner.result.data!.user.id),
        foreign: await readUserState(ctx, foreign.result.data!.user.id),
        accounts: (
          (await ctx.rawRequest({ path: "/__test/social-provider/state" })).body as {
            accounts: Record<string, unknown>[];
          }
        ).accounts,
      };
    }
    async function receipts() {
      return (await ctx.rawRequest({ path: "/__test/generic-token/receipts" })).body as {
        path: string;
        body: [string, string][];
        authorization: string | null;
        contentType: string;
        raw: string;
      }[];
    }
    async function invoke(input: Record<string, unknown>) {
      const response = await ctx
        .actor("refresh-control")
        .fetch(ctx.baseURL + "/__test/generic-token/server-api", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ operation: "refresh-token", accountId, ...input }),
        });
      const text = await response.text();
      return {
        status: response.status,
        body: text ? (JSON.parse(text) as Record<string, unknown>) : null,
        cookies: response.headers.getSetCookie(),
      };
    }
    const before = await state();
    const rejected = [];
    for (const input of [
      {},
      { userId: owner.result.data!.user.id, logicalHeaders: {} },
      { userId: owner.result.data!.user.id, physicalRequest: true },
      { userId: owner.result.data!.user.id, logicalHeaders: foreign.headers },
      { selection: { accountId: 7, userId: owner.result.data!.user.id } },
    ]) {
      rejected.push(await invoke(input));
    }
    expect(rejected.map((r) => r.status)).toEqual([400, 401, 401, 400, 400]);
    expect(rejected[0]!.body).toEqual({
      code: "USER_ID_OR_SESSION_REQUIRED",
      message: "Either userId or session is required",
    });
    expect(rejected[1]!.body).toBeNull();
    expect(rejected[2]!.body).toBeNull();
    expect(rejected[3]!.body).toEqual({ code: "ACCOUNT_NOT_FOUND", message: "Account not found" });
    expect(rejected[4]!.body).toMatchObject({ code: "VALIDATION_ERROR" });
    expect(await state()).toEqual(before);
    expect(await receipts()).toEqual([]);
    expect(
      (
        await ctx.rawRequest({
          path: "/__test/generic-token/control",
          method: "POST",
          json: {
            tokenResponse: {
              access_token: "rotated-access",
              refresh_token: "rotated-refresh",
              expires_in: 3600,
              scope: "narrow scope",
            },
          },
        })
      ).status,
    ).toBe(200);
    const trusted = await invoke({ userId: owner.result.data!.user.id });
    expect(trusted.status).toBe(200);
    expect(trusted.body).toMatchObject({
      accessToken: "rotated-access",
      refreshToken: "rotated-refresh",
      refreshTokenExpiresAt: "2040-01-01T00:00:00.000Z",
      idToken: "retained-id",
      scope: "original scope",
      providerId: "generic",
      accountId,
    });
    expect(trusted.body!.accessTokenExpiresAt).toMatch(/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/);
    expect(trusted.cookies.flatMap(splitSetCookieHeader)).toEqual([
      "application_a=first; Path=/; HttpOnly",
      "application_b=second; Path=/; HttpOnly",
    ]);
    const rotated = await state();
    expect(rotated.foreign).toEqual(before.foreign);
    expect(rotated.owner.user).toEqual(before.owner.user);
    expect(rotated.owner.sessions).toEqual(before.owner.sessions);
    const account = rotated.accounts.find((row) => row.id === accountId)!;
    expect(account).toMatchObject({
      accessToken: "rotated-access",
      refreshToken: "rotated-refresh",
      scope: "original scope",
      idToken: "retained-id",
    });
    expect(rotated.accounts.filter((row) => row.id !== accountId)).toEqual(
      before.accounts.filter((row) => row.id !== accountId),
    );
    function observed(receipt: Awaited<ReturnType<typeof receipts>>[number]) {
      const fields = Object.fromEntries(receipt.body);
      expect(receipt.body).toHaveLength(Object.keys(fields).length);
      expect(receipt.contentType).toBe("application/x-www-form-urlencoded");
      const parsed = [...new URLSearchParams(receipt.raw)];
      expect(parsed).toHaveLength(receipt.body.length);
      expect(Object.fromEntries(parsed)).toEqual(fields);
      return {
        path: receipt.path,
        authorization: receipt.authorization,
        contentType: receipt.contentType,
        body: fields,
      };
    }
    const first = observed((await receipts())[0]!);
    expect(first.body).toMatchObject({
      grant_type: "refresh_token",
      refresh_token: "initial-refresh",
      client_id: "client :+&",
    });
    expect(await receipts()).toHaveLength(1);
    const authenticated = await invoke({
      userId: foreign.result.data!.user.id,
      logicalHeaders: owner.headers,
    });
    expect(authenticated.status).toBe(200);
    expect(authenticated.body).toMatchObject({
      accountId,
      accessToken: "rotated-access",
      refreshToken: "rotated-refresh",
    });
    const second = observed((await receipts())[1]!);
    expect(second.body).toMatchObject({
      grant_type: "refresh_token",
      refresh_token: "rotated-refresh",
    });
    expect(await receipts()).toHaveLength(2);
    const after = await state();
    expect(after.foreign).toEqual(before.foreign);
    expect(after.owner.user).toEqual(before.owner.user);
    expect(after.owner.sessions).toEqual(before.owner.sessions);
    return ctx.snapshot({
      owner,
      foreign,
      accountId,
      before,
      rejected,
      trusted,
      rotated,
      first,
      authenticated,
      second,
      after,
    });
  },
  [],
  30_000,
);
