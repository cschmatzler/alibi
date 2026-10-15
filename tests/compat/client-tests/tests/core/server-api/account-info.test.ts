import { splitSetCookieHeader } from "better-auth/cookies";
import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";
import { readUserState } from "../../../support/verification";

compatScenario(
  "server accountInfo selects through query authority and fetches a profile without rewriting local identity",
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
    const owner = await signup("logical-info-owner");
    const foreign = await signup("logical-info-foreign");
    const subject = ctx.uniqueToken("logical-info-subject");
    const accountId = await ctx.seedOAuthAccount({
      email: owner.result.data!.user.email,
      providerId: "generic",
      accountId: subject,
      accessToken: "current-access",
      refreshToken: "retained-refresh",
      accessTokenExpiresAt: "2039-01-01T00:00:00.000Z",
      scope: "read, write",
    });
    const profile = {
      id: "remote-subject",
      email: "remote-profile@example.test",
      name: "Remote Profile",
      email_verified: true,
      picture: "https://profile.example.test/avatar.png",
      department: "ops",
    };
    expect(
      (
        await ctx.rawRequest({
          path: "/__test/generic-token/control",
          method: "POST",
          json: { profile },
        })
      ).status,
    ).toBe(200);
    async function state() {
      return {
        owner: await readUserState(ctx, owner.result.data!.user.id),
        foreign: await readUserState(ctx, foreign.result.data!.user.id),
        physical: (await ctx.rawRequest({ path: "/__test/social-provider/state" })).body,
      };
    }
    async function userRequests() {
      const rows = (await ctx.rawRequest({ path: "/__test/generic-token/user-receipts" })).body as {
        path: string;
        method: string;
        authorization: string | null;
      }[];
      return rows.map((row) => {
        expect(["/user", "/__test/generic-token/user"]).toContain(row.path);
        // The two recording peers mount their real user-info route at different prefixes.
        return { ...row, path: row.path.replace(/^\/__test\/generic-token/, "") };
      });
    }
    async function invoke(input: Record<string, unknown>) {
      const response = await ctx
        .actor("info-control")
        .fetch(ctx.baseURL + "/__test/generic-token/server-api", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ operation: "account-info", accountId, ...input }),
        });
      const text = await response.text();
      return {
        status: response.status,
        body: text ? (JSON.parse(text) as Record<string, unknown>) : null,
        cookies: response.headers.getSetCookie(),
      };
    }
    const before = await state();
    const denied = [];
    for (const input of [
      {},
      { userId: owner.result.data!.user.id, logicalHeaders: {} },
      { userId: owner.result.data!.user.id, physicalRequest: true },
      { userId: owner.result.data!.user.id, logicalHeaders: foreign.headers },
      { selection: null },
      { selection: { accountId: 7, userId: owner.result.data!.user.id } },
      { selection: { accountId, userId: owner.result.data!.user.id, extra: true } },
    ]) {
      denied.push(await invoke(input));
    }
    expect(denied.map((row) => row.status)).toEqual([400, 401, 401, 400, 400, 400, 400]);
    expect(denied[0]!.body).toEqual({
      code: "USER_ID_OR_SESSION_REQUIRED",
      message: "Either userId or session is required",
    });
    expect(denied[1]!.body).toBeNull();
    expect(denied[2]!.body).toBeNull();
    expect(denied[3]!.body).toEqual({ code: "ACCOUNT_NOT_FOUND", message: "Account not found" });
    for (const row of denied.slice(4)) {
      expect(row.body).toMatchObject({ code: "VALIDATION_ERROR" });
    }
    expect(await userRequests()).toEqual([]);
    expect(await state()).toEqual(before);
    const trusted = await invoke({
      userId: owner.result.data!.user.id,
      logicalBody: { accountId: "foreign-body-selector", userId: foreign.result.data!.user.id },
    });
    expect(trusted.status).toBe(200);
    expect(trusted.body).toEqual({
      user: {
        email: profile.email,
        name: profile.name,
        emailVerified: true,
        image: profile.picture,
      },
      data: { ...profile, emailVerified: true, image: profile.picture },
      account: { id: accountId, providerId: "generic", accountId: subject },
    });
    expect(trusted.cookies.flatMap(splitSetCookieHeader)).toEqual([
      "application_a=first; Path=/; HttpOnly",
      "application_b=second; Path=/; HttpOnly",
    ]);
    const authenticated = await invoke({
      userId: foreign.result.data!.user.id,
      logicalHeaders: owner.headers,
    });
    expect(authenticated.status).toBe(200);
    expect(authenticated.body).toEqual(trusted.body);
    const physical = await invoke({
      userId: foreign.result.data!.user.id,
      logicalHeaders: owner.headers,
      physicalRequest: true,
    });
    expect(physical.status).toBe(200);
    expect(physical.body).toEqual(trusted.body);
    expect(physical.cookies).toEqual([]);
    const peer = await userRequests();
    expect(peer).toEqual(
      Array.from({ length: 3 }, () => ({
        path: "/user",
        method: "GET",
        authorization: "Bearer current-access",
      })),
    );
    expect((await ctx.rawRequest({ path: "/__test/generic-token/receipts" })).body).toEqual([]);
    const after = await state();
    expect(after).toEqual(before);
    return ctx.snapshot({
      owner,
      foreign,
      accountId,
      subject,
      profile,
      before,
      denied,
      trusted,
      authenticated,
      physical,
      peer,
      after,
    });
  },
  [],
  30_000,
);
