import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";

type HookEvent = {
  stage: string;
  path: string | null;
  request: unknown;
  session: { user: { id: string } } | null;
  returned: unknown;
  headers: { cookie?: string } | null;
};

compatScenario(
  "server listUserAccounts resolves logical credentials and publishes owned safe results with all headers",
  async (ctx) => {
    async function signup(name: string) {
      let cookie = "";
      const result = await ctx.actor(name, "server-dispatch").client.signUp.email({
        name,
        email: ctx.uniqueEmail(name),
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
      return { result, headers: { cookie } };
    }
    const owner = await signup("logical-list-owner");
    const foreign = await signup("logical-list-foreign");
    const before = (await ctx.rawRequest({ path: "/__test/server-dispatch/state" })).body;
    const reads = [];
    for (const actor of [owner, foreign]) {
      const response = await ctx.rawRequest({
        path: "/__test/server-dispatch/call",
        method: "POST",
        json: {
          operation: "listUserAccounts",
          mode: "account-list-headers",
          headers: actor.headers,
        },
      });
      expect(response.status).toBe(200);
      const observed = response.body as {
        result: {
          ok: boolean;
          value: {
            response: Record<string, unknown>[];
            headers: Record<string, string>;
            cookies: string[];
          };
        };
        events: HookEvent[];
      };
      expect(observed.result.ok).toBe(true);
      const accounts = observed.result.value.response;
      expect(accounts).toHaveLength(1);
      expect(accounts[0]!.userId).toBe(actor.result.data!.user.id);
      expect(accounts[0]!.accountId).toBe(actor.result.data!.user.id);
      expect(accounts[0]!.providerId).toBe("credential");
      expect(accounts[0]!.scopes).toEqual([]);
      for (const secret of ["accessToken", "refreshToken", "idToken", "password", "scope"]) {
        expect(Object.hasOwn(accounts[0]!, secret)).toBe(false);
      }
      expect(observed.result.value.headers["x-account-list"]).toBe("logical");
      const { splitSetCookieHeader } = await import("better-auth/cookies");
      expect(splitSetCookieHeader(observed.result.value.headers["set-cookie"]!)).toEqual([
        "account-first=owned; Path=/; HttpOnly",
        "account-second=owned; Path=/; HttpOnly",
      ]);
      expect(observed.result.value.cookies).toEqual([
        "account-first=owned; Path=/; HttpOnly",
        "account-second=owned; Path=/; HttpOnly",
      ]);
      const after = observed.events.find((event) => event.stage === "user-after")!;
      expect(after.path).toBe("/list-accounts");
      expect(after.request).toBeNull();
      expect(after.session!.user.id).toBe(actor.result.data!.user.id);
      reads.push(observed);
    }
    const denials = [];
    for (const headers of [
      undefined,
      {},
      { cookie: "better-auth.session_token=unissued.signature" },
    ]) {
      const response = await ctx.rawRequest({
        path: "/__test/server-dispatch/call",
        method: "POST",
        json: {
          operation: "listUserAccounts",
          mode: "account-list-headers",
          ...(headers === undefined ? {} : { headers }),
        },
      });
      expect(response.status).toBe(200);
      const observed = response.body as {
        result: {
          ok: boolean;
          status: number;
          body: { code: string };
          headers: Record<string, string>;
        };
        events: HookEvent[];
      };
      expect(observed.result.ok).toBe(false);
      expect(observed.result.status).toBe(401);
      expect(observed.result.body.code).toBe("UNAUTHORIZED");
      expect(observed.result.headers["x-account-list"]).toBe("logical");
      expect(observed.events.find((event) => event.stage === "user-after")!.session).toBeNull();
      if (headers?.cookie) {
        for (const event of observed.events) expect(event.headers!.cookie).toBe(headers.cookie);
      }
      // Invalid input signatures are not cookie issuance receipts. Compare the
      // actual error and callback principals after checking their literal input.
      denials.push({
        result: observed.result,
        events: observed.events.map(({ stage, path, request, session, returned }) => ({
          stage,
          path,
          request,
          session,
          returned,
        })),
      });
    }
    const after = (await ctx.rawRequest({ path: "/__test/server-dispatch/state" })).body;
    expect(after).toEqual(before);
    return { owner, foreign, before, reads, denials, after };
  },
);
