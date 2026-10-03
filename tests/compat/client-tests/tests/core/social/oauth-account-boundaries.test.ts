import { expect } from "bun:test";

import { authProfilePath } from "../../../support/profiles";
import { compatScenario, type ScenarioContext } from "../../../support/scenario";
async function state(ctx: ScenarioContext): Promise<any> {
  return (await ctx.rawRequest({ path: "/__test/social-provider/state" })).body;
}
async function save(ctx: ScenarioContext, name: string, value: unknown) {
  if (process.env.CLOSE188_EVIDENCE_DIR)
    await Bun.write(
      `${process.env.CLOSE188_EVIDENCE_DIR}/${Bun.hash(ctx.baseURL + name)}.json`,
      JSON.stringify({ name, baseURL: ctx.baseURL, value }, null, 2),
    );
}
for (const endpoint of ["/get-access-token", "/account-info"])
  for (const token of [null, ""]) {
    const name = `oauth automatic ${endpoint} ${token === null ? "null" : "empty"} refresh keeps response distinct from stored grant`;
    compatScenario(
      name,
      async (ctx) => {
        const fixture = "generic-token-dynamic-none";
        const actor = ctx.actor("owner", fixture);
        const email = ctx.uniqueEmail("owner");
        expect(
          (await actor.client.signUp.email({ email, password: "Password123!", name: "Owner" }))
            .error,
        ).toBeNull();
        const id = await ctx.seedOAuthAccount({
          email,
          providerId: "generic",
          accountId: ctx.uniqueToken("subject"),
          accessToken: "old-access",
          refreshToken: "old-refresh",
          idToken: "old-id",
          accessTokenExpiresAt: "2020-01-01T00:00:00.000Z",
          refreshTokenExpiresAt: "2020-01-01T00:00:00.000Z",
          scope: "original scope",
        });
        const before = await state(ctx);
        await ctx.rawRequest({
          path: "/__test/generic-token/control",
          method: "POST",
          json: {
            tokenResponse: {
              access_token: token,
              refresh_token: "",
              id_token: "",
              expires_in: 0,
              refresh_token_expires_in: 0,
            },
            profile: {
              id: "subject",
              email: "info@example.invalid",
              name: "Info",
              email_verified: true,
            },
          },
        });
        const response =
          endpoint === "/get-access-token"
            ? await actor.client.getAccessToken({ accountId: id })
            : await actor.fetch(
                ctx.baseURL + authProfilePath(fixture) + `/account-info?accountId=${id}`,
              );
        const output =
          response instanceof Response
            ? { status: response.status, body: await response.json() }
            : response;
        const after = await state(ctx);
        expect(after.users).toEqual(before.users);
        expect(after.sessions).toEqual(before.sessions);
        const changed = after.accounts.find((a: any) => a.id === id);
        expect(changed.accessToken).toBe(token);
        expect(changed.refreshToken).toBe("old-refresh");
        expect(changed.idToken).toBe("old-id");
        expect(changed.refreshTokenExpiresAt).toBe("2020-01-01T00:00:00.000Z");
        if (endpoint === "/get-access-token") {
          expect((output as any).error).toBeNull();
          expect((output as any).data.accessToken).toBe(token ?? "old-access");
          expect((output as any).data.idToken).toBe("");
        } else if (token === "") {
          expect((output as any).status).toBe(400);
          expect((output as any).body.code).toBe("ACCESS_TOKEN_NOT_FOUND");
        } else {
          expect((output as any).status).toBe(200);
          expect((output as any).body.user.email).toBe("info@example.invalid");
        }
        await save(ctx, name, { before, output, after });
        return { output: ctx.snapshot(output), before, after };
      },
      ["POST /get-access-token", "GET /account-info"],
    );
  }
compatScenario(
  "oauth changed verified email override retains original account authority",
  async (ctx) => {
    const fixture = "generic-token-override";
    const actor = ctx.actor("owner", fixture);
    async function flow(email: string, verified: boolean) {
      await ctx.rawRequest({
        path: "/__test/generic-token/control",
        method: "POST",
        json: {
          profile: {
            id: "stable-subject",
            name: "Owner",
            email,
            email_verified: verified,
            picture: "https://images.example.invalid/owner.png",
          },
        },
      });
      const start = await actor.client.signIn.social({
        provider: "generic",
        callbackURL: "/dashboard",
      });
      expect(start.error).toBeNull();
      const url = new URL(start.data!.url!);
      const r = await actor.fetch(
        ctx.baseURL +
          authProfilePath(fixture) +
          `/callback/generic?code=code&state=${encodeURIComponent(url.searchParams.get("state")!)}`,
        { redirect: "manual" },
      );
      expect(r.headers.get("location")).toBe("/dashboard");
      return actor.client.getSession();
    }
    const first = await flow(ctx.uniqueEmail("first"), true);
    const before = await state(ctx);
    const email = ctx.uniqueEmail("changed");
    const second = await flow(email, true);
    const after = await state(ctx);
    expect(second.data!.user.id).toBe(first.data!.user.id);
    expect(second.data!.user.email).toBe(email);
    expect(second.data!.user.emailVerified).toBe(true);
    expect(after.accounts).toHaveLength(1);
    expect(after.accounts[0].accountId).toBe("stable-subject");
    expect(after.accounts[0].userId).toBe(before.accounts[0].userId);
    expect(after.sessions).toHaveLength(2);
    await save(ctx, "changed-verified-email", { before, after, first, second });
    return { first: ctx.snapshot(first), second: ctx.snapshot(second), before, after };
  },
  ["POST /sign-in/social", "GET /callback/{}"],
);
compatScenario(
  "oauth account info guest cannot select a user through userId",
  async (ctx) => {
    const owner = ctx.actor("owner", "generic-token-none");
    const email = ctx.uniqueEmail("owner");
    expect(
      (await owner.client.signUp.email({ email, password: "Password123!", name: "Owner" })).error,
    ).toBeNull();
    const user = (await owner.client.getSession()).data!.user;
    const id = await ctx.seedOAuthAccount({
      email,
      providerId: "generic",
      accountId: "subject",
      accessToken: "private-access",
    });
    const before = await state(ctx);
    const guest = ctx.actor("guest", "generic-token-none");
    const response = await guest.fetch(
      ctx.baseURL +
        authProfilePath("generic-token-none") +
        `/account-info?accountId=${id}&userId=${user.id}`,
    );
    expect(response.status).toBe(401);
    expect(await state(ctx)).toEqual(before);
    return {
      status: response.status,
      body: await response.text(),
      before,
      after: await state(ctx),
    };
  },
  ["GET /account-info"],
);
for (const operation of ["get-access-token", "refresh-token", "account-info"]) {
  const name = `oauth trusted server ${operation} selects only explicitly authorized account owner`;
  compatScenario(
    name,
    async (ctx) => {
      const actor = ctx.actor("owner", "generic-token-none");
      const email = ctx.uniqueEmail("owner");
      expect(
        (await actor.client.signUp.email({ email, password: "Password123!", name: "Owner" })).error,
      ).toBeNull();
      const user = (await actor.client.getSession()).data!.user;
      const id = await ctx.seedOAuthAccount({
        email,
        providerId: "generic",
        accountId: "subject",
        accessToken: "old-access",
        refreshToken: "old-refresh",
        idToken: "old-id",
        scope: "original scope",
      });
      const before = await state(ctx);
      const call = (userId?: string) =>
        ctx.rawRequest({
          path: "/__test/generic-token/server-api",
          method: "POST",
          json: { operation, accountId: id, ...(userId ? { userId } : {}) },
        });
      const missing = await call();
      expect(missing.status).toBe(400);
      expect((missing.body as any).code).toBe("USER_ID_OR_SESSION_REQUIRED");
      const foreign = await call("foreign-owner");
      expect(foreign.status).toBe(400);
      expect((foreign.body as any).code).toBe("ACCOUNT_NOT_FOUND");
      expect(await state(ctx)).toEqual(before);
      const accepted = await call(user.id);
      expect(accepted.status).toBe(200);
      const after = await state(ctx);
      expect(after.users).toEqual(before.users);
      expect(after.sessions).toEqual(before.sessions);
      expect(after.accounts).toHaveLength(before.accounts.length);
      expect(after.accounts.find((a: any) => a.id === id).userId).toBe(user.id);
      await save(ctx, name, { before, missing, foreign, accepted, after });
      return { missing, foreign, accepted, before, after };
    },
    ["POST /get-access-token", "POST /refresh-token", "GET /account-info"],
  );
}
compatScenario(
  "oauth orphan binding rejects callback without adopting same-email user",
  async (ctx) => {
    const actor = ctx.actor("owner", "generic-token-none");
    const email = ctx.uniqueEmail("owner");
    expect(
      (await actor.client.signUp.email({ email, password: "Password123!", name: "Owner" })).error,
    ).toBeNull();
    const id = await ctx.seedOAuthAccount({
      email,
      providerId: "generic",
      accountId: "orphan-subject",
      accessToken: "old-access",
      refreshToken: "old-refresh",
    });
    expect(
      (
        await ctx.rawRequest({
          path: "/__test/generic-token/orphan",
          method: "POST",
          json: { accountId: id },
        })
      ).status,
    ).toBe(200);
    const before = await state(ctx);
    expect(before.accounts.find((a: any) => a.id === id).userId).toBe("missing-owner");
    await ctx.rawRequest({
      path: "/__test/generic-token/control",
      method: "POST",
      json: { profile: { id: "orphan-subject", email, name: "Owner", email_verified: true } },
    });
    const start = await actor.client.signIn.social({
      provider: "generic",
      callbackURL: "/dashboard",
    });
    expect(start.error).toBeNull();
    const u = new URL(start.data!.url!);
    const callback = await actor.fetch(
      ctx.baseURL +
        authProfilePath("generic-token-none") +
        `/callback/generic?code=code&state=${encodeURIComponent(u.searchParams.get("state")!)}`,
      { redirect: "manual" },
    );
    expect(callback.status).toBe(302);
    expect(new URL(callback.headers.get("location")!, ctx.baseURL).searchParams.get("error")).toBe(
      "unable_to_link_account",
    );
    expect(await state(ctx)).toEqual(before);
    await save(ctx, "orphan-binding", {
      before,
      after: await state(ctx),
      location: callback.headers.get("location"),
    });
    return {
      callback: { status: callback.status, location: callback.headers.get("location") },
      before,
      after: await state(ctx),
    };
  },
  ["GET /callback/{}"],
);
for (const expires of [undefined, "2099-01-01T00:00:00.000Z", "2020-01-01T00:00:00.000Z"]) {
  const name = `oauth expiry ${expires ?? "absent"} determines automatic refresh without treating refresh expiry as local veto`;
  compatScenario(
    name,
    async (ctx) => {
      const actor = ctx.actor("owner", "generic-token-none");
      const email = ctx.uniqueEmail("owner");
      expect(
        (await actor.client.signUp.email({ email, password: "Password123!", name: "Owner" })).error,
      ).toBeNull();
      const id = await ctx.seedOAuthAccount({
        email,
        providerId: "generic",
        accountId: "subject",
        accessToken: "old-access",
        refreshToken: "old-refresh",
        accessTokenExpiresAt: expires ?? null,
        refreshTokenExpiresAt: "2020-01-01T00:00:00.000Z",
      });
      const before = await state(ctx);
      const result = await actor.client.getAccessToken({ accountId: id });
      expect(result.error).toBeNull();
      expect(result.data!.accessToken).toBe(
        expires?.startsWith("2020") ? "generic-access" : "old-access",
      );
      const after = await state(ctx);
      expect(after.users).toEqual(before.users);
      expect(after.sessions).toEqual(before.sessions);
      if (!expires?.startsWith("2020")) expect(after).toEqual(before);
      await save(ctx, name, { before, result, after });
      return { result: ctx.snapshot(result), before, after };
    },
    ["POST /get-access-token"],
  );
}
compatScenario(
  "oauth concurrent refresh keeps persisted owner and scopes with both grants accepted",
  async (ctx) => {
    const actor = ctx.actor("owner", "generic-token-none");
    const email = ctx.uniqueEmail("owner");
    expect(
      (await actor.client.signUp.email({ email, password: "Password123!", name: "Owner" })).error,
    ).toBeNull();
    const id = await ctx.seedOAuthAccount({
      email,
      providerId: "generic",
      accountId: "subject",
      accessToken: "old-access",
      refreshToken: "old-refresh",
      scope: "original scope",
    });
    const before = await state(ctx);
    const results = await Promise.all([
      actor.client.refreshToken({ accountId: id }),
      actor.client.refreshToken({ accountId: id }),
    ]);
    for (const r of results) {
      expect(r.error).toBeNull();
      expect(r.data!.accessToken).toBe("generic-access");
    }
    const after = await state(ctx);
    expect(after.users).toEqual(before.users);
    expect(after.sessions).toEqual(before.sessions);
    expect(after.accounts).toHaveLength(before.accounts.length);
    expect(after.accounts.find((a: any) => a.id === id)).toMatchObject({
      userId: before.accounts.find((a: any) => a.id === id).userId,
      accountId: "subject",
      accessToken: "generic-access",
      refreshToken: "generic-refresh",
      scope: "original scope",
    });
    await save(ctx, "concurrent-refresh", { before, results, after });
    return { results: ctx.snapshot(results), before, after };
  },
  ["POST /refresh-token"],
);
for (const mode of [
  "expiry-positive",
  "expiry-zero",
  "expiry-negative",
  "custom-token",
  "custom-token-error",
] as const) {
  const name = `oauth generic ${mode} applies configured expiry only after real or custom grant`;
  compatScenario(
    name,
    async (ctx) => {
      const fixture = `generic-token-${mode}` as const;
      const actor = ctx.actor("owner", fixture);
      await ctx.rawRequest({
        path: "/__test/generic-token/control",
        method: "POST",
        json: {
          profile: {
            id: "stable-subject",
            email: ctx.uniqueEmail("owner"),
            name: "Owner",
            email_verified: true,
          },
          tokenResponse: { access_token: "access", refresh_token: "refresh", scope: "profile" },
        },
      });
      const before = await state(ctx);
      const start = await actor.client.signIn.social({
        provider: "generic",
        callbackURL: "/dashboard",
      });
      expect(start.error).toBeNull();
      const u = new URL(start.data!.url!);
      const began = Date.now();
      const r = await actor.fetch(
        ctx.baseURL +
          authProfilePath(fixture) +
          `/callback/generic?code=real-code&state=${encodeURIComponent(u.searchParams.get("state")!)}`,
        { redirect: "manual" },
      );
      const after = await state(ctx);
      const seen: any[] = await (
        await fetch(ctx.baseURL + "/__test/generic-token/receipts")
      ).json();
      if (mode === "custom-token-error") {
        expect(new URL(r.headers.get("location")!, ctx.baseURL).searchParams.get("error")).toBe(
          "invalid_code",
        );
        expect(after).toEqual(before);
        expect(seen).toHaveLength(1);
      } else {
        expect(r.headers.get("location")).toBe("/dashboard");
        const account = after.accounts.find((a: any) => a.providerId === "generic");
        expect(account.accessToken).toBe(mode === "custom-token" ? "custom-access" : "access");
        if (mode === "expiry-zero") expect(account.accessTokenExpiresAt).toBeNull();
        else
          expect(
            Math.abs(
              Date.parse(account.accessTokenExpiresAt) -
                began -
                (mode === "expiry-negative" ? -60000 : 17000),
            ),
          ).toBeLessThan(2000);
        if (mode === "custom-token") {
          expect(seen).toHaveLength(1);
          expect(seen[0]).toMatchObject({ kind: "custom-token", code: "real-code" });
          expect(seen[0].codeVerifier.length).toBeGreaterThan(40);
          expect(new URL(seen[0].redirectURI).pathname).toBe(
            authProfilePath(fixture) + "/callback/generic",
          );
        }
        // Refresh uses the same fallback; an actual expires_in takes precedence.
        await ctx.rawRequest({
          path: "/__test/generic-token/control",
          method: "POST",
          json: {
            tokenResponse: {
              access_token: "rotated",
              refresh_token: "rotated-refresh",
              expires_in: 3600,
            },
          },
        });
        const refresh = await actor.client.refreshToken({ accountId: account.id });
        expect(refresh.error).toBeNull();
        expect(
          Math.abs(new Date(refresh.data!.accessTokenExpiresAt!).getTime() - Date.now() - 3600000),
        ).toBeLessThan(2000);
      }
      await save(ctx, name, {
        before,
        after,
        receipts: seen,
        status: r.status,
        location: r.headers.get("location"),
      });
      return { before, after, callback: { status: r.status, location: r.headers.get("location") } };
    },
    ["POST /sign-in/social", "GET /callback/{}", "POST /refresh-token"],
  );
}
