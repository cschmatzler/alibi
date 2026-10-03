import { expect } from "bun:test";

import { authProfilePath } from "../../../support/profiles";
import { compatScenario, type ScenarioContext } from "../../../support/scenario";

type Rows = {
  users: Record<string, any>[];
  accounts: Record<string, any>[];
  sessions: Record<string, any>[];
};
async function rows(ctx: ScenarioContext): Promise<Rows> {
  return (await ctx.rawRequest({ path: "/__test/social-provider/state" })).body as Rows;
}
async function save(ctx: ScenarioContext, name: string, value: unknown) {
  if (process.env.LOGOUT_EVIDENCE_DIR) {
    await Bun.write(
      `${process.env.LOGOUT_EVIDENCE_DIR}/${Bun.hash(ctx.baseURL + name)}.json`,
      JSON.stringify({ name, baseURL: ctx.baseURL, value }, null, 2),
    );
  }
}
const cases = [
  {
    mode: "logout",
    token: "owner-token",
    body: {},
    endpoint: "discovered",
    redirect: true,
    callback: "/signed-out",
    state: null,
  },
  {
    mode: "logout-configured",
    token: "owner-token",
    body: { callbackURL: "/return?done=1", state: "logout state&value", disableRedirect: true },
    endpoint: "configured",
    redirect: false,
    callback: "/return?done=1",
    state: "logout state&value",
  },
  {
    mode: "logout-no-return",
    token: "owner-token",
    body: { state: "ignored-without-return" },
    endpoint: "discovered",
    redirect: true,
    callback: null,
    state: null,
  },
  {
    mode: "logout-no-return",
    token: null,
    body: {},
    endpoint: "discovered",
    redirect: true,
    callback: null,
    state: null,
  },
  {
    mode: "logout",
    token: null,
    body: { state: "without-token" },
    endpoint: "discovered",
    redirect: true,
    callback: "/signed-out",
    state: "without-token",
  },
  { mode: "logout-disabled", token: "owner-token", body: {}, endpoint: null },
  { mode: "logout-invalid", token: "owner-token", body: {}, endpoint: null },
] as const;
for (const [index, item] of cases.entries()) {
  const name = `generic provider logout ${index} ${item.mode} preserves ownership and local revocation`;
  compatScenario(
    name,
    async (ctx) => {
      const fixture = `generic-discovery-${item.mode}` as const;
      const owner = ctx.actor("owner", fixture);
      const foreign = ctx.actor("foreign", fixture);
      const email = ctx.uniqueEmail("owner");
      const foreignEmail = ctx.uniqueEmail("foreign");
      for (const [actor, actorEmail] of [
        [owner, email],
        [foreign, foreignEmail],
      ] as const) {
        expect(
          (
            await actor.client.signUp.email({
              email: actorEmail,
              password: "Password123!",
              name: "Actor",
            })
          ).error,
        ).toBeNull();
      }
      await ctx.seedOAuthAccount({
        email,
        providerId: "discovery",
        accountId: "owner-account",
        idToken: item.token,
      });
      await ctx.seedOAuthAccount({
        email: foreignEmail,
        providerId: "discovery",
        accountId: "foreign-account",
        idToken: "foreign-secret",
      });
      const before = await rows(ctx);
      const response = await owner.fetch(ctx.baseURL + authProfilePath(fixture) + "/sign-out", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          ...item.body,
          accountId: "foreign-account",
          userId: before.users.find((u) => u.email === foreignEmail)!.id,
        }),
        redirect: "manual",
      });
      const body = await response.json();
      const after = await rows(ctx);
      const result = {
        status: response.status,
        location: response.headers.get("location"),
        cookies: response.headers.getSetCookie(),
        body,
        before,
        after,
      };
      await save(ctx, name, result);
      expect(response.status).toBe(200);
      expect(after.users).toEqual(before.users);
      expect(after.accounts).toEqual(before.accounts);
      const foreignUser = before.users.find((u) => u.email === foreignEmail)!;
      expect(after.sessions).toEqual(before.sessions.filter((s) => s.userId === foreignUser.id));
      expect(
        response.headers
          .getSetCookie()
          .some((cookie) => cookie.includes("session_token=") && cookie.includes("Max-Age=0")),
      ).toBe(true);
      if (item.endpoint) {
        expect(body.url).toBeString();
        expect(body.url).toBeString();
        const url = new URL(body.url);
        expect(url.origin).toBe(`https://${item.endpoint}.example.invalid`);
        expect(url.pathname).toBe("/logout");
        expect(url.searchParams.get("id_token_hint")).toBe(item.token);
        expect(url.searchParams.getAll("id_token_hint")).toHaveLength(item.token ? 1 : 0);
        expect(url.searchParams.get("post_logout_redirect_uri")).toBe(
          item.callback ? ctx.baseURL + item.callback : null,
        );
        expect(url.searchParams.get("state")).toBe(item.state);
        expect(url.searchParams.get("client_id")).toBe(
          item.callback || !item.token ? "discovery-client" : null,
        );
        if (item.endpoint === "configured") expect(url.searchParams.get("keep")).toBe("1");
        expect(body.redirect).toBe(item.redirect);
        expect(response.headers.get("location")).toBe(item.redirect ? body.url : null);
      } else {
        expect(body).toEqual({ success: true });
        expect(response.headers.get("location")).toBeNull();
      }
      const replay = await owner.fetch(ctx.baseURL + authProfilePath(fixture) + "/sign-out", {
        method: "POST",
        redirect: "manual",
      });
      expect(await replay.json()).toEqual({ success: true });
      expect(replay.headers.get("location")).toBeNull();
      expect(await rows(ctx)).toEqual(after);
      return result;
    },
    ["POST /sign-out"],
  );
}
compatScenario(
  "generic provider logout selects newest eligible owned account and skips invalid provider",
  async (ctx) => {
    const fixture = "generic-discovery-logout";
    const owner = ctx.actor("owner", fixture);
    const email = ctx.uniqueEmail("ordered");
    expect(
      (await owner.client.signUp.email({ email, password: "Password123!", name: "Owner" })).error,
    ).toBeNull();
    for (const [providerId, accountId, idToken, updatedAt] of [
      ["backup", "backup-account", "backup-token", "2020-01-01T00:00:00Z"],
      ["discovery", "older-account", "older-token", "2021-01-01T00:00:00Z"],
      ["discovery", "newer-account", "newer-token", "2022-01-01T00:00:00Z"],
      ["invalid", "invalid-account", "invalid-token", "2023-01-01T00:00:00Z"],
      ["unregistered", "unknown-account", "unknown-token", "2024-01-01T00:00:00Z"],
    ]) {
      expect(
        (
          await ctx.rawRequest({
            path: "/__test/seed-oauth-account",
            method: "POST",
            json: {
              email,
              providerId,
              accountId,
              idToken,
              accessToken: "access",
              refreshToken: "refresh",
              scope: "openid",
              accessTokenExpiresAt: null,
              refreshTokenExpiresAt: null,
              createdAt: updatedAt,
              updatedAt,
            },
          })
        ).status,
      ).toBe(200);
    }
    const before = await rows(ctx);
    const response = await owner.fetch(ctx.baseURL + authProfilePath(fixture) + "/sign-out", {
      method: "POST",
      redirect: "manual",
    });
    const body = await response.json();
    const after = await rows(ctx);
    const result = {
      before,
      after,
      body,
      status: response.status,
      location: response.headers.get("location"),
    };
    await save(ctx, "ordered", result);
    expect(response.status).toBe(200);
    expect(body.url).toBeString();
    const url = new URL(body.url);
    expect(url.origin).toBe("https://discovered.example.invalid");
    expect(url.searchParams.get("id_token_hint")).toBe("newer-token");
    expect(after.accounts).toEqual(before.accounts);
    expect(after.users).toEqual(before.users);
    expect(after.sessions).toHaveLength(0);
    return result;
  },
  ["POST /sign-out"],
);
