import { Cookie } from "tough-cookie";
import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "SSO deletion retires its actual linked accounts and preserves unrelated providers",
  async (ctx) => {
    const actor = ctx.actor();
    const control = (input: Record<string, unknown>) =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/sso`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(input),
      });
    const signup = async (name: string) => {
      const response = await control({
        action: "signup",
        body: { email: ctx.uniqueEmail(name), name: "Native owner", password: "password123" },
      });
      expect(response.status).toBe(200);
      return {
        user: ((await response.json()) as any).user,
        cookie: response.headers
          .getSetCookie()
          .filter((raw) => Boolean(Cookie.parse(raw)?.value))
          .map((raw) => raw.split(";")[0])
          .join("; "),
      };
    };
    const owner = await signup("sso-delete-owner");
    const foreign = await signup("sso-delete-foreign");
    for (const [providerId, cookie] of [
      ["delete-provider", owner.cookie],
      ["keep-provider", foreign.cookie],
    ]) {
      const response = await control({
        headers: { cookie },
        body: {
          providerId,
          issuer: "https://idp.example.com",
          domain: "company.com",
          oidcConfig: {
            clientId: "enterprise-client",
            clientSecret: "stored-secret",
            skipDiscovery: true,
            pkce: true,
          },
        },
      });
      expect(response.status).toBe(200);
    }
    const links = [
      [owner.user.id, "delete-provider", "owner-subject"],
      [foreign.user.id, "delete-provider", "foreign-subject"],
      [foreign.user.id, "keep-provider", "kept-subject"],
    ];
    for (const [userId, providerId, accountId] of links) {
      const response = await control({
        action: "create-account",
        body: { userId, providerId, accountId },
      });
      expect(response.status).toBe(200);
      const account = (await response.json()) as any;
      expect(account.userId).toBe(userId);
      expect(account.providerId).toBe(providerId);
      expect(account.accountId).toBe(accountId);
      expect(typeof account.id).toBe("string");
    }
    const denied = await control({
      action: "delete",
      body: { providerId: "delete-provider" },
      headers: { cookie: foreign.cookie },
    });
    expect(denied.status).toBe(403);
    for (const [, providerId, accountId] of links) {
      expect(
        await (await control({ action: "account-row", providerId, accountId })).json(),
      ).not.toBe(null);
    }
    const anonymous = await control({
      action: "delete",
      body: { providerId: "delete-provider" },
      headers: {},
    });
    expect(anonymous.status).toBe(401);
    expect((await control({ action: "delete-fault", enabled: true })).status).toBe(200);
    const failed = await control({
      action: "delete",
      body: { providerId: "delete-provider" },
      headers: { cookie: owner.cookie },
    });
    expect(failed.status).toBe(500);
    expect(await failed.text()).toBe("");
    expect(await (await control({ action: "row", providerId: "delete-provider" })).json()).not.toBe(
      null,
    );
    for (const [, providerId, accountId] of links) {
      expect(
        await (await control({ action: "account-row", providerId, accountId })).json(),
      ).not.toBe(null);
    }
    expect((await control({ action: "delete-fault", enabled: false })).status).toBe(200);
    const deleted = await control({
      action: "delete",
      body: { providerId: "delete-provider" },
      headers: { cookie: owner.cookie },
    });
    expect(deleted.status).toBe(200);
    expect(await deleted.json()).toEqual({ success: true });
    const rows = [];
    for (const [, providerId, accountId] of links) {
      rows.push(await (await control({ action: "account-row", providerId, accountId })).json());
    }
    expect(rows[0]).toBe(null);
    expect(rows[1]).toBe(null);
    expect(rows[2]).not.toBe(null);
    expect(await (await control({ action: "row", providerId: "delete-provider" })).json()).toBe(
      null,
    );
    expect(await (await control({ action: "row", providerId: "keep-provider" })).json()).not.toBe(
      null,
    );
    const replay = await control({
      action: "delete",
      body: { providerId: "delete-provider" },
      headers: { cookie: owner.cookie },
    });
    expect(replay.status).toBe(404);
    expect(await replay.json()).toEqual({ message: "Provider not found" });
    return {
      denied: denied.status,
      anonymous: anonymous.status,
      failed: failed.status,
      deleted: deleted.status,
      rows,
      replay: replay.status,
    };
  },
);
