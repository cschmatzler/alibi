import { expect } from "bun:test";

import { compatScenario } from "../../../support/scenario";

compatScenario(
  "list-sessions: real adapter enumeration failure preserves authority and bare upstream 500",
  async (ctx) => {
    async function control(mode?: string) {
      const response = await fetch(`${ctx.baseURL}/__test/session-adapter-failure`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(mode === undefined ? {} : { mode }),
      });
      expect(response.status).toBe(200);
      return response.json() as Promise<{ events: string[] }>;
    }
    await control("");
    const owner = ctx.actor("list-owner", "session-adapter-failure");
    const sibling = ctx.actor("list-sibling", "session-adapter-failure");
    const email = ctx.uniqueEmail("list-owner");
    const signup = await owner.client.signUp.email({
      email,
      password: "password123",
      name: "List Owner",
    });
    const login = await sibling.client.signIn.email({ email, password: "password123" });
    expect(signup.error).toBeNull();
    expect(login.error).toBeNull();
    const userId = signup.data!.user.id;
    const before = await ctx.readUserState({ userId });
    const current = await owner.client.getSession();
    await control("get_user_sessions");
    const failed = await owner.client.listSessions();
    const response = await owner.fetch(
      `${ctx.baseURL}/__test/profiles/session-adapter-failure/api/auth/list-sessions`,
    );
    const transport = {
      status: response.status,
      contentType: response.headers.get("content-type"),
      body: await response.text(),
      cookies: response.headers.getSetCookie(),
    };
    const receipts = await control();
    expect(receipts.events).toContain("get_session");
    expect(receipts.events).toContain("get_user_sessions");
    expect(failed.data).toBeNull();
    expect(failed.error?.status).toBe(500);
    expect(JSON.stringify(failed.error)).not.toContain("application-selected");
    expect(transport.body).not.toContain("application-selected");
    expect(await ctx.readUserState({ userId })).toEqual(before);
    expect((await owner.client.getSession()).data?.session.token).toBe(current.data!.session.token);
    expect((await sibling.client.getSession()).data?.user.id).toBe(userId);
    await control("");
    const retry = await owner.client.listSessions();
    expect(retry.error).toBeNull();
    expect(retry.data).toHaveLength(2);
    expect(retry.data?.map((s) => s.userId)).toEqual([userId, userId]);
    expect(await ctx.readUserState({ userId })).toEqual(before);
    expect(transport).toEqual({
      status: 500,
      contentType: "application/json",
      body: "",
      cookies: [],
    });
    expect(failed.error).toEqual({ status: 500, statusText: "Internal Server Error" });
    return {
      signup: ctx.snapshot(signup),
      login: ctx.snapshot(login),
      current: ctx.snapshot(current),
      failed: ctx.snapshot(failed),
      transport,
      retry: ctx.snapshot(retry),
      before,
    };
  },
  ["GET /list-sessions"],
);
