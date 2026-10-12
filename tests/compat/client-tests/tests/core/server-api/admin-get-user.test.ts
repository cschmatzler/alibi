import { expect } from "bun:test";

import { cacheReceipt } from "../../../support/compact-cache-receipt";
import { authProfilePath } from "../../../support/profiles";
import { compatScenario } from "../../../support/scenario";
import { readUserState } from "../../../support/verification";

compatScenario(
  "server admin getUser uses authoritative query and permission without exposing credentials",
  async (ctx) => {
    async function signup(
      name: string,
      profile: "admin-standard" | "admin-server-cache" | undefined,
    ) {
      const actor = ctx.actor(name, profile);
      let headers = new Headers();
      const result = await actor.client.signUp.email({
        email: ctx.uniqueEmail(name),
        password: "Password123!",
        name,
        fetchOptions: {
          onSuccess({ response }) {
            headers = new Headers(response.headers);
          },
        },
      });
      expect(result.error).toBeNull();
      return {
        actor,
        result,
        headers: {
          cookie: headers
            .getSetCookie()
            .map((c) => c.split(";")[0])
            .join("; "),
        },
      };
    }
    const administrator = await signup("logical-admin", "admin-standard");
    const member = await signup("logical-member", undefined);
    const cached = await signup("logical-cached-admin", "admin-server-cache");
    const target = member.result.data!.user.id;
    const before = {
      admin: await readUserState(ctx, administrator.result.data!.user.id),
      member: await readUserState(ctx, target),
      cached: await readUserState(ctx, cached.result.data!.user.id),
    };
    async function invoke(input: Record<string, unknown>) {
      const response = await ctx
        .actor("admin-control")
        .fetch(ctx.baseURL + "/__test/admin/server-api", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(input),
        });
      const text = await response.text();
      const publication = response.headers
        .getSetCookie()
        .some(
          (cookie) =>
            cookie.startsWith("better-auth.session_data=") && !cookie.includes("Max-Age=0"),
        )
        ? await cacheReceipt(response.headers)
        : undefined;
      return {
        status: response.status,
        body: text ? (JSON.parse(text) as Record<string, unknown>) : null,
        principal: response.headers.get("x-admin-principal"),
        cookies: response.headers
          .getSetCookie()
          .map((cookie) =>
            publication &&
            cookie.startsWith("better-auth.session_data=") &&
            !cookie.includes("Max-Age=0")
              ? publication
              : cookie,
          ),
      };
    }
    const denials = [];
    for (const [input, status] of [
      [{}, 400],
      [{ query: null }, 400],
      [{ query: 7 }, 400],
      [{ query: {} }, 400],
      [{ query: { id: 7 }, headers: administrator.headers }, 400],
      [{ query: { id: target } }, 401],
      [{ query: { id: target }, headers: {} }, 401],
      [
        {
          query: { id: target },
          headers: { ...member.headers, "x-user-role": "admin" },
          body: { role: "admin", userId: administrator.result.data!.user.id },
        },
        403,
      ],
      [{ query: { id: target }, profile: "admin-deny-all", headers: administrator.headers }, 403],
      [{ query: { id: "" }, headers: administrator.headers }, 404],
      [{ query: { id: "missing-user" }, headers: administrator.headers }, 404],
    ] as const) {
      const response = await invoke(input);
      expect(response.status).toBe(status);
      if (status === 401) {
        expect(response.body).toBeNull();
      }
      if (status === 403) {
        expect(response.body).toEqual({
          code: "YOU_ARE_NOT_ALLOWED_TO_GET_USER",
          message: "You are not allowed to get user",
        });
      }
      denials.push(response);
    }
    const successes = [];
    for (const input of [
      { query: { id: target }, headers: administrator.headers },
      {
        query: { id: target, userId: administrator.result.data!.user.id, role: "admin" },
        body: { id: administrator.result.data!.user.id },
        headers: administrator.headers,
      },
      { query: { id: target }, body: 7, profile: "admin-server-cache", headers: cached.headers },
    ]) {
      const response = await invoke(input);
      expect(response.status).toBe(200);
      expect(response.body).toMatchObject({
        id: target,
        email: member.result.data!.user.email,
        name: "logical-member",
        role: "user",
        banned: false,
      });
      expect(response.body).not.toHaveProperty("password");
      expect(response.body).not.toHaveProperty("token");
      expect(response.body).not.toHaveProperty("user");
      expect(response.principal).toBe(
        input.profile ? cached.result.data!.user.email : administrator.result.data!.user.email,
      );
      expect(response.cookies.slice(-2)).toEqual([
        "application_a=first; Path=/; HttpOnly",
        "application_b=second; Path=/; HttpOnly",
      ]);
      successes.push(response);
    }
    expect(await readUserState(ctx, target)).toEqual(before.member);
    expect(await readUserState(ctx, administrator.result.data!.user.id)).toEqual(before.admin);
    expect(await readUserState(ctx, cached.result.data!.user.id)).toEqual(before.cached);
    const demoted = await cached.actor.fetch(
      ctx.baseURL + authProfilePath("admin-server-cache") + "/admin/set-role",
      {
        method: "POST",
        headers: { "content-type": "application/json", cookie: cached.headers.cookie },
        body: JSON.stringify({ userId: cached.result.data!.user.id, role: "user" }),
      },
    );
    expect(demoted.status).toBe(200);
    const stale = await invoke({
      profile: "admin-server-cache",
      query: { id: target },
      headers: cached.headers,
    });
    expect(stale.status).toBe(403);
    expect(stale.principal).toBe(cached.result.data!.user.email);
    const refreshed = stale.cookies.find((cookie) => typeof cookie !== "string");
    expect(refreshed?.compactSessionCache.decoded?.user).toMatchObject({
      id: cached.result.data!.user.id,
      role: "user",
    });
    const afterDemotion = await readUserState(ctx, cached.result.data!.user.id);
    const roleState = await ctx.rawRequest({
      path: "/__test/admin-role-state?email=" + encodeURIComponent(cached.result.data!.user.email),
    });
    expect(roleState.body).toMatchObject({ user: { role: "user" } });
    const logout = await cached.actor.fetch(
      ctx.baseURL + authProfilePath("admin-server-cache") + "/sign-out",
      { method: "POST", headers: { cookie: cached.headers.cookie } },
    );
    expect(logout.status).toBe(200);
    const revoked = await invoke({
      profile: "admin-server-cache",
      query: { id: target },
      headers: cached.headers,
    });
    expect(revoked.status).toBe(401);
    expect(revoked.body).toBeNull();
    expect(await readUserState(ctx, target)).toEqual(before.member);
    return ctx.snapshot({
      administrator: administrator.result,
      member: member.result,
      cached: cached.result,
      before,
      denials,
      successes,
      stale,
      afterDemotion,
      revoked,
      after: await readUserState(ctx, cached.result.data!.user.id),
    });
  },
  [],
  30_000,
);
