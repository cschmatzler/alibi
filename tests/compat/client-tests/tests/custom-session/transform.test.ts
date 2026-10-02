import { expect } from "bun:test";

import { createAuthClient } from "better-auth/client";
import { customSessionClient, jwtClient, multiSessionClient } from "better-auth/client/plugins";
import { z } from "zod";

import { authProfilePath } from "../../support/profiles";
import { compatScenario } from "../../support/scenario";

type Context = Parameters<Parameters<typeof compatScenario>[1]>[0];

function client(
  ctx: Context,
  actor = "browser",
  mode?: string,
  profile: "custom-session" | "custom-session-jwt" | "custom-session-deferred" = "custom-session",
) {
  return createAuthClient({
    baseURL: `${ctx.baseURL}${authProfilePath(profile)}`,
    plugins: [customSessionClient(), multiSessionClient(), jwtClient()],
    fetchOptions: {
      customFetchImpl: ctx.actor(actor, profile).fetch,
      ...(mode ? { headers: { "x-custom-session": mode } } : {}),
    },
  });
}

const projected = z.object({
  user: z.object({ id: z.string(), name: z.string() }),
  session: z.object({ token: z.string(), userId: z.string(), label: z.string() }),
  application: z.object({ userId: z.string(), label: z.string(), path: z.string() }),
});

compatScenario(
  "custom session projects actual owners preserves device selection and rejects foreign cookies without mutating storage",
  async (ctx) => {
    const auth = client(ctx);
    const guest = await auth.getSession();
    expect(guest.data).toBeNull();
    expect(guest.error).toBeNull();

    const alice = await auth.signUp.email({
      email: ctx.uniqueEmail("custom-alice"),
      password: "password123",
      name: "Alice",
    });
    expect(alice.error).toBeNull();

    if (!alice.data?.token) {
      throw new Error("Alice session required");
    }

    const before = await ctx.readUserState({ userId: alice.data.user.id });
    const read = await auth.getSession();
    const result = projected.parse(read.data);
    expect(result.application).toEqual({
      userId: alice.data.user.id,
      label: "Alice",
      path: "/get-session",
    });
    expect(result.session.token).toBe(alice.data.token);
    expect(result.session.label).toBe("custom-public-label");
    expect(read.data?.session).not.toHaveProperty("hidden");

    const sibling = createAuthClient({
      baseURL: `${ctx.baseURL}${authProfilePath("custom-session-jwt")}`,
      plugins: [customSessionClient()],
      fetchOptions: { customFetchImpl: ctx.actor("browser", "custom-session").fetch },
    });
    const siblingRead = await sibling.getSession();
    expect(projected.parse(siblingRead.data).user.id).toBe(alice.data.user.id);

    const broken = createAuthClient({
      baseURL: `${ctx.baseURL}${authProfilePath("custom-session-core-error")}`,
      plugins: [customSessionClient()],
      fetchOptions: {
        customFetchImpl: ctx.actor("browser", "custom-session").fetch,
        headers: { "x-custom-session": "error" },
      },
    });
    const coreError = await broken.getSession();
    expect(coreError.data).toBeNull();
    expect(coreError.error).toBeNull();
    expect(await ctx.readUserState({ userId: alice.data.user.id })).toEqual(before);

    const filtered = await client(ctx, "browser", "filtered").getSession();
    expect(
      z.object({ userId: z.string(), label: z.string() }).strict().parse(filtered.data),
    ).toEqual({ userId: alice.data.user.id, label: "Alice" });

    const nullResult = await client(ctx, "browser", "null").getSession();
    expect(nullResult.data).toBeNull();
    expect(nullResult.error).toBeNull();

    const denied = await client(ctx, "browser", "error").getSession();
    expect(denied.error?.code).toBe("CUSTOM_SESSION_DENIED");
    expect(denied.error?.status).toBe(403);

    const ordinary = await ctx
      .actor("browser", "custom-session")
      .fetch(`${ctx.baseURL}${authProfilePath("custom-session")}/get-session`, {
        headers: { "x-custom-session": "ordinary" },
      });
    const ordinaryResult = { status: ordinary.status, body: await ordinary.text() };
    expect(ordinaryResult).toEqual({ status: 500, body: "" });
    expect(await ctx.readUserState({ userId: alice.data.user.id })).toEqual(before);

    const bob = await auth.signUp.email({
      email: ctx.uniqueEmail("custom-bob"),
      password: "password123",
      name: "Bob",
    });
    expect(bob.error).toBeNull();

    if (!bob.data?.token) {
      throw new Error("Bob session required");
    }

    const list = await auth.multiSession.listDeviceSessions();
    expect(list.error).toBeNull();
    expect(list.data).toHaveLength(2);

    const entries = z.array(projected).parse(list.data);
    expect(new Set(entries.map((row) => row.application.userId))).toEqual(
      new Set([alice.data.user.id, bob.data.user.id]),
    );

    for (const entry of entries) {
      expect(entry.application.userId).toBe(entry.user.id);
      expect(entry.session.userId).toBe(entry.user.id);
      expect(entry.application.path).toBe("/multi-session/list-device-sessions");
    }

    const outsider = await client(ctx, "outsider").multiSession.setActive({
      sessionToken: alice.data.token,
    });
    expect(outsider.error?.code).toBe("INVALID_SESSION_TOKEN");

    const select = await auth.multiSession.setActive({ sessionToken: alice.data.token });
    expect(select.error).toBeNull();

    const selected = await auth.getSession();
    expect(projected.parse(selected.data).application.userId).toBe(alice.data.user.id);

    const invalid = await ctx
      .actor("invalid", "custom-session")
      .fetch(`${ctx.baseURL}${authProfilePath("custom-session")}/get-session`, {
        credentials: "omit",
        headers: { cookie: `better-auth.session_token=${alice.data.token}.invalid` },
      });
    expect(await invalid.json()).toBeNull();
    expect(await ctx.readUserState({ userId: alice.data.user.id })).toEqual(before);

    const expire = await ctx.rawRequest({
      path: "/__test/expire-session",
      method: "POST",
      json: { token: alice.data.token, expiresAt: new Date(Date.now() - 60_000).toISOString() },
    });
    expect(expire.status).toBe(200);

    const expired = await auth.getSession();
    expect(expired.error).toBeNull();
    expect(expired.data).toBeNull();

    const logout = await auth.signOut();
    expect(logout.error).toBeNull();
    expect((await auth.getSession()).data).toBeNull();

    return {
      guest,
      alice,
      before,
      read,
      siblingRead,
      coreError,
      filtered,
      nullResult,
      denied,
      ordinaryResult,
      bob,
      list,
      outsider,
      select,
      selected,
      expire,
      expired,
      logout,
    };
  },
  ["GET /get-session", "GET /multi-session/list-device-sessions", "POST /multi-session/set-active"],
);

for (const profile of ["custom-session-jwt", "custom-session-deferred"] as const) {
  compatScenario(
    `custom session ${profile} retains refresh cookies and JWT authority when the application filters its response`,
    async (ctx) => {
      const auth = client(ctx, "browser", undefined, profile);
      const signup = await auth.signUp.email({
        email: ctx.uniqueEmail("custom-refresh"),
        password: "password123",
        name: "Refresh",
      });
      expect(signup.error).toBeNull();

      if (!signup.data?.token) {
        throw new Error("Session required");
      }

      const clock = await ctx.rawRequest({
        path: "/__test/expire-session",
        method: "POST",
        json: { token: signup.data.token, expiresAt: new Date(Date.now() + 60_000).toISOString() },
      });
      expect(clock.status).toBe(200);

      const headers: Array<Array<[string, string]>> = [];
      const read = await auth.getSession({
        fetchOptions: {
          onSuccess: (context) => {
            headers.push([...context.response.headers]);
          },
        },
      });
      const data = projected.extend({ needsRefresh: z.boolean().optional() }).parse(read.data);
      expect(data.needsRefresh).toBe(profile.endsWith("-deferred") ? true : undefined);

      const issuedCookies = headers.flat().filter(([name]) => name.toLowerCase() === "set-cookie");

      if (profile.endsWith("-deferred")) {
        expect(issuedCookies).toHaveLength(0);
      } else {
        expect(issuedCookies.length).toBeGreaterThan(0);
      }

      expect(data.application.userId).toBe(signup.data.user.id);

      const jwtHeader = headers.flat().find(([name]) => name.toLowerCase() === "set-auth-jwt")?.[1];
      expect(jwtHeader).toBeDefined();

      const token = await auth.token();
      expect(token.error).toBeNull();
      expect(token.data?.token).toBeDefined();

      const failures = [];

      for (const mode of ["error", "ordinary"]) {
        expect(
          (
            await ctx.rawRequest({
              path: "/__test/expire-session",
              method: "POST",
              json: {
                token: signup.data.token,
                expiresAt: new Date(Date.now() + 60_000).toISOString(),
              },
            })
          ).status,
        ).toBe(200);

        const failure = await ctx
          .actor("browser", profile)
          .fetch(`${ctx.baseURL}${authProfilePath(profile)}/get-session`, {
            headers: { "x-custom-session": mode },
          });
        expect(failure.status).toBe(mode === "error" ? 403 : 500);
        expect(failure.headers.getSetCookie()).toHaveLength(0);

        failures.push({
          status: failure.status,
          body: await failure.text(),
          cookies: failure.headers.getSetCookie(),
        });
      }

      const filtered = await client(ctx, "browser", "filtered", profile).getSession({
        fetchOptions: {
          onSuccess: ({ response }) => {
            const signed = response.headers.get("set-auth-jwt");
            expect(signed).toBeDefined();

            const payload = JSON.parse(Buffer.from(signed!.split(".")[1]!, "base64url").toString());
            expect(payload.sub).toBe(signup.data!.user.id);
            expect(payload.name).toBe("Refresh");
          },
        },
      });
      expect(
        z.object({ userId: z.string(), label: z.string() }).strict().parse(filtered.data).userId,
      ).toBe(signup.data.user.id);

      const post = await ctx
        .actor("browser", profile)
        .fetch(`${ctx.baseURL}${authProfilePath(profile)}/get-session`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: "{}",
        });
      const postBody = await post.text();
      expect(post.status).toBe(404);
      expect(postBody).toBe("");

      return {
        signup,
        clock,
        read,
        token,
        failures,
        filtered,
        post: { status: post.status, body: postBody },
        state: await ctx.readUserState({ userId: signup.data.user.id }),
      };
    },
    ["GET /get-session", "POST /get-session", "GET /token"],
  );
}
