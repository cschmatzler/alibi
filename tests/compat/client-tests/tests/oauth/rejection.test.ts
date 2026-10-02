import { expect } from "bun:test";
import { createAuthClient } from "better-auth/client";
import { Cookie } from "tough-cookie";
import { compatScenario } from "../../support/scenario";

compatScenario(
  "social linking rejects missing tampered and revoked sessions without changing owners",
  async (ctx) => {
    const cookies = new Map<string, string>();
    const wires: { status: number; body: unknown; contentType: string | null }[] = [];
    const actor = (name: string) => {
      const transport = ctx.actor(name);
      const client = createAuthClient({
        baseURL: ctx.baseURL,
        fetchOptions: {
          customFetchImpl: async (input, init) => {
            const response = await transport.fetch(input, init);
            const path = new URL(input instanceof Request ? input.url : input, ctx.baseURL)
              .pathname;
            if (path === "/api/auth/link-social")
              wires.push({
                status: response.status,
                body: await response.clone().json(),
                contentType: response.headers.get("content-type")?.split(";")[0] ?? null,
              });
            for (const header of response.headers.getSetCookie()) {
              const cookie = Cookie.parse(header);
              if (cookie?.key.endsWith(".session_token") && cookie.value && cookie.maxAge !== 0)
                cookies.set(name, cookie.cookieString());
            }
            return response;
          },
        },
      });
      return { client, fetch: transport.fetch };
    };
    const owner = actor("owner"),
      foreign = actor("foreign"),
      retired = actor("retired"),
      guest = actor("guest");
    const signup = async (client: typeof owner.client, name: string) => {
      const result = await client.signUp.email({
        email: ctx.uniqueEmail(name),
        password: "password123",
        name,
      });
      expect(result.error).toBeNull();
      if (!result.data) throw new Error("actual signup owner required");
      return result;
    };
    const ownerSignup = await signup(owner.client, "oauth-rejection-owner"),
      foreignSignup = await signup(foreign.client, "oauth-rejection-foreign"),
      retiredSignup = await signup(retired.client, "oauth-rejection-retired");
    const retiredCookie = cookies.get("retired"),
      ownerCookie = cookies.get("owner");
    if (!retiredCookie || !ownerCookie) throw new Error("actual signed session cookies required");
    const signout = await retired.client.signOut();
    expect(signout.error).toBeNull();
    const parsed = Cookie.parse(ownerCookie);
    if (!parsed) throw new Error("actual cookie must parse");
    const value = decodeURIComponent(parsed.value),
      separator = value.lastIndexOf(".");
    if (separator < 0) throw new Error("issued signature required");
    expect(value.slice(0, separator)).toBe(ownerSignup.data!.token!);
    const signature = value.slice(separator + 1);
    const altered = `${parsed.key}=${encodeURIComponent(value.slice(0, separator + 1) + (signature.startsWith("A") ? "B" : "A") + signature.slice(1))}`;
    const ids = [ownerSignup, foreignSignup, retiredSignup].map((result) => result.data!.user.id);
    const readAll = async () => {
      const result = [];
      for (const userId of ids) result.push(await ctx.readUserState({ userId }));
      return result;
    };
    const before = await readAll();
    expect(before[2]).toMatchObject({ user: { id: ids[2] }, sessions: [] });
    const denied = [];
    for (const mode of ["missing", "tampered", "revoked"] as const) {
      const count = wires.length;
      const result = await guest.client.linkSocial(
        { provider: "google", callbackURL: "/settings" },
        {
          headers:
            mode === "missing"
              ? undefined
              : { cookie: mode === "tampered" ? altered : retiredCookie },
        },
      );
      expect(result).toEqual({
        data: null,
        error: {
          status: 401,
          statusText: "Unauthorized",
          code: "UNAUTHORIZED",
          message: "Unauthorized",
        },
      });
      expect(wires).toHaveLength(count + 1);
      expect(wires.at(-1)).toEqual({
        status: 401,
        body: { code: "UNAUTHORIZED", message: "Unauthorized" },
        contentType: "application/json",
      });
      const state = await readAll();
      expect(state).toEqual(before);
      denied.push({ mode, result: ctx.snapshot(result), wire: wires.at(-1), state });
    }
    const providerAccountId = ctx.uniqueToken("oauth-rejection-google");
    await ctx.setSocialProfile({
      sub: providerAccountId,
      email: ownerSignup.data!.user.email,
      name: "Actual Linked Owner",
      emailVerified: true,
      idTokenValid: true,
    });
    const link = await owner.client.linkSocial({ provider: "google", callbackURL: "/settings" });
    expect(link.error).toBeNull();
    expect(wires.at(-1)?.status).toBe(200);
    const state = link.data?.url && new URL(link.data.url).searchParams.get("state");
    if (!state) throw new Error("server-issued OAuth state required");
    expect(await readAll()).toEqual(before);
    const callbackPath = `/api/auth/callback/google?code=compat-code&state=${encodeURIComponent(state)}`;
    const callback = await ctx.rawRequest({
      actor: "owner",
      path: callbackPath,
      redirect: "manual",
    });
    expect(callback).toMatchObject({ status: 302, location: "/settings" });
    const after = await readAll();
    expect(after[0]).toMatchObject({ user: { id: ids[0] } });
    const accounts = (
      after[0] as { accounts: { providerId: string; accountId: string; userId: string }[] }
    ).accounts;
    expect(accounts).toHaveLength((before[0] as { accounts: unknown[] }).accounts.length + 1);
    expect(accounts.find((row) => row.providerId === "google")).toMatchObject({
      accountId: providerAccountId,
      userId: ids[0],
    });
    expect((after[0] as { sessions: unknown }).sessions).toEqual(
      (before[0] as { sessions: unknown }).sessions,
    );
    expect(after[1]).toEqual(before[1]);
    expect(after[2]).toEqual(before[2]);
    const current = await owner.client.getSession(),
      foreignCurrent = await foreign.client.getSession();
    expect(current.data?.user.id).toBe(ids[0]);
    expect(current.data?.session.token).toBe(ownerSignup.data!.token!);
    expect(foreignCurrent.data?.session.token).toBe(foreignSignup.data!.token!);
    const foreignLink = await foreign.client.linkSocial({
      provider: "google",
      callbackURL: "/settings",
    });
    expect(foreignLink.error).toBeNull();
    const foreignState = new URL(foreignLink.data!.url!).searchParams.get("state");
    if (!foreignState) throw new Error("actual foreign linking state required");
    const foreignCallback = await ctx.rawRequest({
      actor: "foreign",
      path: `/api/auth/callback/google?${new URLSearchParams({ code: "compat-code", state: foreignState })}`,
      redirect: "manual",
    });
    expect(foreignCallback.status).toBe(302);
    expect(new URL(foreignCallback.location!, ctx.baseURL).searchParams.get("error")).toBe(
      "email_does_not_match",
    );
    const afterForeign = await readAll();
    expect(afterForeign).toEqual(after);
    const ownerAfterForeign = await owner.client.getSession(),
      foreignAfterCurrent = await foreign.client.getSession();
    expect(ownerAfterForeign).toEqual(current);
    expect(foreignAfterCurrent).toEqual(foreignCurrent);
    return {
      ownerSignup: ctx.snapshot(ownerSignup),
      foreignSignup: ctx.snapshot(foreignSignup),
      retiredSignup: ctx.snapshot(retiredSignup),
      signout: ctx.snapshot(signout),
      before,
      denied,
      link: ctx.snapshot(link),
      callback,
      after,
      current: ctx.snapshot(current),
      foreignCurrent: ctx.snapshot(foreignCurrent),
      foreignLink: ctx.snapshot(foreignLink),
      foreignCallback,
      afterForeign,
      ownerAfterForeign: ctx.snapshot(ownerAfterForeign),
      foreignAfterCurrent: ctx.snapshot(foreignAfterCurrent),
    };
  },
  ["POST /link-social", "GET /callback/{}"],
);

compatScenario(
  "social callback rejects consumed database state while retaining the issued session and foreign state",
  async (ctx) => {
    const owner = ctx.actor("owner"),
      foreign = ctx.actor("foreign");
    const foreignSignup = await foreign.client.signUp.email({
      email: ctx.uniqueEmail("oauth-replay-foreign"),
      password: "password123",
      name: "Foreign Owner",
    });
    expect(foreignSignup.error).toBeNull();
    const foreignId = foreignSignup.data!.user.id;
    const foreignBefore = await ctx.readUserState({ userId: foreignId });
    const providerAccountId = ctx.uniqueToken("oauth-replay-google"),
      email = ctx.uniqueEmail("oauth-replay-owner");
    await ctx.setSocialProfile({
      sub: providerAccountId,
      email,
      name: "OAuth Replay Owner",
      emailVerified: true,
      idTokenValid: true,
    });
    const signin = await owner.client.signIn.social({
      provider: "google",
      callbackURL: "/dashboard",
      disableRedirect: true,
    });
    expect(signin.error).toBeNull();
    const state = signin.data?.url && new URL(signin.data.url).searchParams.get("state");
    if (!state) throw new Error("server-issued OAuth state required");
    const path = `/api/auth/callback/google?code=compat-code&state=${encodeURIComponent(state)}`;
    const callback = await ctx.rawRequest({ actor: "owner", path, redirect: "manual" });
    expect(callback).toMatchObject({ status: 302, location: "/dashboard" });
    const current = await owner.client.getSession();
    expect(current.error).toBeNull();
    if (!current.data) throw new Error("real OAuth session required");
    expect(current.data.user.email).toBe(email);
    expect(current.data.user.id).not.toBe(foreignId);
    const beforeReplay = await ctx.readUserState({ userId: current.data.user.id });
    expect(beforeReplay).toMatchObject({
      user: { id: current.data.user.id },
      accounts: [
        { accountId: providerAccountId, providerId: "google", userId: current.data.user.id },
      ],
      sessions: [{ token: current.data.session.token, userId: current.data.user.id }],
    });
    const replay = await ctx.rawRequest({ actor: "owner", path, redirect: "manual" });
    expect(replay.status).toBe(302);
    expect(new URL(replay.location!, ctx.baseURL).searchParams.get("error")).toBe("state_mismatch");
    const afterReplay = await ctx.readUserState({ userId: current.data.user.id }),
      foreignAfter = await ctx.readUserState({ userId: foreignId });
    expect(afterReplay).toEqual(beforeReplay);
    expect(foreignAfter).toEqual(foreignBefore);
    const replayCurrent = await owner.client.getSession(),
      foreignCurrent = await foreign.client.getSession();
    expect(replayCurrent).toEqual(current);
    expect(foreignCurrent.data?.session.token).toBe(foreignSignup.data!.token!);
    return {
      foreignSignup: ctx.snapshot(foreignSignup),
      foreignBefore,
      signin: ctx.snapshot(signin),
      callback,
      current: ctx.snapshot(current),
      beforeReplay,
      replay,
      afterReplay,
      foreignAfter,
      replayCurrent: ctx.snapshot(replayCurrent),
      foreignCurrent: ctx.snapshot(foreignCurrent),
    };
  },
  ["GET /callback/{}"],
);

// A grant captures the authenticated owner before that credential session retires.
// This complements the live-session guard owner above with rotation and replay.
compatScenario(
  "social linking rejects missing tampered and revoked sessions without changing any principal",
  async (ctx) => {
    const transport = ctx.actor("rotated-owner"),
      foreign = ctx.actor("foreign"),
      guest = ctx.actor("guest");
    let signedCookie: string | undefined;
    const owner = createAuthClient({
      baseURL: ctx.baseURL,
      fetchOptions: {
        customFetchImpl: async (input, init) => {
          const response = await transport.fetch(input, init);
          for (const header of response.headers.getSetCookie()) {
            const cookie = Cookie.parse(header);
            if (cookie?.key.endsWith(".session_token") && cookie.value && cookie.maxAge !== 0)
              signedCookie = cookie.cookieString();
          }
          return response;
        },
      },
    });
    const email = ctx.uniqueEmail("oauth-retired-grant-owner"),
      password = "password123";
    const signup = await owner.signUp.email({ email, password, name: "Grant Owner" });
    const foreignSignup = await foreign.client.signUp.email({
      email: ctx.uniqueEmail("oauth-retired-grant-foreign"),
      password,
      name: "Foreign Owner",
    });
    expect(signup.error).toBeNull();
    expect(foreignSignup.error).toBeNull();
    if (!signup.data || !foreignSignup.data || !signedCookie)
      throw new Error("actual credential owners and signed cookie required");
    const retiredCookie = signedCookie,
      ownerId = signup.data.user.id,
      foreignId = foreignSignup.data.user.id;
    const foreignBefore = await ctx.readUserState({ userId: foreignId });
    const providerId = ctx.uniqueToken("oauth-retired-grant-provider");
    await ctx.setSocialProfile({
      sub: providerId,
      email,
      name: "Provider Grant Owner",
      emailVerified: true,
      idTokenValid: true,
    });
    const granted = await owner.linkSocial({
      provider: "google",
      callbackURL: "/retired-grant-complete",
    });
    expect(granted.error).toBeNull();
    const issued = granted.data?.url && new URL(granted.data.url).searchParams.get("state");
    if (!issued) throw new Error("actual owned linking grant required");
    const retired = await owner.signOut();
    expect(retired.error).toBeNull();
    const reauthenticated = await owner.signIn.email({ email, password });
    expect(reauthenticated.error).toBeNull();
    expect(reauthenticated.data!.user.id).toBe(ownerId);
    expect(reauthenticated.data!.token).not.toBe(signup.data.token);
    const before = await ctx.readUserState({ userId: ownerId });
    expect(before).toMatchObject({
      user: { id: ownerId },
      sessions: [{ userId: ownerId, token: reauthenticated.data!.token }],
    });
    if (!signedCookie) throw new Error("actual rotated signed cookie required");
    const cookie = Cookie.parse(signedCookie)!;
    const decoded = decodeURIComponent(cookie.value),
      split = decoded.lastIndexOf(".");
    expect(decoded.slice(0, split)).toBe(reauthenticated.data!.token!);
    const signature = decoded.slice(split + 1);
    const tamperedCookie = `${cookie.key}=${encodeURIComponent(decoded.slice(0, split + 1) + (signature.startsWith("A") ? "B" : "A") + signature.slice(1))}`;
    const denied = [];
    for (const mode of ["missing", "tampered", "revoked"] as const) {
      const denial = await guest.client.linkSocial(
        { provider: "google", callbackURL: "/retired-grant-complete" },
        {
          headers:
            mode === "missing"
              ? undefined
              : { cookie: mode === "tampered" ? tamperedCookie : retiredCookie },
        },
      );
      expect(denial).toEqual({
        data: null,
        error: {
          status: 401,
          statusText: "Unauthorized",
          code: "UNAUTHORIZED",
          message: "Unauthorized",
        },
      });
      const owned = await ctx.readUserState({ userId: ownerId }),
        foreignState = await ctx.readUserState({ userId: foreignId });
      expect(owned).toEqual(before);
      expect(foreignState).toEqual(foreignBefore);
      denied.push({ mode, denial: ctx.snapshot(denial), owned, foreignState });
    }
    const path = `/api/auth/callback/google?${new URLSearchParams({ code: "compat-code", state: issued })}`;
    const callback = await ctx.rawRequest({ actor: "rotated-owner", path, redirect: "manual" });
    expect(callback).toMatchObject({ status: 302, location: "/retired-grant-complete" });
    const after = await ctx.readUserState({ userId: ownerId });
    expect((after as { accounts: unknown[] }).accounts).toHaveLength(
      (before as { accounts: unknown[] }).accounts.length + 1,
    );
    expect(
      (
        after as { accounts: { accountId: string; providerId: string; userId: string }[] }
      ).accounts.find((row) => row.providerId === "google"),
    ).toMatchObject({ accountId: providerId, providerId: "google", userId: ownerId });
    expect((after as { sessions: unknown }).sessions).toEqual(
      (before as { sessions: unknown }).sessions,
    );
    const current = await owner.getSession();
    expect(current.data!.session.token).toBe(reauthenticated.data!.token!);
    expect(current.data!.user.id).toBe(ownerId);
    const replay = await ctx.rawRequest({ actor: "rotated-owner", path, redirect: "manual" });
    expect(replay.status).toBe(302);
    expect(new URL(replay.location!, ctx.baseURL).pathname).toBe("/api/auth/error");
    expect(new URL(replay.location!, ctx.baseURL).searchParams.getAll("error")).toEqual([
      "state_mismatch",
    ]);
    const afterReplay = await ctx.readUserState({ userId: ownerId }),
      foreignAfter = await ctx.readUserState({ userId: foreignId });
    expect(afterReplay).toEqual(after);
    expect(foreignAfter).toEqual(foreignBefore);
    const currentAfterReplay = await owner.getSession(),
      foreignCurrent = await foreign.client.getSession();
    expect(currentAfterReplay).toEqual(current);
    expect(foreignCurrent.data!.session.token).toBe(foreignSignup.data.token!);
    return {
      signup: ctx.snapshot(signup),
      foreignSignup: ctx.snapshot(foreignSignup),
      foreignBefore,
      granted: ctx.snapshot(granted),
      retired: ctx.snapshot(retired),
      reauthenticated: ctx.snapshot(reauthenticated),
      before,
      denied,
      callback,
      after,
      current: ctx.snapshot(current),
      replay,
      afterReplay,
      foreignAfter,
      currentAfterReplay: ctx.snapshot(currentAfterReplay),
      foreignCurrent: ctx.snapshot(foreignCurrent),
    };
  },
  ["POST /link-social", "GET /callback/{}"],
);
