import { expect } from "bun:test";
import { createAuthClient } from "better-auth/client";
import { compatScenario } from "../../support/scenario";

compatScenario(
  "social sign-in preserves previously granted account scopes",
  async (ctx) => {
    const owner = ctx.actor();
    const email = ctx.uniqueEmail("oauth-retained-scopes");
    const sub = ctx.uniqueToken("oauth-retained-scope-sub");
    const signup = await owner.client.signUp.email({
      email,
      password: "password123",
      name: "Scope Owner",
    });
    expect(signup.error).toBeNull();
    const foreign = ctx.actor("foreign");
    const foreignSignup = await foreign.client.signUp.email({
      email: ctx.uniqueEmail("oauth-foreign-scopes"),
      password: "password123",
      name: "Foreign Scope Owner",
    });
    expect(foreignSignup.error).toBeNull();
    expect(foreignSignup.data?.token).toBeTruthy();
    const foreignBefore = await ctx.readUserState({
      userId: foreignSignup.data!.user.id,
    });
    const foreignListedBefore = await foreign.client.listAccounts();
    const createdAt = "2026-10-02T06:19:31.630828Z",
      updatedAt = "2026-10-02T06:20:00.145927123Z";
    const seeded = await ctx.rawRequest({
      path: "/__test/seed-oauth-account",
      method: "POST",
      json: {
        email,
        providerId: "google",
        accountId: sub,
        scope: "calendar,drive",
        idToken: "old-id-token",
        accessToken: "stale-access-token",
        refreshToken: "seed-refresh-token",
        accessTokenExpiresAt: "2000-01-01T00:00:00Z",
        refreshTokenExpiresAt: "2099-01-01T00:00:00Z",
        createdAt,
        updatedAt,
      },
    });
    expect(seeded.status).toBe(200);
    const seedBody = seeded.body as {
      accountId: string;
      timestamps: { createdAt: string; updatedAt: string };
    };
    expect(seedBody.timestamps).toEqual({ createdAt, updatedAt });
    const accountId = seedBody.accountId;
    const wires: Record<string, unknown>[][] = [];
    const reader = createAuthClient({
      baseURL: ctx.baseURL,
      fetchOptions: {
        customFetchImpl: async (input, init) => {
          const response = await owner.fetch(input, init);
          if (new URL(String(input)).pathname.endsWith("/list-accounts"))
            wires.push(await response.clone().json());
          return response;
        },
      },
    });
    const before = await reader.listAccounts();
    expect(before.error).toBeNull();
    const original = before.data!.find((account) => account.id === accountId)!;
    expect(original.createdAt).toBeInstanceOf(Date);
    expect(original.createdAt.getTime()).toBe(Date.parse(createdAt));
    expect(original.updatedAt).toBeInstanceOf(Date);
    expect(original.updatedAt.getTime()).toBe(Date.parse(updatedAt));
    const originalWire = wires
      .at(-1)!
      .find((account) => account.id === accountId)!;
    expect(originalWire.createdAt).toBe("2026-10-02T06:19:31.630Z");
    expect(originalWire.updatedAt).toBe("2026-10-02T06:20:00.145Z");
    const credential = before.data!.find(
      (account) => account.providerId === "credential",
    )!;
    const guest = await ctx.actor("guest").client.listAccounts();
    expect(guest.error?.status).toBe(401);
    expect(guest.error?.code).toBe("UNAUTHORIZED");
    expect(guest.error?.message).toBe("Unauthorized");
    const callbackStarted = Date.now();
    await ctx.setSocialProfile({
      sub,
      email,
      emailVerified: true,
      name: "Google Scope Owner",
    });
    const started = await owner.client.signIn.social({
      provider: "google",
      callbackURL: "/scopes",
    });
    expect(started.error).toBeNull();
    const state = new URL(started.data!.url!).searchParams.get("state");
    expect(state).toBeTruthy();
    const callback = await ctx.rawRequest({
      path: `/api/auth/callback/google?code=compat-code&state=${encodeURIComponent(state!)}`,
      redirect: "manual",
    });
    expect(callback.status).toBe(302);
    expect(callback.location).toBe("/scopes");
    const session = await owner.client.getSession();
    expect(session.data?.user.id).toBe(signup.data?.user.id);
    expect(session.data?.session.userId).toBe(signup.data?.user.id);
    const callbackFinished = Date.now();
    const listed = await reader.listAccounts();
    expect(listed.error).toBeNull();
    const google = listed.data?.find(
      (account) => account.providerId === "google",
    );
    expect(google?.id).toBe(accountId);
    expect(google?.accountId).toBe(sub);
    expect(google?.scopes).toEqual(["calendar", "drive"]);
    expect(google?.createdAt).toBeInstanceOf(Date);
    expect(google?.createdAt.getTime()).toBe(Date.parse(createdAt));
    expect(google?.updatedAt).toBeInstanceOf(Date);
    expect(google!.updatedAt.getTime()).toBeGreaterThanOrEqual(callbackStarted);
    expect(google!.updatedAt.getTime()).toBeLessThanOrEqual(callbackFinished);
    const googleWire = wires
      .at(-1)!
      .find((account) => account.id === accountId)!;
    expect(googleWire.createdAt).toBe(originalWire.createdAt);
    expect(googleWire.updatedAt).toMatch(
      /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/,
    );
    expect(google!.updatedAt.getTime()).toBe(
      Date.parse(googleWire.updatedAt as string),
    );
    expect(
      listed.data!.find((account) => account.providerId === "credential"),
    ).toEqual(credential);
    const foreignAfter = await ctx.readUserState({
      userId: foreignSignup.data!.user.id,
    });
    const foreignListedAfter = await foreign.client.listAccounts();
    expect(foreignAfter).toEqual(foreignBefore);
    expect(foreignListedAfter).toEqual(foreignListedBefore);
    const foreignSession = await foreign.client.getSession();
    expect(foreignSession.data?.user.id).toBe(foreignSignup.data?.user.id);
    expect(foreignSession.data?.session.token).toBe(foreignSignup.data!.token!);
    return {
      seeded,
      before,
      wires,
      guest,
      callback,
      session,
      listed,
      foreignBefore,
      foreignAfter,
      foreignListedBefore,
      foreignListedAfter,
      foreignSession,
    };
  },
  ["GET /list-accounts"],
);
