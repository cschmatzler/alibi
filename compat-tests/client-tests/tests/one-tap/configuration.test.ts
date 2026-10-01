import { expect } from "bun:test";
import { z } from "zod";
import { compatScenario } from "../../support/scenario";
import {
  credential,
  state,
  successful,
  oneTap,
  responseSchema,
} from "./helpers";
const deliverySchema = z.object({ url: z.string(), token: z.string() });
compatScenario(
  "One Tap immutable audience configuration and hosted domains",
  async (ctx) => {
    const initial = await state(ctx);
    const outcomes = [];
    for (const [profile, aud, hd, allowed] of [
      ["one-tap-default", "one-tap-plugin-client", undefined, true],
      ["one-tap-default", "one-tap-provider-client", undefined, false],
      ["one-tap-fallback", "one-tap-provider-client", undefined, true],
      ["one-tap-fallback", "one-tap-provider-secondary", undefined, true],
      [
        "one-tap-fallback",
        ["foreign-audience", "one-tap-provider-secondary"],
        undefined,
        true,
      ],
      [
        "one-tap-domain",
        "one-tap-plugin-client",
        "workspace.fixture.test",
        true,
      ],
      [
        "one-tap-domain",
        "one-tap-plugin-client",
        "WORKSPACE.fixture.test",
        false,
      ],
      ["one-tap-domain", "one-tap-plugin-client", undefined, false],
      [
        "one-tap-domain-any",
        "one-tap-plugin-client",
        "another.fixture.test",
        true,
      ],
      ["one-tap-domain-any", "one-tap-plugin-client", "", false],
    ] as const) {
      const sub = ctx.uniqueToken(`config-${outcomes.length}`);
      const email = ctx.uniqueEmail(`config-${outcomes.length}`);
      const result = responseSchema.parse(
        await oneTap(
          ctx,
          await credential({ sub, email, aud, hd, email_verified: true }),
          profile,
        ),
      );
      if (allowed) expect(result.response.error).toBeNull();
      else
        expect(result.response.error).toMatchObject({
          status: 400,
          message: "invalid id token",
        });
      outcomes.push(result);
    }
    const beforeMissing = await state(ctx);
    for (const profile of ["one-tap-missing", "one-tap-empty-array"] as const) {
      const result = responseSchema.parse(
        await oneTap(
          ctx,
          await credential({ sub: "missing-sub", email: "missing@test.com" }),
          profile,
        ),
      );
      expect(result.response.error?.status).toBe(400);
      expect(result.response.error?.message).toContain(
        "Google client ID is required for One Tap",
      );
      outcomes.push(result);
    }
    const persisted = await state(ctx);
    expect(persisted.jwksFetches).toBe(beforeMissing.jwksFetches);
    expect(persisted.users).toHaveLength(6);
    expect(persisted.accounts).toHaveLength(6);
    expect(persisted.sessions).toHaveLength(6);
    return {
      outcomes,
      persisted: {
        ...persisted,
        jwksFetches: persisted.jwksFetches - initial.jwksFetches,
      },
    };
  },
);
compatScenario(
  "One Tap required email verification commits identity before delivery and session",
  async (ctx) => {
    const initial = await state(ctx);
    const email = ctx.uniqueEmail("google-verification");
    const sub = ctx.uniqueToken("google-verification");
    const token = await credential({
      sub,
      email,
      name: "Unverified Google",
      email_verified: false,
    });
    const denied = responseSchema.parse(
      await oneTap(ctx, token, "one-tap-required", "verify", "/after-google"),
    );
    expect(denied.response.error).toMatchObject({
      status: 403,
      code: "EMAIL_NOT_VERIFIED",
      message: "Email not verified",
    });
    expect(denied.location).toBe("/before");
    const committed = await state(ctx);
    expect(committed.users).toMatchObject([{ email, emailVerified: false }]);
    expect(committed.accounts).toMatchObject([
      { accountId: sub, userId: committed.users[0]!.id, idToken: token },
    ]);
    expect(committed.sessions).toHaveLength(0);
    const delivery = deliverySchema.parse(
      await ctx.readVerificationEmail({ email }),
    );
    expect(new URL(delivery.url).pathname).toBe(
      "/__test/profiles/one-tap-required/api/auth/verify-email",
    );
    expect(new URL(delivery.url).searchParams.get("callbackURL")).toBe("/");
    const again = responseSchema.parse(
      await oneTap(ctx, token, "one-tap-required", "verify"),
    );
    expect(again.response.error?.code).toBe("EMAIL_NOT_VERIFIED");
    const verified = await ctx
      .actor("verify", "one-tap-required")
      .client.verifyEmail({ query: { token: delivery.token } });
    expect(verified.error).toBeNull();
    const accepted = await successful(ctx, token, "one-tap-required", "verify");
    expect(accepted.response.data?.user).toMatchObject({
      id: committed.users[0]!.id,
      email,
      emailVerified: true,
    });
    const session = await ctx
      .actor("verify", "one-tap-required")
      .client.getSession();
    expect(session.data?.session.userId).toBe(committed.users[0]!.id);
    expect(session.data?.session.token).toBe(accepted.response.data?.token);
    const final = await state(ctx);
    expect(final.accounts).toHaveLength(1);
    expect(final.users).toHaveLength(1);
    expect(final.sessions).toHaveLength(1);
    return {
      denied,
      again,
      delivery,
      verified,
      accepted,
      session,
      committed: {
        ...committed,
        jwksFetches: committed.jwksFetches - initial.jwksFetches,
      },
      final: { ...final, jwksFetches: final.jwksFetches - initial.jwksFetches },
    };
  },
);
compatScenario(
  "One Tap explicit signup mail suppression preserves verification denial side effects",
  async (ctx) => {
    const initial = await state(ctx);
    const email = ctx.uniqueEmail("google-no-mail");
    const token = await credential({
      sub: ctx.uniqueToken("no-mail"),
      email,
      email_verified: false,
    });
    const denied = responseSchema.parse(
      await oneTap(ctx, token, "one-tap-required-no-mail"),
    );
    expect(denied.response.error?.code).toBe("EMAIL_NOT_VERIFIED");
    const delivery = await ctx.readVerificationEmail({ email });
    expect(delivery).toBeNull();
    const persisted = await state(ctx);
    expect(persisted.users).toMatchObject([{ email, emailVerified: false }]);
    expect(persisted.accounts).toHaveLength(1);
    expect(persisted.sessions).toHaveLength(0);
    return {
      denied,
      delivery,
      persisted: {
        ...persisted,
        jwksFetches: persisted.jwksFetches - initial.jwksFetches,
      },
    };
  },
);
compatScenario(
  "One Tap implicit linking applies configured profile sync and preserves local identity",
  async (ctx) => {
    const baseline = await state(ctx);
    const actor = ctx.actor("local", "one-tap-update-link");
    const email = ctx.uniqueEmail("local-link");
    const signup = await actor.client.signUp.email({
      email,
      password: "password123",
      name: "Local Profile",
    });
    expect(signup.error).toBeNull();
    const userId = signup.data!.user.id;
    const sub = ctx.uniqueToken("linked-google");
    const token = await credential({
      sub,
      email,
      email_verified: false,
      name: "Linked Provider Profile",
      picture: "https://fixture.test/linked.png",
      userId: "forged-owner",
    });
    const denied = responseSchema.parse(
      await oneTap(ctx, token, "one-tap-update-link", "local"),
    );
    expect(denied.response.error).toMatchObject({
      status: 401,
      message: "account not linked",
    });
    const blocked = await state(ctx);
    expect(blocked.accounts).toMatchObject([
      { userId, providerId: "credential" },
    ]);
    expect(blocked.users).toMatchObject([
      { id: userId, email, name: "Local Profile", emailVerified: false },
    ]);
    const sent = await actor.client.sendVerificationEmail({ email });
    expect(sent.error).toBeNull();
    const delivery = deliverySchema.parse(
      await ctx.readVerificationEmail({ email }),
    );
    const verified = await actor.client.verifyEmail({
      query: { token: delivery.token },
    });
    expect(verified.error).toBeNull();
    const linked = await successful(ctx, token, "one-tap-update-link", "local");
    expect(linked.response.data?.user).toMatchObject({
      id: userId,
      email,
      emailVerified: true,
      name: "Linked Provider Profile",
      image: "https://fixture.test/linked.png",
    });
    const persisted = await state(ctx);
    expect(persisted.users).toMatchObject([
      {
        id: userId,
        email,
        emailVerified: true,
        name: "Linked Provider Profile",
      },
    ]);
    expect(persisted.accounts).toHaveLength(2);
    expect(
      persisted.accounts.find((row) => row.providerId === "google"),
    ).toMatchObject({
      userId,
      accountId: sub,
      scope: "openid,profile,email",
      idToken: token,
    });
    expect(
      persisted.sessions.find(
        (row) => row.token === linked.response.data?.token,
      ),
    ).toMatchObject({ userId });
    return {
      signup,
      denied,
      sent,
      verified,
      linked,
      persisted: {
        ...persisted,
        jwksFetches: persisted.jwksFetches - baseline.jwksFetches,
      },
    };
  },
);
compatScenario(
  "One Tap ID token storage honors encryption and retained-account configurations",
  async (ctx) => {
    const baseline = await state(ctx);
    const email = ctx.uniqueEmail("stored-google");
    const sub = ctx.uniqueToken("stored-google");
    const token = await credential({
      sub,
      email,
      email_verified: true,
      name: "Stored Google",
    });
    const created = await successful(
      ctx,
      token,
      "one-tap-encrypted",
      "storage",
    );
    const initial = await state(ctx);
    expect(initial.accounts).toMatchObject([
      { userId: created.response.data?.user.id, idToken: token },
    ]);
    const fresh = await credential({
      sub,
      email,
      email_verified: true,
      name: "Changed Profile",
      nonce: "fresh-token",
    });
    const retained = await successful(
      ctx,
      fresh,
      "one-tap-retain-account",
      "storage",
    );
    const unchanged = await state(ctx);
    expect(unchanged.accounts).toEqual(initial.accounts);
    expect(retained.response.data?.user.id).toBe(
      created.response.data?.user.id,
    );
    const cookie = await successful(
      ctx,
      fresh,
      "one-tap-account-cookie",
      "storage",
    );
    const persisted = await state(ctx);
    expect(persisted.accounts).toMatchObject([
      {
        userId: created.response.data?.user.id,
        idToken: fresh,
        scope: "openid,profile,email",
      },
    ]);
    const session = await ctx
      .actor("storage", "one-tap-account-cookie")
      .client.getSession();
    expect(session.data?.user.id).toBe(created.response.data?.user.id);
    expect(session.data?.session.token).toBe(cookie.response.data?.token);
    return {
      created,
      retained,
      cookie,
      session,
      persisted: {
        ...persisted,
        jwksFetches: persisted.jwksFetches - baseline.jwksFetches,
      },
    };
  },
);

compatScenario(
  "One Tap preserves the signed browser-session preference cookie",
  async (ctx) => {
    const baseline = await state(ctx);
    const actor = ctx.actor("browser-session", "one-tap-default");
    const email = ctx.uniqueEmail("browser-google");
    const signup = await actor.client.signUp.email({
      email,
      password: "password123",
      name: "Browser Session",
    });
    expect(signup.error).toBeNull();
    await actor.client.signOut();
    const shortSession = await actor.client.signIn.email({
      email,
      password: "password123",
      rememberMe: false,
    });
    expect(shortSession.error).toBeNull();
    const sent = await actor.client.sendVerificationEmail({ email });
    expect(sent.error).toBeNull();
    const delivery = deliverySchema.parse(
      await ctx.readVerificationEmail({ email }),
    );
    const verified = await actor.client.verifyEmail({
      query: { token: delivery.token },
    });
    expect(verified.error).toBeNull();
    const token = await credential({
      sub: ctx.uniqueToken("browser-google"),
      email,
      email_verified: true,
    });
    const signedIn = await successful(
      ctx,
      token,
      "one-tap-default",
      "browser-session",
    );
    expect(signedIn.sessionMaxAge).toBeNull();
    const session = await actor.client.getSession();
    expect(session.data?.session.userId).toBe(signup.data?.user.id);
    expect(session.data?.session.token).toBe(signedIn.response.data?.token);
    const persisted = await state(ctx);
    expect(
      persisted.accounts.find((row) => row.providerId === "google"),
    ).toMatchObject({ userId: signup.data?.user.id, idToken: token });
    return {
      signup,
      signedIn,
      session,
      persisted: {
        ...persisted,
        jwksFetches: persisted.jwksFetches - baseline.jwksFetches,
      },
    };
  },
);
compatScenario(
  "One Tap retains the upstream user snapshot during email verification upgrades",
  async (ctx) => {
    const baseline = await state(ctx);
    const outcomes = [];
    for (const profile of ["one-tap-default", "one-tap-required"] as const) {
      const email = ctx.uniqueEmail(`upgrade-${profile}`);
      const sub = ctx.uniqueToken(`upgrade-${profile}`);
      const initial = await credential({
        sub,
        email,
        email_verified: false,
        name: "Snapshot Google",
      });
      const verifiedToken = await credential({
        sub,
        email,
        email_verified: true,
        name: "Snapshot Google",
      });
      const first = responseSchema.parse(
        await oneTap(ctx, initial, profile, "upgrade"),
      );
      if (profile === "one-tap-required")
        expect(first.response.error?.code).toBe("EMAIL_NOT_VERIFIED");
      else expect(first.response.data?.user.emailVerified).toBe(false);
      const committed = await state(ctx);
      const userId = committed.users.find((row) => row.email === email)!.id;
      const beforeSessions = committed.sessions.filter(
        (row) => row.userId === userId,
      ).length;
      const upgrade = responseSchema.parse(
        await oneTap(ctx, verifiedToken, profile, "upgrade"),
      );
      if (profile === "one-tap-required")
        expect(upgrade.response.error?.code).toBe("EMAIL_NOT_VERIFIED");
      else
        expect(upgrade.response.data?.user).toMatchObject({
          id: userId,
          emailVerified: false,
        });
      const upgraded = await state(ctx);
      expect(
        upgraded.users.find((row) => row.id === userId)?.emailVerified,
      ).toBe(true);
      expect(
        upgraded.sessions.filter((row) => row.userId === userId),
      ).toHaveLength(beforeSessions + (profile === "one-tap-default" ? 1 : 0));
      const repeat = await successful(ctx, verifiedToken, profile, "upgrade");
      expect(repeat.response.data?.user).toMatchObject({
        id: userId,
        email,
        emailVerified: true,
      });
      outcomes.push({ first, upgrade, repeat });
    }
    const persisted = await state(ctx);
    return {
      outcomes,
      persisted: {
        ...persisted,
        jwksFetches: persisted.jwksFetches - baseline.jwksFetches,
      },
    };
  },
);
