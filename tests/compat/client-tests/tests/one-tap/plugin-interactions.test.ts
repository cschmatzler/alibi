import { expect } from "bun:test";
import { createHmac } from "node:crypto";
import { createAuthClient } from "better-auth/client";
import { twoFactorClient } from "better-auth/client/plugins";
import { z } from "zod";
import { credential } from "../../support/id-token";
import { authProfilePath } from "../../support/profiles";
import { compatScenario } from "../../support/scenario";
import { oneTap, responseSchema, state, successful } from "./helpers";

function totp(uri: string) {
  const parsed = new URL(uri);
  const secret = parsed.searchParams.get("secret");
  if (!secret) throw new Error("Missing actual TOTP enrollment secret");
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0,
    value = 0;
  const bytes = [];
  for (const char of secret.toUpperCase().replace(/=+$/g, "")) {
    const index = alphabet.indexOf(char);
    if (index < 0) throw new Error("Invalid actual enrollment secret");
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      bytes.push((value >>> bits) & 255);
    }
  }
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(
    BigInt(Math.floor(Date.now() / 1000 / Number(parsed.searchParams.get("period") ?? 30))),
  );
  const digest = createHmac("sha1", Buffer.from(bytes)).update(counter).digest();
  const offset = digest[digest.length - 1]! & 15;
  return (
    (digest.readUInt32BE(offset) & 0x7fffffff) %
    10 ** Number(parsed.searchParams.get("digits") ?? 6)
  )
    .toString()
    .padStart(Number(parsed.searchParams.get("digits") ?? 6), "0");
}
compatScenario(
  "One Tap respects persisted admin bans and existing two-factor session behavior",
  async (ctx) => {
    const baseline = await state(ctx);
    const email = ctx.uniqueEmail("plugin-google");
    const sub = ctx.uniqueToken("plugin-google");
    const token = await credential({
      sub,
      email,
      email_verified: true,
      name: "Plugin Google",
    });
    const owner = ctx.actor("owner", "one-tap-default");
    const local = await owner.client.signUp.email({
      email,
      password: "password123",
      name: "Plugin Google",
    });
    expect(local.error).toBeNull();
    const sent = await owner.client.sendVerificationEmail({ email });
    expect(sent.error).toBeNull();
    const delivery = z
      .object({ token: z.string() })
      .parse(await ctx.readVerificationEmail({ email }));
    const emailVerified = await owner.client.verifyEmail({
      query: { token: delivery.token },
    });
    expect(emailVerified.error).toBeNull();
    const created = await successful(ctx, token, "one-tap-default", "owner");
    const userId = created.response.data!.user.id;
    const twoFactor = createAuthClient({
      baseURL: ctx.baseURL + authProfilePath("one-tap-default"),
      plugins: [twoFactorClient()],
      fetchOptions: { customFetchImpl: owner.fetch },
    });
    const enrollment = await twoFactor.twoFactor.enable({
      password: "password123",
    });
    expect(enrollment.error).toBeNull();
    if (!enrollment.data || !("totpURI" in enrollment.data))
      throw new Error("Missing real TOTP enrollment");
    const verified = await twoFactor.twoFactor.verifyTotp({
      code: totp(enrollment.data.totpURI),
    });
    expect(verified.error).toBeNull();
    const enabled = await owner.client.getSession();
    expect(enabled.data?.user).toMatchObject({
      id: userId,
      twoFactorEnabled: true,
    });
    await owner.client.signOut();
    const signedIn = await successful(ctx, token, "one-tap-default", "owner");
    expect(signedIn.response.data?.user).toMatchObject({
      id: userId,
      twoFactorEnabled: true,
    });
    const session = await owner.client.getSession();
    expect(session.data?.session.token).toBe(signedIn.response.data?.token);
    expect(session.data?.session.userId).toBe(userId);
    const admin = ctx.actor("admin", "one-tap-default");
    const adminEmail = ctx.uniqueEmail("one-tap-admin");
    const signup = await admin.client.signUp.email({
      email: adminEmail,
      password: "password123",
      name: "Fixture Admin",
    });
    expect(signup.error).toBeNull();
    await ctx.promoteAdmin({ email: adminEmail });
    const banned = await admin.client.admin.banUser({
      userId,
      banReason: "fixture policy",
    });
    expect(banned.error).toBeNull();
    const before = await state(ctx);
    expect(before.sessions.filter((row) => row.userId === userId)).toHaveLength(0);
    const denied = responseSchema.parse(await oneTap(ctx, token, "one-tap-default", "blocked"));
    expect(denied.response.error).toMatchObject({
      status: 403,
      code: "BANNED_USER",
    });
    const after = await state(ctx);
    expect(after.users).toEqual(before.users);
    expect(after.accounts).toEqual(before.accounts);
    expect(after.sessions).toEqual(before.sessions);
    const unauthenticated = await ctx.actor("blocked", "one-tap-default").client.getSession();
    expect(unauthenticated.data).toBeNull();
    return {
      created,
      signedIn,
      session,
      denied,
      unauthenticated,
      after: {
        ...after,
        jwksFetches: after.jwksFetches - baseline.jwksFetches,
      },
    };
  },
  ["POST /one-tap/callback"],
);
