import { expect } from "bun:test";

import { compatScenario } from "../../../support/scenario";
import { readMagicLink } from "./helpers";
compatScenario(
  "magic-link async custom hasher owns the purpose-scoped stored identifier and verification lookup",
  async (ctx) => {
    const actor = ctx.actor("owner", "magic-link-custom-hasher");
    const email = ctx.uniqueEmail("custom-hasher");
    const issued = await actor.client.signIn.magicLink({ email, name: "Hasher owner" });
    expect(issued.error).toBeNull();
    const delivered = await readMagicLink(ctx, email);
    expect(new URL(delivered.url).searchParams.get("token")).toBe(delivered.token);
    const digest = `application:${delivered.token}`;
    const identifier = `magic-link:${digest}`;
    const stored = (await ctx.readVerificationState({ identifier })) as any[];
    expect(stored).toHaveLength(1);
    expect(stored[0].identifier).toBe(identifier);
    expect(JSON.parse(stored[0].value)).toMatchObject({
      type: "magic-link",
      email,
      name: "Hasher owner",
    });
    for (const other of [
      digest,
      `magic-link:${delivered.token}`,
      `magic-link:${new Bun.CryptoHasher("sha256").update(delivered.token).digest("base64url")}`,
    ]) {
      expect(await ctx.readVerificationState({ identifier: other })).toEqual([]);
    }
    const verified = await actor.client.magicLink.verify({ query: { token: delivered.token } });
    expect(verified.error).toBeNull();
    expect(verified.data!.user).toMatchObject({ email, emailVerified: true, name: "Hasher owner" });
    const session = await actor.client.getSession();
    expect(session.data!.user.id).toBe(verified.data!.user.id);
    const state = await ctx.readUserState({ userId: verified.data!.user.id });
    expect((state as any).sessions).toHaveLength(1);
    expect(await ctx.readVerificationState({ identifier })).toEqual([]);
    const replay = await actor.client.magicLink.verify({ query: { token: delivered.token } });
    expect(replay.error).not.toBeNull();
    expect(await ctx.readUserState({ userId: verified.data!.user.id })).toEqual(state);
    return ctx.snapshot({
      issued,
      delivered,
      stored: stored.map((row) => ({ ...row, identifier: { token: row.identifier } })),
      verified,
      session,
      state,
      replay,
    });
  },
  ["POST /sign-in/magic-link", "GET /magic-link/verify"],
);
