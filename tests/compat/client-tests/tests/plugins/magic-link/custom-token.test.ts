import { expect } from "bun:test";

import { z } from "zod";

import { compatScenario } from "../../../support/scenario";
import { readMagicLink } from "./helpers";

compatScenario(
  "magic-link custom generator receives email and its exact token is hashed stored verified and consumed",
  async (ctx) => {
    const actor = ctx.actor("custom-magic", "magic-link-hashed-custom-token");
    const email = ctx.uniqueEmail("custom-magic");
    const issued = await actor.client.signIn.magicLink({ email });
    expect(issued.error).toBeNull();
    const delivered = await readMagicLink(ctx, email);
    expect(delivered.token).toBe(`custom-link-${email}`);
    expect(new URL(delivered.url).searchParams.get("token")).toBe(delivered.token);
    const digest = new Bun.CryptoHasher("sha256").update(delivered.token).digest("base64url");
    const identifier = `magic-link:${digest}`;
    const stored = z
      .array(
        z.object({
          id: z.string(),
          identifier: z.string(),
          value: z.string(),
          expiresAt: z.string(),
        }),
      )
      .parse(await ctx.readVerificationState({ identifier }));
    expect(stored).toHaveLength(1);
    expect(stored[0]!.identifier).toBe(identifier);
    expect(
      await ctx.readVerificationState({ identifier: `magic-link:${delivered.token}` }),
    ).toEqual([]);
    const verified = await actor.client.magicLink.verify({ query: { token: delivered.token } });
    expect(verified.error).toBeNull();
    expect(verified.data?.user.email).toBe(email);
    expect(verified.data?.user.emailVerified).toBe(true);
    expect(await ctx.readVerificationState({ identifier })).toEqual([]);
    const session = await actor.client.getSession();
    expect(session.data?.user.id).toBe(verified.data!.user.id);
    const replay = await actor.client.magicLink.verify({ query: { token: delivered.token } });
    expect(replay.error).not.toBeNull();
    return ctx.snapshot({ issued, delivered, stored, verified, session, replay });
  },
  ["POST /sign-in/magic-link", "GET /magic-link/verify"],
);
