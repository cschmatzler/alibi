import { expect } from "bun:test";

import { compatScenario } from "../../../support/scenario";
import { readMagicLink } from "./helpers";
for (const mode of ["coded", "ordinary"] as const) {
  compatScenario(
    `magic-link ${mode} custom hasher rejection preserves proof until successful verification retry`,
    async (ctx) => {
      const configure = async (mode: string) => {
        const response = await ctx.rawRequest({
          path: "/__test/magic-link/hasher-control",
          method: "POST",
          json: { mode },
        });
        expect(response.status).toBe(200);
      };
      await configure("success");
      const actor = ctx.actor("owner", "magic-link-custom-hasher-errors");
      const email = ctx.uniqueEmail("hash-error");
      const issued = await actor.client.signIn.magicLink({ email });
      expect(issued.error).toBeNull();
      const delivered = await readMagicLink(ctx, email);
      const identifier = `magic-link:application:${delivered.token}`;
      const before = (await ctx.readVerificationState({ identifier })) as any[];
      expect(before).toHaveLength(1);
      await configure(mode);
      const denied = await actor.client.magicLink.verify({ query: { token: delivered.token } });
      expect(denied.error!.status).toBe(mode === "coded" ? 403 : 500);
      if (mode === "coded") {
        expect(denied.error).toMatchObject({
          code: "MAGIC_HASH_REJECTED",
          message: "Application hasher rejected",
        });
      }
      expect(await ctx.readVerificationState({ identifier })).toEqual(before);
      expect((await actor.client.getSession()).data).toBeNull();
      const untouched = (await ctx.rawRequest({ path: "/__test/social-provider/state" }))
        .body as any;
      expect(untouched.users).toEqual([]);
      expect(untouched.accounts).toEqual([]);
      expect(untouched.sessions).toEqual([]);
      await configure("success");
      const verified = await actor.client.magicLink.verify({ query: { token: delivered.token } });
      expect(verified.error).toBeNull();
      expect(verified.data!.user.email).toBe(email);
      expect(await ctx.readVerificationState({ identifier })).toEqual([]);
      const after = (await ctx.readUserState({ userId: verified.data!.user.id })) as any;
      expect(after.sessions).toHaveLength(1);
      const replay = await actor.client.magicLink.verify({ query: { token: delivered.token } });
      expect(replay.error).not.toBeNull();
      return ctx.snapshot({
        issued,
        delivered,
        before: before.map((r) => ({ ...r, identifier: { token: r.identifier } })),
        denied,
        untouched,
        verified,
        after,
        replay,
      });
    },
    ["GET /magic-link/verify"],
  );
}
