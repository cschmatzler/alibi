import { expect } from "bun:test";

import { compatScenario } from "../../../support/scenario";
import { readMagicLink } from "./helpers";
for (const mode of ["coded", "ordinary"] as const) {
  compatScenario(
    `magic-link ${mode} sender rejection retains its committed proof for redemption`,
    async (ctx) => {
      const control = async (json: unknown = {}) => {
        const r = await ctx.rawRequest({
          path: "/__test/magic-link/generator-control",
          method: "POST",
          json,
        });
        expect(r.status).toBe(200);
        return r.body as any;
      };
      const before = await control({ mode: "success", clear: true });
      expect(before).toMatchObject({ proofCount: 0, userCount: 0, sessionCount: 0 });
      const actor = ctx.actor("owner", `magic-link-sender-${mode}`);
      const email = ctx.uniqueEmail("delivery-owner");
      const denied = await actor.client.signIn.magicLink({ email, name: "Delivery owner" });
      expect(denied.error!.status).toBe(mode === "coded" ? 403 : 500);
      const delivered = await readMagicLink(ctx, email);
      expect(new URL(delivered.url).searchParams.get("token")).toBe(delivered.token);
      const identifier = `magic-link:${delivered.token}`;
      const pending = (await ctx.readVerificationState({ identifier })) as any[];
      expect(pending).toHaveLength(1);
      expect(pending[0].identifier).toBe(identifier);
      expect(JSON.parse(pending[0].value)).toMatchObject({
        type: "magic-link",
        email,
        name: "Delivery owner",
      });
      const failed = await control();
      expect(failed).toMatchObject({ proofCount: 1, userCount: 0, sessionCount: 0 });
      expect((await actor.client.getSession()).data).toBeNull();
      const verified = await actor.client.magicLink.verify({ query: { token: delivered.token } });
      expect(verified.error).toBeNull();
      expect(verified.data!.user).toMatchObject({
        email,
        name: "Delivery owner",
        emailVerified: true,
      });
      const session = await actor.client.getSession();
      expect(session.data!.user.id).toBe(verified.data!.user.id);
      expect(await ctx.readVerificationState({ identifier })).toEqual([]);
      const after = await control();
      expect(after).toMatchObject({ proofCount: 0, userCount: 1, sessionCount: 1 });
      const replay = await actor.client.magicLink.verify({ query: { token: delivered.token } });
      expect(replay.error).not.toBeNull();
      if (mode === "coded")
        expect(denied.error).toMatchObject({
          code: "MAGIC_DELIVERY_REJECTED",
          message: "Application delivery rejected",
        });
      return ctx.snapshot({
        before,
        denied,
        delivered,
        pending: pending.map((row) => ({ ...row, identifier: { token: row.identifier } })),
        failed,
        verified,
        session,
        after,
        replay,
      });
    },
    ["POST /sign-in/magic-link"],
  );
}
