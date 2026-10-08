import { expect } from "bun:test";

import { authProfilePath } from "../../../support/profiles";
import { compatScenario } from "../../../support/scenario";
for (const skip of [false, true]) {
  for (const cookie of ["absent", "mismatched"] as const) {
    compatScenario(
      `OAuth skipStateCookieCheck=${skip} with ${cookie} cookie still requires stored state`,
      async (ctx) => {
        const profile = skip ? "generic-token-skip-state-cookie" : "generic-token-none";
        const initiator = ctx.actor("initiator", profile);
        const receiver = ctx.actor("receiver", profile);
        const email = ctx.uniqueEmail("cookie-state-owner");
        await ctx.rawRequest({
          path: "/__test/generic-token/control",
          method: "POST",
          json: {
            profile: {
              id: "cookie-state-subject",
              email,
              name: "State owner",
              email_verified: true,
            },
          },
        });
        const start = await initiator.client.signIn.social({
          provider: "generic",
          callbackURL: "/dashboard",
        });
        expect(start.error).toBeNull();
        const state = new URL(start.data!.url!).searchParams.get("state")!;
        if (cookie === "mismatched")
          expect(
            (await receiver.client.signIn.social({ provider: "generic", callbackURL: "/wrong" }))
              .error,
          ).toBeNull();
        const physical = async () =>
          (await ctx.rawRequest({ path: "/__test/social-provider/state" })).body as any;
        const before = await physical();
        const callback = async (actor: typeof receiver, state: string) => {
          const r = await actor.fetch(
            ctx.baseURL +
              authProfilePath(profile) +
              `/callback/generic?code=state-code&state=${encodeURIComponent(state)}`,
            { redirect: "manual" },
          );
          return { status: r.status, location: r.headers.get("location") };
        };
        const invalid = await callback(receiver, "never-issued-state");
        expect(new URL(invalid.location!, ctx.baseURL).searchParams.get("error")).toBe(
          "state_mismatch",
        );
        expect(await physical()).toEqual(before);
        const result = await callback(receiver, state);
        expect(result.status).toBe(302);
        if (skip) {
          expect(result.location).toBe("/dashboard");
        } else {
          expect(new URL(result.location!, ctx.baseURL).searchParams.get("error")).toBe(
            "state_mismatch",
          );
          expect(await physical()).toEqual(before);
          expect((await receiver.client.getSession()).data).toBeNull();
          const recovered = await callback(initiator, state);
          expect(recovered.location).toBe("/dashboard");
        }
        const admitted = skip ? receiver : initiator;
        const session = await admitted.client.getSession();
        expect(session.data!.user.email).toBe(email);
        const after = await physical();
        expect(after.users).toHaveLength(1);
        expect(after.accounts).toHaveLength(1);
        expect(after.sessions).toHaveLength(1);
        const replay = await callback(admitted, state);
        expect(new URL(replay.location!, ctx.baseURL).searchParams.get("error")).toBe(
          "state_mismatch",
        );
        expect(await physical()).toEqual(after);
        return ctx.snapshot({ before, invalid, result, session, after, replay });
      },
      ["POST /sign-in/social", "GET /callback/{}"],
    );
  }
}
