import { expect } from "bun:test";

import { compatScenario } from "../../../support/scenario";
for (const mode of ["masked", "throw"] as const)
  for (const kind of ["ordinary", "coded"] as const) {
    compatScenario(
      `onAPIError ${mode} ${kind} preserves the actual public handler return or exception boundary`,
      async (ctx) => {
        const state = async () =>
          (
            await ctx.rawRequest({
              path: "/__test/user-lifecycle/control",
              method: "POST",
              json: { profile: "default", action: "state" },
            })
          ).body;
        const before = await state();
        const r = await ctx.rawRequest({
          path: "/__test/api-error/invoke",
          method: "POST",
          json: { mode, kind, marker: "actual-handler-marker" },
        });
        expect(r.status).toBe(200);
        const observed = r.body as any;
        expect(observed.events).toEqual([
          { path: "/fixture-failure", method: "POST", marker: "actual-handler-marker" },
        ]);
        expect(await state()).toEqual(before);
        if (mode === "throw" && kind === "ordinary") {
          expect(observed.outcome).toBe("thrown");
          expect(observed.name).toBe("Error");
          expect(observed.message).toBe("Application handler failed");
        } else {
          expect(observed.outcome).toBe("returned");
          expect(observed.status).toBe(kind === "coded" ? 403 : 500);
          if (kind === "coded")
            expect(observed.body).toEqual({
              code: "APPLICATION_DENIED",
              message: "Application handler rejected",
            });
          expect(observed.headers["set-cookie"]).toEqual([]);
        }
        return ctx.snapshot({ before, observed });
      },
    );
  }
