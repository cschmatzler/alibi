import { expect } from "bun:test";

import { createAuthClient } from "better-auth/client";
import { deviceAuthorizationClient } from "better-auth/client/plugins";

import { authProfilePath } from "../../../support/profiles";
import { compatScenario } from "../../../support/scenario";

compatScenario(
  "device successful async request callback observes raw scope before issuance",
  async (ctx) => {
    const profile = "device-callback-success";
    const actor = createAuthClient({
      baseURL: ctx.baseURL + authProfilePath(profile),
      plugins: [deviceAuthorizationClient()],
      fetchOptions: { customFetchImpl: ctx.actor("request", profile).fetch },
    });
    await ctx.rawRequest({ path: "/__test/device-callback-events" });
    const observations = [];
    for (const [index, scope] of [undefined, "read write", "s".repeat(1024)].entries()) {
      const clientId = ctx.uniqueToken(`device-callback-${index}`);
      const issued = await actor.device.code({
        client_id: clientId,
        ...(scope === undefined ? {} : { scope }),
      });
      expect(issued.error).toBeNull();
      const events = await ctx.rawRequest({ path: "/__test/device-callback-events" });
      expect(events.body).toEqual([{ clientId, scope: scope ?? null, persistedBeforeCallback: 0 }]);
      const stored = await ctx.rawRequest({
        path: `/__test/device-state?deviceCode=${encodeURIComponent(issued.data!.device_code)}`,
      });
      expect(stored.body).toMatchObject({
        clientId,
        scope: scope ?? null,
        status: "pending",
        userId: null,
      });
      expect((stored.body as any).deviceCode).toBe(issued.data!.device_code);
      observations.push({ issued, events, stored });
    }
    return ctx.snapshot(observations);
  },
  ["POST /device/code"],
);
