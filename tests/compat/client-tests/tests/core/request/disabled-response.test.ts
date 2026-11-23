import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";

compatScenario(
  "Disabled paths preserve the upstream literal rejection before parsing and hooks",
  async (ctx) => {
    const actor = ctx.actor();
    const observations = [];
    for (const [profile, path, method] of [
      ["dispatch-disabled-email", "/sign-in/email/", "POST"],
      ["dispatch-disabled-literal", "/owned/item", "GET"],
    ] as const) {
      // Drain events left by other scenarios before recording this request.
      const reset = await fetch(`${ctx.baseURL}/__test/dispatch-events`);
      expect(reset.status).toBe(200);
      await reset.arrayBuffer();
      const response = await actor.fetch(
        `${ctx.baseURL}/__test/profiles/${profile}/api/auth${path}`,
        {
          method,
          headers: { "content-type": "application/json", origin: "https://foreign.fixture.test" },
          ...(method === "POST" ? { body: "{" } : {}),
        },
      );
      expect(response.status).toBe(404);
      const contentType = response.headers.get("content-type");
      const body = await response.text();
      expect(contentType).toBe("text/plain; charset=UTF-8");
      expect(body).toBe("Not Found");
      expect(response.headers.getSetCookie()).toEqual([]);
      const hooks = await actor.fetch(`${ctx.baseURL}/__test/dispatch-events`);
      expect(hooks.status).toBe(200);
      expect(await hooks.json()).toEqual([]);
      observations.push({ profile, path, method, status: response.status, contentType, body });
    }
    return observations;
  },
);
