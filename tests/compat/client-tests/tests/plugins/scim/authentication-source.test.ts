import { expect } from "bun:test";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "SCIM startup requires a provisioning authentication source while valid catalogs retain public discovery",
  async (ctx) => {
    const results = [];
    for (const mode of ["empty", "static", "managed"]) {
      const result = await ctx.rawRequest({
        path: "/__test/server-api/scim?operation=probe-authentication-source",
        method: "POST",
        json: { mode },
      });
      expect(result.status).toBe(mode === "empty" ? 400 : 200);
      if (mode === "empty") {
        expect(result.body).toEqual({
          error:
            "The scim plugin requires a provisioning connection, bearer token verifier, or managed connection catalog.",
        });
      } else expect((result.body as any).Resources).toHaveLength(2);
      results.push({ mode, result });
    }
    return ctx.snapshot({ results });
  },
  ["GET /scim/v2/ResourceTypes"],
);
