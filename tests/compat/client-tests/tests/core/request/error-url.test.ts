import { expect } from "bun:test";

import { authProfilePath } from "../../../support/profiles";
import { compatScenario } from "../../../support/scenario";
compatScenario(
  "configured error URL preserves existing query and fragment and takes precedence over HTML customization",
  async (ctx) => {
    const observations = [];
    for (const profile of ["error-url-redirect", "error-url-html"] as const) {
      for (const description of [undefined, "detail + & café"]) {
        const query = new URLSearchParams({ error: "BAD_CODE" });
        if (description !== undefined) query.set("error_description", description);
        const response = await ctx.rawRequest({
          path: authProfilePath(profile) + "/error?" + query,
          redirect: "manual",
        });
        expect(response).toEqual({
          status: 302,
          location:
            "/problem?keep=a%2Bb&error=BAD_CODE" +
            (description === undefined ? "" : "&error_description=detail+%2B+%26+caf%C3%A9") +
            "#error-panel",
          body: null,
        });
        observations.push({ profile, response });
      }
    }
    return { observations };
  },
  ["GET /error"],
);
