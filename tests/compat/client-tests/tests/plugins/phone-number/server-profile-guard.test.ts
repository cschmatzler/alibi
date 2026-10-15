import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";

compatScenario(
  "phone server profile guard precedes validation and session admission",
  async (ctx) => {
    const results = [];
    for (const phoneNumber of ["", 0, false, [], {}, "+15555555555"]) {
      const response = await ctx.rawRequest({
        path: "/__test/server-api/phone-update-user",
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ headers: {}, body: { phoneNumber, name: 42 } }),
      });
      expect(response.status).toBe(400);
      expect(response.body).toEqual({
        code: "PHONE_NUMBER_CANNOT_BE_UPDATED",
        message: "Phone number cannot be updated",
      });
      results.push(response);
    }
    for (const body of [undefined, null, 1, "x", false, [], {}, { phoneNumber: null }]) {
      const response = await ctx.rawRequest({
        path: "/__test/server-api/phone-update-user",
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ headers: {}, ...(body === undefined ? {} : { body }) }),
      });
      if (body === undefined || body === null || typeof body !== "object") {
        expect(response.status).toBe(500);
        expect(response.body).toEqual({
          message:
            "An error occurred during hook matcher execution. Check the logs for more details.",
        });
      } else if (Array.isArray(body)) {
        expect(response.status).toBe(400);
        expect(response.body).toMatchObject({ code: "VALIDATION_ERROR" });
      } else {
        expect(response.status).toBe(401);
        expect(response.body).toMatchObject({ code: "UNAUTHORIZED" });
      }
      results.push(response);
    }
    return ctx.snapshot({ results });
  },
  ["POST /update-user"],
);
