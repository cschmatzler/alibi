import { expect } from "bun:test";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "SCIM User SDK Dates retain schema types before bearer admission",
  async (ctx) => {
    const core = "urn:ietf:params:scim:schemas:core:2.0:User";
    const enterprise = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";
    const date = "2026-01-02T03:04:05.000Z";
    const cases: [Record<string, unknown>, string[], string | null][] = [
      [{ title: date }, ["title"], "[body.title] Invalid input: expected string, received Date"],
      [
        { title: [date] },
        ["title", "0"],
        "[body.title] Invalid input: expected string, received Date",
      ],
      [
        { name: { formatted: date } },
        ["name", "formatted"],
        "[body.name.formatted] Invalid input: expected string, received Date",
      ],
      [
        { roles: [{ value: date }] },
        ["roles", "0", "value"],
        "[body.roles.0.value] Invalid input: expected string, received Date",
      ],
      [
        { schemas: date },
        ["schemas"],
        "[body.schemas] Invalid input: expected array, received Date",
      ],
      [
        { [enterprise]: { department: date } },
        [enterprise, "department"],
        `[body.${enterprise}.department] Invalid input: expected string, received Date`,
      ],
      [{ ignored: date }, ["ignored"], null],
    ];
    const results = [];
    for (const [extra, datePath, detail] of cases) {
      for (const operation of ["createSCIMUser", "replaceSCIMUser"]) {
        const result = await ctx.rawRequest({
          path: `/__test/server-api/scim?operation=${operation}`,
          method: "POST",
          json: {
            body: { schemas: [core, enterprise], userName: "owner@example.com", ...extra },
            datePath,
            params: { userId: "missing" },
          },
        });
        expect(result.status).toBe(detail ? 400 : 401);
        if (detail) expect(result.body).toMatchObject({ detail, scimType: "invalidValue" });
        results.push({ operation, datePath, result });
      }
    }
    const jsonString = await ctx.rawRequest({
      path: "/__test/server-api/scim?operation=createSCIMUser",
      method: "POST",
      json: { body: { schemas: [core], userName: "owner@example.com", title: date } },
    });
    expect(jsonString.status).toBe(401);
    return ctx.snapshot({ results, jsonString });
  },
  ["POST /scim/v2/Users", "PUT /scim/v2/Users/{}"],
);
