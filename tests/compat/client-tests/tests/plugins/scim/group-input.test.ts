import { expect } from "bun:test";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "SCIM Group input preserves schema order and member type diagnostics before authentication",
  async (ctx) => {
    const schema = "urn:ietf:params:scim:schemas:core:2.0:Group";
    const cases: [unknown, string][] = [
      [
        { schemas: [schema], externalId: false, displayName: 0 },
        "[body.externalId] Invalid input: expected string, received boolean; [body.displayName] Invalid input: expected string, received number",
      ],
      [
        { schemas: [schema], externalId: "", displayName: " " },
        "[body.externalId] Too small: expected string to have >=1 characters; [body.displayName] Too small: expected string to have >=1 characters",
      ],
    ];
    for (const [value, kind] of [
      [42, "number"],
      [null, "null"],
      [false, "boolean"],
      [[], "array"],
      [{}, "object"],
    ] as const) {
      cases.push([
        { schemas: [schema], displayName: "Group", members: [{ value: "member", type: value }] },
        `[body.members.0.type] Invalid input: expected string, received ${kind}`,
      ]);
    }
    const results = [];
    for (const [body, detail] of cases) {
      for (const operation of ["createSCIMGroup", "replaceSCIMGroup"]) {
        const result = await ctx.rawRequest({
          path: `/__test/server-api/scim?operation=${operation}`,
          method: "POST",
          json: { body, params: { groupId: "missing" }, query: {} },
        });
        expect(result.status).toBe(400);
        expect(result.body).toMatchObject({ detail, scimType: "invalidValue" });
        results.push({ operation, result });
      }
    }
    for (const operation of ["createSCIMGroup", "replaceSCIMGroup"]) {
      const result = await ctx.rawRequest({
        path: `/__test/server-api/scim?operation=${operation}`,
        method: "POST",
        json: {
          body: {
            schemas: [schema],
            displayName: "Group",
            members: [{ value: "member", type: "USER" }],
          },
          params: { groupId: "missing" },
          query: {},
        },
      });
      expect(result.status).toBe(401);
      results.push({ operation, result });
    }
    return ctx.snapshot({ results });
  },
  ["POST /scim/v2/Groups", "PUT /scim/v2/Groups/{}"],
);
