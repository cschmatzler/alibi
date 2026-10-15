import { expect } from "bun:test";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "SCIM Group SDK validation preserves NaN and numeric diagnostic types",
  async (ctx) => {
    const results = [];
    for (const kind of ["NaN", "Infinity", "-Infinity", "number"]) {
      for (const [extra, path, field] of [
        [{ externalId: null }, ["externalId"], "externalId"],
        [{ displayName: null }, ["displayName"], "displayName"],
        [{ members: [{ value: null }] }, ["members", "0", "value"], "members.0.value"],
        [
          { members: [{ value: "member", type: null }] },
          ["members", "0", "type"],
          "members.0.type",
        ],
        [{ ignored: null }, ["ignored"], undefined],
      ] as const) {
        const body: any = {
          schemas: ["urn:ietf:params:scim:schemas:core:2.0:Group"],
          displayName: "Group",
          ...structuredClone(extra),
        };
        if (kind === "number") {
          let target = body;
          for (const key of path.slice(0, -1)) target = target[key];
          target[path.at(-1)!] = 42;
        }
        for (const operation of ["createSCIMGroup", "replaceSCIMGroup"]) {
          const result = await ctx.rawRequest({
            path: `/__test/server-api/scim?operation=${operation}`,
            method: "POST",
            json: {
              body,
              params: { groupId: "missing" },
              query: {},
              ...(kind === "number" ? {} : { numberPath: path, numberKind: kind }),
            },
          });
          expect(result.status).toBe(field ? 400 : 401);
          if (field) {
            expect(result.body).toMatchObject({
              detail: `[body.${field}] Invalid input: expected string, received ${kind}`,
              scimType: "invalidValue",
            });
          }
          results.push({ kind, field, operation, result });
        }
      }
    }
    return ctx.snapshot({ results });
  },
  ["POST /scim/v2/Groups", "PUT /scim/v2/Groups/{}"],
);
