import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "SCIM User SDK diagnostics preserve non-finite numeric types",
  async (ctx) => {
    const results = [];
    for (const kind of ["Infinity", "-Infinity", "NaN", "number"]) {
      for (const [extra, path, field, expected] of [
        [{ title: null }, ["title"], "title", "string"],
        [{ name: { formatted: null } }, ["name", "formatted"], "name.formatted", "string"],
        [{ roles: [{ value: null }] }, ["roles", "0", "value"], "roles.0.value", "string"],
        [{ schemas: null }, ["schemas"], "schemas", "array"],
        [{ ignored: null }, ["ignored"], "ignored", undefined],
      ] as const) {
        const body: any = {
          schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
          userName: "owner@example.com",
          ...structuredClone(extra),
        };
        if (kind === "number") {
          let target = body;
          for (const key of path.slice(0, -1)) target = target[key];
          target[path.at(-1)!] = 42;
        }
        for (const operation of ["createSCIMUser", "replaceSCIMUser"]) {
          const result = await ctx.rawRequest({
            path: `/__test/server-api/scim?operation=${operation}`,
            method: "POST",
            json: {
              body,
              params: { userId: "missing" },
              ...(kind === "number" ? {} : { numberPath: path, numberKind: kind }),
            },
          });
          expect(result.status).toBe(expected ? 400 : 401);
          if (expected) {
            expect(result.body).toMatchObject({
              detail: `[body.${field}] Invalid input: expected ${expected}, received ${kind}`,
              scimType: "invalidValue",
            });
          }
          results.push({ kind, field, operation, result });
        }
      }
    }
    return ctx.snapshot({ results });
  },
  ["POST /scim/v2/Users", "PUT /scim/v2/Users/{}"],
);
