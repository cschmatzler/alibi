import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "SCIM Group PATCH treats pathless SDK Dates as empty records",
  async (ctx) => {
    const invoke = (operation: string, input: unknown) =>
      ctx.rawRequest({
        path: `/__test/server-api/scim?operation=${operation}`,
        method: "POST",
        json: input,
      });
    const created = await invoke("createSCIMGroup", {
      body: {
        schemas: ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        displayName: ctx.uniqueEmail("date-group"),
      },
      query: {},
      token: "group-reader",
    });
    expect(created.status).toBe(201);
    const groupId = (created.body as any).id;
    const results = [];
    for (const [op, path, status] of [
      ["replace", undefined, 200],
      ["add", undefined, 200],
      ["remove", undefined, 400],
      ["replace", "displayName", 400],
    ] as const) {
      const result = await invoke("patchSCIMGroup", {
        params: { groupId },
        token: "group-reader",
        datePath: ["Operations", "0", "value"],
        body: {
          schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
          Operations: [{ op, ...(path ? { path } : {}), value: "2026-01-02T03:04:05.000Z" }],
        },
      });
      expect(result.status).toBe(status);
      if (status === 200) {
        expect(result.body).toEqual(created.body);
      } else {
        expect(result.body).toMatchObject({
          detail:
            op === "remove"
              ? "A pathless remove operation has no target"
              : "displayName must be a non-empty string",
          scimType: op === "remove" ? "noTarget" : "invalidValue",
        });
      }
      results.push(result);
    }
    return ctx.snapshot({ created, results });
  },
  ["PATCH /scim/v2/Groups/{}"],
);
