import { expect } from "bun:test";

import { compatScenario } from "../../../support/scenario";

compatScenario(
  "SCIM User PATCH reports the first invalid canonical profile attribute",
  async (ctx) => {
    async function invoke(operation: string, input: unknown) {
      return ctx.rawRequest({
        path: `/__test/server-api/scim?operation=${operation}`,
        method: "POST",
        json: input,
      });
    }
    const created = await invoke("createSCIMUser", {
      body: {
        schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
        userName: ctx.uniqueEmail("patch-invalid-owner"),
      },
      token: "group-reader",
    });
    expect(created.status).toBe(201);
    const userId = (created.body as any).id;
    const results = [];
    for (const [operations, detail] of [
      [[{ path: "title", value: {} }], "title: Invalid input: expected string, received object"],
      [
        [{ path: "roles", value: [{ value: {} }] }],
        "roles.0.value: Invalid input: expected string, received object",
      ],
      [
        [
          { path: "roles", value: [{ value: {} }] },
          { path: "title", value: 42 },
        ],
        "title: Invalid input: expected string, received number",
      ],
    ] as const) {
      const result = await invoke("patchSCIMUser", {
        params: { userId },
        token: "group-reader",
        body: {
          schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
          Operations: operations,
        },
      });
      expect(result.status).toBe(400);
      expect(result.body).toMatchObject({ detail, scimType: "invalidValue" });
      results.push(result);
    }
    const current = await invoke("getSCIMUser", {
      params: { userId },
      query: {},
      token: "group-reader",
    });
    expect(current.status).toBe(200);
    expect(current.body).toEqual(created.body);
    return ctx.snapshot({ created, results, current });
  },
  ["PATCH /scim/v2/Users/{}"],
);
