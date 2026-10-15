import { expect } from "bun:test";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "SCIM User PATCH retains non-finite SDK values until final validation",
  async (ctx) => {
    const invoke = (operation: string, input: unknown) =>
      ctx.rawRequest({
        path: `/__test/server-api/scim?operation=${operation}`,
        method: "POST",
        json: input,
      });
    const created = await invoke("createSCIMUser", {
      body: {
        schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
        userName: ctx.uniqueEmail("patch-number-owner"),
      },
      token: "group-reader",
    });
    expect(created.status).toBe(201);
    const userId = (created.body as any).id;
    const results = [];
    for (const kind of ["NaN", "Infinity", "-Infinity"]) {
      for (const [path, nested, field] of [
        ["title", false, "title"],
        ["roles", true, "roles.0.value"],
        [`roles[type eq "access"].value`, false, "roles.0.value"],
      ] as const) {
        const result = await invoke("patchSCIMUser", {
          params: { userId },
          token: "group-reader",
          numberKind: kind,
          numberPath: ["Operations", "0", "value", ...(nested ? ["0", "value"] : [])],
          body: {
            schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            Operations: [{ path, value: nested ? [{ value: null }] : null }],
          },
        });
        expect(result.status).toBe(400);
        expect(result.body).toMatchObject({
          detail: `${field}: Invalid input: expected string, received ${kind}`,
          scimType: "invalidValue",
        });
        results.push(result);
      }
    }
    for (const [last, status, detail] of [
      [{ path: "unknown", value: null }, 400, "User PATCH path unknown is not supported"],
      [{ path: "title", value: "Safe" }, 200, undefined],
    ] as const) {
      const result = await invoke("patchSCIMUser", {
        params: { userId },
        token: "group-reader",
        numberKind: "NaN",
        numberPath: ["Operations", "0", "value"],
        body: {
          schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
          Operations: [{ path: "title", value: null }, last],
        },
      });
      expect(result.status).toBe(status);
      if (detail) {
        expect(result.body).toMatchObject({ detail, scimType: "invalidPath" });
      } else {
        expect(result.body).toMatchObject({ id: userId, title: "Safe" });
      }
      results.push(result);
    }
    return ctx.snapshot({ created, results });
  },
  ["PATCH /scim/v2/Users/{}"],
);
