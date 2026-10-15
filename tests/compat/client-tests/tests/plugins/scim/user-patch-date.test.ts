import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "SCIM User PATCH clones SDK Date values by own properties without string coercion",
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
        userName: ctx.uniqueEmail("patch-date-owner"),
      },
      token: "group-reader",
    });
    expect(created.status).toBe(201);
    const userId = (created.body as any).id;
    const actor = ctx.actor();
    async function state() {
      const response = await actor.fetch(
        `${ctx.baseURL}/__test/server-api/scim?operation=user-replace-state`,
        { method: "POST", headers: { "content-type": "application/json" }, body: "{}" },
      );
      expect(response.status).toBe(200);
      const body = (await response.json()) as any;
      return {
        sessions: body.sessions,
        subject: body.subjects.find((subject: any) => subject.profileSourceId === userId),
      };
    }
    const before = await state();
    expect(before.subject).toBeDefined();
    const date = "2026-01-02T03:04:05.000Z";
    const results = [];
    for (const [path, shape] of [
      ["userName", "direct"],
      ["userName", "array"],
      [undefined, "object"],
      [undefined, "direct"],
    ] as const) {
      const result = await invoke("patchSCIMUser", {
        params: { userId },
        token: "group-reader",
        datePath: [
          "Operations",
          "0",
          "value",
          ...(shape === "array" ? ["0"] : shape === "object" ? ["userName"] : []),
        ],
        body: {
          schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
          Operations: [
            {
              op: "replace",
              ...(path ? { path } : {}),
              value: shape === "array" ? [date] : shape === "object" ? { userName: date } : date,
            },
          ],
        },
      });
      expect(result.status).toBe(path || shape === "object" ? 400 : 200);
      if (path || shape === "object") {
        expect(result.body).toMatchObject({
          detail: "userName must be a non-empty string",
          scimType: "invalidValue",
        });
      } else expect(result.body).toEqual(created.body);
      const after = await state();
      if (path || shape === "object") {
        expect(after).toEqual(before);
      } else {
        expect(after.sessions).toBe(before.sessions);
        expect(after.subject.profileSourceId).toBe(before.subject.profileSourceId);
        expect(after.subject.revision).toBe(before.subject.revision + 1);
      }
      results.push({ path, shape, result });
    }
    const updated = await invoke("patchSCIMUser", {
      params: { userId },
      token: "group-reader",
      body: {
        schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        Operations: [{ op: "replace", path: "userName", value: date }],
      },
    });
    expect(updated.status).toBe(200);
    expect(updated.body).toMatchObject({ id: userId, userName: date });
    return ctx.snapshot({ created, results, updated });
  },
  ["POST /scim/v2/Users", "PATCH /scim/v2/Users/{}"],
);
