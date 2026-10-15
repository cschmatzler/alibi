import { expect } from "bun:test";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "SCIM Entra Group compatibility is HTTP-only and preserves canonical Groups",
  async (ctx) => {
    const actor = ctx.actor();
    const core = "urn:ietf:params:scim:schemas:core:2.0:Group";
    const legacy = "http://schemas.microsoft.com/2006/11/ResourceManagement/ADSCIM/2.0/Group";
    const control = (operation: string, input: unknown) =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/scim?operation=${operation}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(input),
      });
    const http = (method: string, path: string, body: unknown) =>
      actor.fetch(`${ctx.baseURL}/__test/profiles/scim/api/auth/scim/v2/${path}`, {
        method,
        headers: { "content-type": "application/scim+json", authorization: "Bearer group-reader" },
        body: JSON.stringify(body),
      });
    for (const enabled of [true, false]) {
      expect((await control("configure-entra-group-compatibility", { enabled })).status).toBe(200);
      const input = { schemas: [core, legacy], displayName: `Legacy-${enabled}` };
      const response = await http("POST", "Groups", input);
      expect(response.status).toBe(enabled ? 201 : 400);
      if (enabled) {
        const group = (await response.json()) as any;
        expect(group.schemas).toEqual([core]);
        expect(group[legacy]).toBeUndefined();
      }
      const sdk = await control("createSCIMGroup", {
        token: "group-reader",
        query: {},
        body: input,
      });
      expect(sdk.status).toBe(400);
      expect(((await sdk.json()) as any).detail).toBe(
        `[body.schemas.1] Invalid input: expected "${core}"; [body.schemas] schemas must contain only the core SCIM Group schema`,
      );
      if (enabled) {
        for (const [schemas, detail] of [
          [
            [core, legacy, legacy],
            "The Microsoft Entra Group compatibility schema must not be duplicated",
          ],
          [[legacy], "[body.schemas] schemas must contain only the core SCIM Group schema"],
        ] as const) {
          const rejected = await http("POST", "Groups", { schemas, displayName: "Rejected" });
          expect(rejected.status).toBe(400);
          expect(((await rejected.json()) as any).detail).toBe(detail);
        }
      }
      for (const [method, path] of [
        ["POST", "Groups"],
        ["PUT", "Groups/missing"],
        ["PATCH", "Groups/missing"],
      ]) {
        const input =
          method === "PATCH"
            ? {
                schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                Operations: [],
                [legacy]: {},
              }
            : { schemas: [core], displayName: "Attributes", [legacy]: {} };
        const rejected = await http(method!, path!, input);
        expect(rejected.status).toBe(400);
        expect(((await rejected.json()) as any).detail).toBe(
          "The Microsoft Entra Group compatibility schema cannot contain attributes",
        );
      }
      const accepted = await control("createSCIMGroup", {
        token: "group-reader",
        query: {},
        body: { schemas: [core], displayName: `SDK attributes-${enabled}`, [legacy]: {} },
      });
      expect(accepted.status).toBe(201);
      const group = (await accepted.json()) as any;
      expect(group.schemas).toEqual([core]);
      expect(group[legacy]).toBeUndefined();
      const schemaResponse = await actor.fetch(
        `${ctx.baseURL}/__test/profiles/scim/api/auth/scim/v2/Schemas`,
      );
      expect(schemaResponse.status).toBe(200);
      expect(await schemaResponse.text()).not.toContain(legacy);
    }
    const state = await actor.fetch(`${ctx.baseURL}/__test/profiles/scim/api/auth/scim/v2/Groups`, {
      headers: { authorization: "Bearer group-reader" },
    });
    expect(state.status).toBe(200);
    expect(await state.json()).toMatchObject({
      totalResults: 3,
      Resources: expect.arrayContaining([expect.objectContaining({ schemas: [core] })]),
    });
    return { enabled: true, httpOnly: true, canonical: true };
  },
);
