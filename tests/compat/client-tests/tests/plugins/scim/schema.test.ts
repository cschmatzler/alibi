import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "SCIM schema lookup decodes identifiers once and preserves exact SCIM errors",
  async (ctx) => {
    const actor = ctx.actor();
    const base = `${ctx.baseURL}/__test/profiles/scim/api/auth`;
    const direct = (id: string) =>
      actor.fetch(
        `${ctx.baseURL}/__test/server-api/scim?operation=getSCIMSchema&id=${encodeURIComponent(id)}`,
        { method: "POST" },
      );
    const schemas: any[] = [];
    for (const [id, name, count] of [
      ["urn:ietf:params:scim:schemas:core:2.0:User", "User", 14],
      ["urn:ietf:params:scim:schemas:extension:enterprise:2.0:User", "EnterpriseUser", 6],
      ["urn:ietf:params:scim:schemas:core:2.0:Group", "Group", 2],
    ] as const) {
      for (const parameter of [id, encodeURIComponent(id)]) {
        const response = await actor.fetch(`${base}/scim/v2/Schemas/${parameter}`);
        expect(response.status).toBe(200);
        expect(response.headers.get("content-type")).toBe("application/scim+json");
        const schema = (await response.json()) as any;
        expect(schema.id).toBe(id);
        expect(schema.name).toBe(name);
        expect(schema.schemas).toEqual(["urn:ietf:params:scim:schemas:core:2.0:Schema"]);
        expect(schema.attributes).toHaveLength(count);
        expect(schema.meta).toEqual({
          resourceType: "Schema",
          location: `${base}/scim/v2/Schemas/${id}`,
        });
        const server = await direct(parameter);
        expect(server.status).toBe(200);
        expect(await server.json()).toEqual(schema);
        schemas.push({
          ...schema,
          meta: { ...schema.meta, location: new URL(schema.meta.location).pathname },
        });
      }
    }
    const error = {
      schemas: ["urn:ietf:params:scim:api:messages:2.0:Error"],
      status: "404",
      detail: "Schema not found",
    };
    for (const id of [
      "Unknown",
      "urn:ietf:params:scim:schemas:core:2.0:user",
      "%ZZ",
      "%2575rn:ietf:params:scim:schemas:core:2.0:User",
    ]) {
      const response = await actor.fetch(`${base}/scim/v2/Schemas/${id}`);
      expect(response.status).toBe(404);
      expect(await response.json()).toEqual(error);
      expect(response.headers.get("content-type")).toBe("application/scim+json");
      const server = await direct(id);
      expect(server.status).toBe(404);
      expect(await server.json()).toEqual(error);
    }
    return { schemas, error };
  },
);
