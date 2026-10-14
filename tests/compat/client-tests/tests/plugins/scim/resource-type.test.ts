import { expect } from "bun:test";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "SCIM resource-type lookup preserves case-sensitive IDs and SCIM errors",
  async (ctx) => {
    const actor = ctx.actor();
    const base = `${ctx.baseURL}/__test/profiles/scim/api/auth`;
    const group = {
      schemas: ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
      id: "Group",
      name: "Group",
      endpoint: "/Groups",
      description: "Group",
      schema: "urn:ietf:params:scim:schemas:core:2.0:Group",
      meta: { resourceType: "ResourceType", location: `${base}/scim/v2/ResourceTypes/Group` },
    };
    const direct = (id: string) =>
      actor.fetch(
        `${ctx.baseURL}/__test/server-api/scim?operation=getSCIMResourceType&id=${encodeURIComponent(id)}`,
        { method: "POST" },
      );
    const http = await actor.fetch(`${base}/scim/v2/ResourceTypes/Group`);
    expect(http.status).toBe(200);
    expect(http.headers.get("content-type")).toBe("application/scim+json");
    expect(await http.json()).toEqual(group);
    const server = await direct("Group");
    expect(server.status).toBe(200);
    expect(await server.json()).toEqual(group);
    const encoded = await actor.fetch(`${base}/scim/v2/ResourceTypes/%55ser`);
    expect(encoded.status).toBe(404);
    expect(await encoded.json()).toEqual({
      schemas: ["urn:ietf:params:scim:api:messages:2.0:Error"],
      status: "404",
      detail: "Resource type not found",
    });
    const error = {
      schemas: ["urn:ietf:params:scim:api:messages:2.0:Error"],
      status: "404",
      detail: "Resource type not found",
    };
    for (const id of ["group", "Unknown", "%47roup"]) {
      const server = await direct(id);
      expect(server.status).toBe(404);
      expect(await server.json()).toEqual(error);
      if (id !== "%47roup") {
        const http = await actor.fetch(`${base}/scim/v2/ResourceTypes/${id}`);
        expect(http.status).toBe(404);
        expect(http.headers.get("content-type")).toBe("application/scim+json");
        expect(await http.json()).toEqual(error);
      }
    }
    return {
      group: { ...group, meta: { ...group.meta, location: new URL(group.meta.location).pathname } },
      error,
    };
  },
);
