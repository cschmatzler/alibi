import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "SCIM resource-type discovery includes the optional Enterprise User extension",
  async (ctx) => {
    const actor = ctx.actor();
    const base = `${ctx.baseURL}/__test/profiles/scim/api/auth`;
    const expected = {
      schemas: ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
      totalResults: 2,
      startIndex: 1,
      itemsPerPage: 2,
      Resources: [
        {
          schemas: ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
          id: "User",
          name: "User",
          endpoint: "/Users",
          description: "User Account",
          schema: "urn:ietf:params:scim:schemas:core:2.0:User",
          schemaExtensions: [
            {
              schema: "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User",
              required: false,
            },
          ],
          meta: { resourceType: "ResourceType", location: `${base}/scim/v2/ResourceTypes/User` },
        },
        {
          schemas: ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
          id: "Group",
          name: "Group",
          endpoint: "/Groups",
          description: "Group",
          schema: "urn:ietf:params:scim:schemas:core:2.0:Group",
          meta: { resourceType: "ResourceType", location: `${base}/scim/v2/ResourceTypes/Group` },
        },
      ],
    };
    const response = await actor.fetch(`${base}/scim/v2/ResourceTypes`);
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toBe("application/scim+json");
    expect(await response.json()).toEqual(expected);
    const server = await actor.fetch(
      `${ctx.baseURL}/__test/server-api/scim?operation=getSCIMResourceTypes`,
      { method: "POST" },
    );
    expect(server.status).toBe(200);
    expect(await server.json()).toEqual(expected);
    return {
      ...expected,
      Resources: expected.Resources.map((resource) => ({
        ...resource,
        meta: { ...resource.meta, location: new URL(resource.meta.location).pathname },
      })),
    };
  },
);
