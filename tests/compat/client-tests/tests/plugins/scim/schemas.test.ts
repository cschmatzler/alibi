import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "SCIM schema listing exposes standard attributes, references and mutability",
  async (ctx) => {
    const actor = ctx.actor();
    const base = `${ctx.baseURL}/__test/profiles/scim/api/auth`;
    const response = await actor.fetch(`${base}/scim/v2/Schemas`);
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toBe("application/scim+json");
    const document = (await response.json()) as any;
    expect(document.schemas).toEqual(["urn:ietf:params:scim:api:messages:2.0:ListResponse"]);
    expect(document.totalResults).toBe(3);
    expect(document.itemsPerPage).toBe(3);
    expect(document.startIndex).toBe(1);
    const resources = document.Resources;
    expect(resources).toHaveLength(3);
    const contracts = [
      [
        "urn:ietf:params:scim:schemas:core:2.0:User",
        [
          "userName",
          "displayName",
          "active",
          "name",
          "emails",
          "title",
          "userType",
          "preferredLanguage",
          "locale",
          "timezone",
          "phoneNumbers",
          "addresses",
          "roles",
          "entitlements",
        ],
      ],
      [
        "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User",
        ["employeeNumber", "costCenter", "organization", "division", "department", "manager"],
      ],
      ["urn:ietf:params:scim:schemas:core:2.0:Group", ["displayName", "members"]],
    ] as const;
    for (const [index, [id, names]] of contracts.entries()) {
      const schema = resources[index];
      expect(schema.id).toBe(id);
      expect(schema.schemas).toEqual(["urn:ietf:params:scim:schemas:core:2.0:Schema"]);
      expect(schema.meta).toEqual({
        resourceType: "Schema",
        location: `${base}/scim/v2/Schemas/${id}`,
      });
      expect(schema.attributes.map((attribute: any) => attribute.name)).toEqual(names);
    }
    expect(resources[0].attributes[0].required).toBe(true);
    expect(resources[0].attributes[0].uniqueness).toBe("server");
    const manager = resources[1].attributes[5];
    expect(manager.type).toBe("complex");
    expect(manager.subAttributes[1].referenceTypes).toEqual(["User"]);
    expect(manager.subAttributes[2].mutability).toBe("readOnly");
    const members = resources[2].attributes[1];
    expect(members.multiValued).toBe(true);
    expect(members.subAttributes[0].required).toBe(true);
    expect(members.subAttributes[0].mutability).toBe("immutable");
    expect(members.subAttributes[3].canonicalValues).toEqual(["User"]);
    const server = await actor.fetch(
      `${ctx.baseURL}/__test/server-api/scim?operation=getSCIMSchemas`,
      { method: "POST" },
    );
    expect(server.status).toBe(200);
    expect(await server.json()).toEqual(document);
    return {
      ...document,
      Resources: resources.map((resource: any) => ({
        ...resource,
        meta: { ...resource.meta, location: new URL(resource.meta.location).pathname },
      })),
    };
  },
);
