import { expect } from "bun:test";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "SCIM HTTP admission preserves protocol errors and ignores DELETE bodies",
  async (ctx) => {
    const actor = ctx.actor();
    const base = `${ctx.baseURL}/__test/profiles/scim/api/auth/scim/v2`;
    const cases = [
      {
        method: "POST",
        path: "Users",
        media: "text/plain",
        body: "bad",
        status: 415,
        expected: {
          schemas: ["urn:ietf:params:scim:api:messages:2.0:Error"],
          status: "415",
          detail: "SCIM requests must use application/scim+json or application/json",
        },
      },
      {
        method: "PUT",
        path: "Users/missing",
        media: "application/json",
        body: "{",
        status: 400,
        expected: {
          schemas: ["urn:ietf:params:scim:api:messages:2.0:Error"],
          status: "400",
          detail: "SCIM request body must contain valid JSON",
          scimType: "invalidSyntax",
        },
      },
      {
        method: "PATCH",
        path: "Groups/missing",
        media: "application/scim+json",
        body: "",
        status: 400,
        expected: {
          schemas: ["urn:ietf:params:scim:api:messages:2.0:Error"],
          status: "400",
          detail: "SCIM request body must contain valid JSON",
          scimType: "invalidSyntax",
        },
      },
      {
        method: "POST",
        path: "Groups",
        body: "{}",
        status: 415,
        expected: {
          schemas: ["urn:ietf:params:scim:api:messages:2.0:Error"],
          status: "415",
          detail: "SCIM requests must use application/scim+json or application/json",
        },
      },
      {
        method: "POST",
        path: "Groups",
        media: "application/json; charset=utf-8",
        body: "{",
        status: 400,
        expected: {
          schemas: ["urn:ietf:params:scim:api:messages:2.0:Error"],
          status: "400",
          detail: "SCIM request body must contain valid JSON",
          scimType: "invalidSyntax",
        },
      },
      {
        method: "DELETE",
        path: "Users/missing",
        media: "application/json",
        body: "{",
        status: 401,
        expected: {
          schemas: ["urn:ietf:params:scim:api:messages:2.0:Error"],
          status: "401",
          detail: "SCIM bearer token is required",
        },
      },
      {
        method: "DELETE",
        path: "Groups/missing",
        media: "text/plain",
        body: "{",
        token: "group-reader",
        status: 404,
        expected: {
          schemas: ["urn:ietf:params:scim:api:messages:2.0:Error"],
          status: "404",
          detail: "SCIM Group not found",
        },
      },
      {
        method: "POST",
        path: "unknown",
        media: "text/plain",
        body: "bad",
        status: 415,
        expected: {
          schemas: ["urn:ietf:params:scim:api:messages:2.0:Error"],
          status: "415",
          detail: "SCIM requests must use application/scim+json or application/json",
        },
      },
    ];
    for (const input of cases) {
      const response = await actor.fetch(`${base}/${input.path}`, {
        method: input.method,
        headers: {
          ...(input.media ? { "content-type": input.media } : {}),
          ...(input.token ? { authorization: `Bearer ${input.token}` } : {}),
        },
        body: new TextEncoder().encode(input.body),
      });
      expect(response.status).toBe(input.status);
      expect(await response.json()).toEqual(input.expected);
      expect(response.headers.get("content-type")).toBe("application/scim+json");
    }
    for (const kind of ["Users", "Groups"]) {
      const body =
        kind === "Users"
          ? {
              schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
              userName: ctx.uniqueEmail("delete-body"),
            }
          : {
              schemas: ["urn:ietf:params:scim:schemas:core:2.0:Group"],
              displayName: "Delete body",
            };
      const created = await actor.fetch(
        `${ctx.baseURL}/__test/server-api/scim?operation=${kind === "Users" ? "createSCIMUser" : "createSCIMGroup"}`,
        {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ token: "group-reader", body, query: {} }),
        },
      );
      expect(created.status).toBe(201);
      const resource = (await created.json()) as any;
      const removed = await actor.fetch(`${base}/${kind}/${resource.id}`, {
        method: "DELETE",
        headers: { "content-type": "text/plain", authorization: "Bearer group-reader" },
        body: "{",
      });
      expect(removed.status).toBe(204);
      expect(await removed.text()).toBe("");
      const missing = await actor.fetch(`${base}/${kind}/${resource.id}`, {
        headers: { authorization: "Bearer group-reader" },
      });
      expect(missing.status).toBe(404);
    }
    return { admission: true, ignoredDeleteBody: true, durableRemoval: true };
  },
);
