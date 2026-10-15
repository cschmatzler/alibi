import { expect } from "bun:test";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "SCIM discovery SDK preserves logical marker headers and JSON responses across all operations",
  async (ctx) => {
    const core = "urn:ietf:params:scim:schemas:core:2.0:User";
    const cases: [string, Record<string, string> | undefined][] = [
      ["getSCIMServiceProviderConfig", undefined],
      ["getSCIMResourceTypes", undefined],
      ["getSCIMSchemas", undefined],
      ["getSCIMResourceType", { resourceTypeId: "User" }],
      ["getSCIMSchema", { schemaId: core }],
    ];
    const results = [];
    for (const [api, params] of cases) {
      const headers = await ctx.rawRequest({
        path: "/__test/server-api/scim?operation=discovery-sdk",
        method: "POST",
        json: { api, params, mode: "headers" },
      });
      expect(headers.status).toBe(200);
      expect((headers.body as any).headers).toEqual({ "x-better-auth-scim-response": "1" });
      const response = await ctx
        .actor("sdk-response")
        .fetch(`${ctx.baseURL}/__test/server-api/scim?operation=discovery-sdk`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ api, params, mode: "response" }),
        });
      expect(response.status).toBe(200);
      expect(response.headers.get("content-type")).toBe("application/json");
      expect(response.headers.get("x-better-auth-scim-response")).toBe("1");
      const body = await response.json();
      expect(body).toEqual((headers.body as any).response);
      const resource =
        api === "getSCIMServiceProviderConfig"
          ? "ServiceProviderConfig"
          : api === "getSCIMResourceTypes"
            ? "ResourceTypes"
            : api === "getSCIMSchemas"
              ? "Schemas"
              : api === "getSCIMResourceType"
                ? `ResourceTypes/${params!.resourceTypeId}`
                : `Schemas/${encodeURIComponent(params!.schemaId!)}`;
      const http = await ctx
        .actor("http-discovery")
        .fetch(`${ctx.baseURL}/__test/profiles/scim/api/auth/scim/v2/${resource}`);
      expect(http.status).toBe(200);
      expect(http.headers.get("content-type")).toBe("application/scim+json");
      expect(http.headers.has("x-better-auth-scim-response")).toBe(false);
      expect(await http.json()).toEqual(body);
      results.push({ api, headers, body });
    }
    for (const [api, params] of [
      ["getSCIMSchema", { schemaId: "unknown" }],
      ["getSCIMResourceType", { resourceTypeId: "unknown" }],
    ] as const) {
      const response = await ctx
        .actor("sdk-errors")
        .fetch(`${ctx.baseURL}/__test/server-api/scim?operation=discovery-sdk`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ api, params, mode: "response" }),
        });
      expect(response.status).toBe(404);
      expect(response.headers.get("content-type")).toBe("application/json");
      expect(response.headers.get("x-better-auth-scim-response")).toBe("1");
      const body = await response.json();
      expect(body).toMatchObject({
        schemas: ["urn:ietf:params:scim:api:messages:2.0:Error"],
        status: "404",
      });
      results.push({ api, body });
    }
    return ctx.snapshot({ results });
  },
  [
    "GET /scim/v2/ServiceProviderConfig",
    "GET /scim/v2/ResourceTypes",
    "GET /scim/v2/Schemas",
    "GET /scim/v2/ResourceTypes/{}",
    "GET /scim/v2/Schemas/{}",
  ],
);
