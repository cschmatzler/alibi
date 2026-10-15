import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "SCIM service-provider discovery is public over HTTP and the server API",
  async (ctx) => {
    const actor = ctx.actor();
    const path = "/__test/profiles/scim/api/auth/scim/v2/ServiceProviderConfig";
    const expected = {
      schemas: ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
      patch: { supported: true },
      bulk: { supported: false, maxOperations: 0, maxPayloadSize: 0 },
      filter: { supported: true, maxResults: 100 },
      changePassword: { supported: false },
      sort: { supported: false },
      etag: { supported: false },
      authenticationSchemes: [
        {
          name: "OAuth Bearer Token",
          description: "Authentication using a bearer token in the Authorization header.",
          specUri: "https://www.rfc-editor.org/info/rfc6750",
          type: "oauthbearertoken",
          primary: true,
        },
      ],
      meta: { resourceType: "ServiceProviderConfig", location: `${ctx.baseURL}${path}` },
    };
    const http = await actor.fetch(`${ctx.baseURL}${path}`);
    expect(http.status).toBe(200);
    expect(http.headers.get("content-type")).toBe("application/scim+json");
    expect(await http.json()).toEqual(expected);
    const server = await actor.fetch(`${ctx.baseURL}/__test/server-api/scim`, { method: "POST" });
    expect(server.status).toBe(200);
    expect(await server.json()).toEqual(expected);
    return { ...expected, meta: { ...expected.meta, location: path } };
  },
);
