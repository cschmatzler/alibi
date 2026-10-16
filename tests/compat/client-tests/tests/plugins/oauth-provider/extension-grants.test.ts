import { expect } from "bun:test";

import { Cookie } from "tough-cookie";

import { compatScenario } from "../../../support/scenario";
const grant = "urn:fixture:extension";
compatScenario(
  "Configured extension grants dispatch through bound authentication and real issuance",
  async (ctx) => {
    const actor = ctx.actor();
    const control = (input: object) =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/oauth-provider-clients`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ mode: "extension-grant", ...input }),
      });
    const metadata = await control({ action: "grant-metadata" });
    expect(metadata.status).toBe(200);
    expect(((await metadata.json()) as any).grant_types_supported).toEqual([
      "authorization_code",
      "client_credentials",
      "refresh_token",
      "urn:fixture:orphan",
      grant,
    ]);
    const signup = await control({
      action: "signup",
      body: {
        email: ctx.uniqueEmail("extension-owner"),
        name: "Extension owner",
        password: "password123",
      },
    });
    expect(signup.status).toBe(200);
    const cookie = signup.headers
      .getSetCookie()
      .filter((raw) => Boolean(Cookie.parse(raw)?.value))
      .map((raw) => raw.split(";")[0])
      .join("; ");
    const created = await control({
      action: "admin-create",
      headers: { cookie },
      body: {
        client_name: "Extension client",
        redirect_uris: ["https://app.fixture.test/callback"],
        scope: "email",
        grant_types: [grant],
        token_endpoint_auth_method: "client_secret_post",
      },
    });
    expect(created.status).toBe(201);
    const client = (await created.json()) as any;
    const credentials = { client_id: client.client_id, client_secret: client.client_secret };
    const token = (body: object) =>
      control({
        action: "token",
        body: {
          grant_type: grant,
          ...credentials,
          scope: "email",
          marker: "passthrough",
          grantType: "urn:forged",
          ...body,
        },
      });
    const early = await token({
      marker: "deny",
      client_id: "not-a-client",
      client_secret: "wrong",
    });
    expect(early.status).toBe(400);
    expect(await early.json()).toEqual({
      error: "invalid_grant",
      error_description: "extension rejected request",
    });
    const success = await token({ grant_type: " " + grant + " " });
    expect(success.status).toBe(200);
    expect(success.headers.get("cache-control")).toBe("no-store");
    expect(success.headers.get("pragma")).toBe("no-cache");
    const issued = (await success.json()) as any;
    expect(issued.access_token).toBeTruthy();
    expect(issued.token_type).toBe("Bearer");
    expect(issued.scope).toBe("email");
    expect(issued.custom).toBe("passthrough");
    expect(issued.boundGrant).toBe(grant);
    expect(issued.observedGrant).toBe(grant);
    const introspection = await control({
      action: "introspect",
      body: { token: issued.access_token, ...credentials },
    });
    expect(introspection.status).toBe(200);
    const authority = (await introspection.json()) as any;
    expect(authority.active).toBe(true);
    expect(authority.client_id).toBe(client.client_id);
    expect(authority.scope).toBe("email");
    const invalid = await token({ client_secret: "wrong" });
    expect(invalid.status).toBe(400);
    expect(((await invalid.json()) as any).error).toBe("invalid_client");
    const overscope = await token({ scope: "profile" });
    expect(overscope.status).toBe(400);
    expect(await overscope.json()).toEqual({
      error: "invalid_scope",
      error_description: "client does not allow scope profile",
    });
    for (const unsupported of ["urn:fixture:orphan", "urn:fixture:undeclared"]) {
      const denied = await token({ grant_type: unsupported, client_secret: "wrong" });
      expect(denied.status).toBe(400);
      expect(await denied.json()).toEqual({
        error: "unsupported_grant_type",
        error_description: "unsupported grant_type " + unsupported,
      });
    }
    const update = await control({
      action: "admin-update",
      headers: { cookie },
      body: { client_id: client.client_id, update: { grant_types: ["authorization_code"] } },
    });
    expect(update.status).toBe(200);
    const denied = await token({});
    expect(denied.status).toBe(400);
    expect(await denied.json()).toEqual({
      error: "unauthorized_client",
      error_description: "client is not authorized to use grant type " + grant,
    });
    return ctx.snapshot({
      delivered: true,
      boundGrant: grant,
      scope: authority.scope,
      orphan: "unsupported_grant_type",
    });
  },
);
