import { createHash } from "node:crypto";

import { Cookie } from "tough-cookie";
import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "Machine credentials issue real scope-limited access authority without a user or session",
  async (ctx) => {
    const actor = ctx.actor();
    const control = (input: Record<string, unknown>) =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/oauth-provider-clients`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ mode: "machine", ...input }),
      });
    const signup = await control({
      action: "signup",
      body: {
        email: ctx.uniqueEmail("machine-owner"),
        name: "Native owner",
        password: "password123",
      },
    });
    expect(signup.status).toBe(200);
    const cookie = signup.headers
      .getSetCookie()
      .filter((raw) => Boolean(Cookie.parse(raw)?.value))
      .map((raw) => raw.split(";")[0])
      .join("; ");
    const denied = await control({
      action: "admin-create",
      headers: { cookie },
      body: {
        client_name: "Machine client",
        scope: "api:read api:write",
        token_endpoint_auth_method: "client_secret_post",
        grant_types: ["client_credentials"],
        client_credentials_scopes: ["api:read", "api:write"],
      },
    });
    expect(denied.status).toBe(401);
    expect(await denied.text()).toBe("");
    const created = await control({
      action: "admin-create",
      headers: { cookie, "x-machine-operator": "grant" },
      body: {
        client_name: "Machine client",
        scope: "api:read api:write",
        token_endpoint_auth_method: "client_secret_post",
        grant_types: ["client_credentials"],
        client_credentials_scopes: ["api:read", "api:write"],
      },
    });
    expect(created.status).toBe(201);
    const client = (await created.json()) as any;
    const id = client.client_id;
    const secret = client.client_secret;
    expect(typeof secret).toBe("string");
    const failures = [];
    for (const [input, error, error_description] of [
      [{ grant_type: "client_credentials" }, "invalid_request", "Missing required client_id"],
      [
        { grant_type: "client_credentials", client_id: "missing", client_secret: secret },
        "invalid_client",
        "missing client",
      ],
      [
        { grant_type: "client_credentials", client_id: id, client_secret: "wrong" },
        "invalid_client",
        "invalid client_secret",
      ],
      [
        { grant_type: "client_credentials", client_id: id, client_secret: secret, scope: "openid" },
        "invalid_scope",
        "The following scopes are invalid: openid",
      ],
      [
        {
          grant_type: "client_credentials",
          client_id: id,
          client_secret: secret,
          resource: "https://api.fixture.test/missing-machine",
        },
        "invalid_target",
        "requested resource https://api.fixture.test/missing-machine is not configured",
      ],
    ] as const) {
      const r = await control({ action: "token", body: input });
      expect(r.status).toBe(400);
      const body = await r.json();
      expect(body).toEqual({ error, error_description });
      failures.push(body);
    }
    const results = [];
    for (const scope of [undefined, "api:read"]) {
      const issued = await control({
        action: "token",
        body: {
          grant_type: "client_credentials",
          client_id: id,
          client_secret: secret,
          ...(scope ? { scope } : {}),
        },
      });
      expect(issued.status).toBe(200);
      expect(issued.headers.get("cache-control")).toBe("no-store");
      const token = (await issued.json()) as any;
      expect(token.scope).toBe(scope ?? "api:read api:write");
      expect(token.expires_in).toBe(3600);
      expect(token.token_type).toBe("Bearer");
      expect(token.refresh_token).toBeUndefined();
      expect(token.id_token).toBeUndefined();
      expect(token.access_token).toMatch(/^[A-Za-z]{32}$/);
      const storedResponse = await control({ action: "token-row", token: token.access_token });
      expect(storedResponse.status).toBe(200);
      const row = (await storedResponse.json()) as any;
      expect(row.token).toBe(createHash("sha256").update(token.access_token).digest("base64url"));
      expect(row.clientId).toBe(id);
      expect(row.userId).toBeNull();
      expect(row.sessionId).toBeNull();
      expect(row.authorizationCodeId).toBeNull();
      expect(row.scopes).toEqual((scope ?? "api:read api:write").split(" "));
      expect(Date.parse(row.expiresAt) - Date.parse(row.createdAt)).toBe(3600_000);
      const observed = await control({
        action: "introspect",
        body: {
          client_id: id,
          client_secret: secret,
          token: token.access_token,
          token_type_hint: "access_token",
        },
      });
      expect(observed.status).toBe(200);
      const claims = (await observed.json()) as any;
      expect(claims.active).toBe(true);
      expect(claims.scope).toBe(token.scope);
      expect(claims.sub).toBeUndefined();
      expect(claims.sid).toBeUndefined();
      results.push({ scope: token.scope, active: claims.active });
    }
    return ctx.snapshot({ failures, results });
  },
);
