import { createLocalJWKSet, jwtVerify } from "jose";
import { Cookie } from "tough-cookie";
import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "Minting and refreshing recheck live resource admission before writing authority",
  async (ctx) => {
    const actor = ctx.actor();
    const control = (input: object) =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/oauth-provider-clients`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(input),
      });
    const signup = await control({
      action: "signup",
      body: { email: ctx.uniqueEmail("resource-mint"), name: "Owner", password: "password123" },
    });
    expect(signup.status).toBe(200);
    const owner = (await signup.json()) as any;
    const cookie = signup.headers
      .getSetCookie()
      .filter((raw) => Boolean(Cookie.parse(raw)?.value))
      .map((raw) => raw.split(";")[0])
      .join("; ");
    const headers = { cookie };
    // Application-defined IDs keep protocol descriptions containing the ID
    // literal across independent reference and Rust servers.
    const created = await control({
      mode: "basic-special",
      action: "admin-create",
      headers,
      body: {
        client_name: "Resource mint",
        redirect_uris: ["https://app.fixture.test/callback"],
        scope: "email profile offline_access",
        grant_types: ["authorization_code"],
        token_endpoint_auth_method: "none",
      },
    });
    expect(created.status).toBe(201);
    const client = (await created.json()) as any;
    const session = (await (await control({ action: "session", headers })).json()) as any;
    const uri = (name: string) => `https://api.fixture.test/mint/${name}`;
    for (const [name, policy] of [
      ["disabled", { disabled: true }],
      ["unlinked", {}],
      ["empty", { allowedScopes: [] }],
      ["alg-a", { signingAlgorithm: "EdDSA" }],
      ["alg-b", { signingAlgorithm: "ES256" }],
      ["key-a", { signingKeyId: "key-a" }],
      ["key-b", { signingKeyId: "key-b" }],
      ["allow-a", { allowedScopes: ["email", "offline_access"] }],
      ["allow-b", { allowedScopes: ["email"] }],
    ] as [string, object][]) {
      const made = await control({
        action: "resource-create",
        headers,
        body: { identifier: uri(name), ...policy },
      });
      expect(made.status).toBe(200);
      if (name !== "unlinked") {
        const linked = await control({
          action: "resource-link",
          headers,
          params: { identifier: uri(name), client_id: client.client_id },
        });
        expect(linked.status).toBe(200);
      }
    }
    const scopes = ["email", "profile", "offline_access"];
    const params = { scopes, sessionId: session.session.id };
    const issue = (resources?: string[]) =>
      control({
        action: "issue-tokens",
        body: {
          clientId: client.client_id,
          userId: owner.user.id,
          grantType: "urn:fixture:server",
          params: { ...params, ...(resources ? { resources } : {}) },
        },
      });
    const initial = await issue();
    expect(initial.status).toBe(200);
    const seed = (await initial.json()) as any;
    const count = async () =>
      await (await control({ action: "authority-counts", sessionId: session.session.id })).json();
    const before = await count();
    const results = [];
    const cases: [string, string[], string, string][] = [
      [
        "unknown",
        [uri("missing")],
        "invalid_target",
        `requested resource ${uri("missing")} is not configured`,
      ],
      [
        "disabled",
        [uri("disabled")],
        "invalid_target",
        `requested resource ${uri("disabled")} is disabled`,
      ],
      [
        "unlinked",
        [uri("unlinked")],
        "invalid_target",
        `client ${client.client_id} is not linked to resource(s) ${uri("unlinked")}`,
      ],
      [
        "empty",
        [uri("empty")],
        "invalid_scope",
        `none of the requested scopes are allowed for resource ${uri("empty")}`,
      ],
      [
        "alg",
        [uri("alg-a"), uri("alg-b")],
        "invalid_request",
        "multi-resource request has conflicting signingAlgorithm pins; a single JWS signature cannot satisfy multiple algorithms",
      ],
      [
        "key",
        [uri("key-a"), uri("key-b")],
        "invalid_request",
        "multi-resource request has conflicting signingKeyId pins; a single JWS signature cannot satisfy multiple key ids",
      ],
    ];
    for (const [name, resources, error, description] of cases) {
      for (const path of ["trusted", "refresh"]) {
        const response =
          path === "trusted"
            ? await issue(resources)
            : await control({
                action: "token",
                body: {
                  grant_type: "refresh_token",
                  client_id: client.client_id,
                  refresh_token: seed.refresh_token,
                  resource: resources,
                },
              });
        expect(response.status).toBe(400);
        const body = await response.json();
        expect(body).toEqual({ error, error_description: description });
        expect(await count()).toEqual(before);
        results.push({ name, path, status: response.status, error });
      }
    }
    // Empty strings in an array are ignored; duplicate resources are resolved once.
    const response = await issue(["", uri("allow-a"), uri("allow-b"), uri("allow-a")]);
    expect(response.status).toBe(200);
    const issued = (await response.json()) as any;
    expect(issued.scope).toBe("email");
    // Reference deliberately decides refresh issuance from the pre-intersection request.
    expect(typeof issued.refresh_token).toBe("string");
    const refresh = (await (
      await control({ action: "token-row", kind: "refresh", token: issued.refresh_token })
    ).json()) as any;
    expect(refresh.scopes).toEqual(["email"]);
    const issuer = `${ctx.baseURL}/api/auth`;
    const keys = createLocalJWKSet((await (await control({ action: "jwks" })).json()) as any);
    const { payload } = await jwtVerify(issued.access_token, keys, { issuer });
    expect(payload.scope).toBe("email");
    expect(payload.aud).toEqual([uri("allow-a"), uri("allow-b")]);
    // A denied redemption must leave the original refresh authority usable.
    const accepted = await control({
      action: "token",
      body: {
        grant_type: "refresh_token",
        client_id: client.client_id,
        refresh_token: seed.refresh_token,
        resource: [uri("allow-a"), uri("allow-b")],
      },
    });
    expect(accepted.status).toBe(200);
    const redeemed = (await accepted.json()) as any;
    expect(redeemed.scope).toBe("email");
    const rotated = (await (
      await control({ action: "token-row", kind: "refresh", token: redeemed.refresh_token })
    ).json()) as any;
    expect(rotated.scopes).toEqual(["email"]);
    expect(rotated.resources).toEqual([uri("allow-a"), uri("allow-b")]);
    const verified = await jwtVerify(redeemed.access_token, keys, { issuer });
    expect(verified.payload.scope).toBe("email");
    const beforeCeiling = await count();
    const outside = await control({
      action: "token",
      body: {
        grant_type: "refresh_token",
        client_id: client.client_id,
        refresh_token: redeemed.refresh_token,
        resource: [uri("unlinked")],
      },
    });
    expect(outside.status).toBe(400);
    expect(await outside.json()).toEqual({
      error: "invalid_target",
      error_description: "requested resource invalid",
    });
    expect(await count()).toEqual(beforeCeiling);
    return ctx.snapshot({ owner: owner.user, results, scope: issued.scope });
  },
);
