import { Cookie } from "tough-cookie";
import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "JWT introspection uses signed access authority and live resource-peer admission",
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
      body: { email: ctx.uniqueEmail("jwt-introspection"), name: "Owner", password: "password123" },
    });
    expect(signup.status).toBe(200);
    const owner = (await signup.json()) as any;
    const cookie = signup.headers
      .getSetCookie()
      .filter((raw) => Boolean(Cookie.parse(raw)?.value))
      .map((raw) => raw.split(";")[0])
      .join("; ");
    const clients = [];
    for (const name of ["issuer", "peer", "stranger"]) {
      const created = await control({
        action: "admin-create",
        headers: { cookie },
        body: {
          client_name: name,
          redirect_uris: ["https://app.fixture.test/callback"],
          scope: "email offline_access",
          token_endpoint_auth_method: "client_secret_post",
          grant_types: ["authorization_code"],
        },
      });
      expect(created.status).toBe(201);
      clients.push((await created.json()) as any);
    }
    const [issuer, peer, stranger] = clients;
    const resource = "https://api.fixture.test/introspection/signed";
    expect(
      (
        await control({
          action: "resource-create",
          headers: { cookie },
          body: { identifier: resource },
        })
      ).status,
    ).toBe(200);
    for (const client of [issuer, peer]) {
      expect(
        (
          await control({
            action: "resource-link",
            headers: { cookie },
            params: { identifier: resource, client_id: client.client_id },
          })
        ).status,
      ).toBe(200);
    }
    const issued = await control({
      action: "issue-tokens",
      body: {
        clientId: issuer.client_id,
        userId: owner.user.id,
        grantType: "urn:fixture:introspection",
        params: {
          scopes: ["email", "offline_access"],
          resources: [resource],
          confirmation: { jkt: "trusted-binding" },
        },
      },
    });
    expect(issued.status).toBe(200);
    const tokens = (await issued.json()) as any;
    expect(tokens.access_token.split(".")).toHaveLength(3);
    const introspect = async (client: any, token = tokens.access_token, hint?: string) => {
      const response = await control({
        action: "protocol-http",
        path: "/oauth2/introspect",
        method: "POST",
        body: {
          client_id: client.client_id,
          client_secret: client.client_secret,
          token,
          ...(hint ? { token_type_hint: hint } : {}),
        },
      });
      return response;
    };
    const successes = [];
    for (const client of [issuer, peer]) {
      for (const hint of ["access_token", undefined, "unknown_hint"]) {
        const response = await introspect(client, tokens.access_token, hint);
        expect(response.status).toBe(200);
        const payload = (await response.json()) as any;
        expect(payload).toMatchObject({
          active: true,
          iss: `${ctx.baseURL}/api/auth`,
          aud: resource,
          client_id: issuer.client_id,
          azp: issuer.client_id,
          sub: owner.user.id,
          scope: "email offline_access",
          token_type: "DPoP",
          cnf: { jkt: "trusted-binding" },
        });
        successes.push({
          client: client === issuer ? "issuer" : "peer",
          hint: hint ?? "absent",
          type: payload.token_type,
          confirmation: payload.cnf,
        });
      }
    }
    const denied = await introspect(stranger);
    expect(denied.status).toBe(200);
    expect(await denied.json()).toEqual({ active: false });
    const prefixed = await introspect(issuer, "  dpop   " + tokens.access_token + "  ");
    expect(prefixed.status).toBe(200);
    expect(((await prefixed.json()) as any).active).toBe(true);
    const parts = tokens.access_token.split(".");
    const signature = Buffer.from(parts[2], "base64url");
    signature[0] = signature[0]! ^ 1;
    parts[2] = signature.toString("base64url");
    const tampered = await introspect(issuer, parts.join("."));
    expect(tampered.status).toBe(500);
    expect(tampered.headers.get("content-type")).toBe("application/json");
    expect(await tampered.text()).toBe("");
    const unlinked = await control({
      action: "resource-unlink",
      headers: { cookie },
      params: { identifier: resource, client_id: peer.client_id },
    });
    expect(unlinked.status).toBe(200);
    const retiredPeer = await introspect(peer);
    expect(retiredPeer.status).toBe(200);
    expect(await retiredPeer.json()).toEqual({ active: false });
    return ctx.snapshot({ successes, unlinked: true, tampered: tampered.status });
  },
);
