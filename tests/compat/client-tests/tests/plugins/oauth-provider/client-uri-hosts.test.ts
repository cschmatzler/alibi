import { Cookie } from "tough-cookie";
import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "OAuth client URI hosts follow reference public routability even on trusted origins",
  async (ctx) => {
    const actor = ctx.actor();
    const control = (input: object) =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/oauth-provider-clients`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ mode: "uri-host", ...input }),
      });
    const signup = await control({
      action: "signup",
      body: { email: ctx.uniqueEmail("uri-host-owner"), name: "Owner", password: "password123" },
    });
    expect(signup.status).toBe(200);
    const cookie = signup.headers
      .getSetCookie()
      .filter((raw) => Boolean(Cookie.parse(raw)?.value))
      .map((raw) => raw.split(";")[0])
      .join("; ");
    const hosts = [
      "100.64.0.1",
      "198.18.0.1",
      "192.0.0.9",
      "192.88.99.1",
      "240.0.0.1",
      "metadata.google.internal",
      "instance-data.ec2.internal",
      "[::ffff:127.0.0.1]",
      "[64:ff9b::a00:1]",
      "[2002:a00:1::]",
      "[3fff::1]",
      "[5f00::1]",
      "8.8.8.8",
      "[2001:4860:4860::8888]",
      "keys.fixture.test",
      "external",
    ];
    const results = [];
    for (const [index, host] of hosts.entries()) {
      for (const field of ["jwks_uri", "backchannel_logout_uri"]) {
        const uri = `https://${host}/keys`;
        const response = await control({
          headers: { cookie },
          body: {
            client_name: "URI host",
            redirect_uris: ["https://app.fixture.test/callback"],
            token_endpoint_auth_method: field === "jwks_uri" ? "private_key_jwt" : "none",
            [field]: uri,
          },
        });
        const allowed = index >= 12;
        expect(response.status, `${field}: ${host}`).toBe(allowed ? 201 : 400);
        const body = (await response.json()) as any;
        if (allowed) {
          expect(body[field]).toBe(uri);
          expect(body.client_secret).toBeUndefined();
        } else {
          expect(body).toEqual({
            error: "invalid_client_metadata",
            error_description: `${field} must not point to a private or reserved address`,
          });
        }
        results.push({ host, field, status: response.status, body });
      }
    }
    return ctx.snapshot({ results });
  },
);
