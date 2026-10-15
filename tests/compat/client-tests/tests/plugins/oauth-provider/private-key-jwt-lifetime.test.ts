import { expect } from "bun:test";
import { randomUUID } from "node:crypto";

import { importJWK, SignJWT } from "jose";
import { Cookie } from "tough-cookie";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "Configured assertion lifetime follows reference number semantics without consuming rejected identifiers",
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
      body: {
        email: ctx.uniqueEmail("assertion-lifetime-owner"),
        name: "Owner",
        password: "password123",
      },
    });
    expect(signup.status).toBe(200);
    const cookie = signup.headers
      .getSetCookie()
      .filter((raw) => Boolean(Cookie.parse(raw)?.value))
      .map((raw) => raw.split(";")[0])
      .join("; ");
    const fixture = await Bun.file(
      new URL("../../../../../fixtures/oauth/client-assertion-keys.json", import.meta.url),
    ).json();
    const key = fixture.keys.find((key: any) => key.family === "RSA");
    const signingKey = await importJWK(key.privateJwk, "RS256");
    const created = await control({
      headers: { cookie },
      body: {
        client_name: "Assertion lifetime",
        redirect_uris: ["https://app.fixture.test/callback"],
        token_endpoint_auth_method: "private_key_jwt",
        jwks: { keys: [{ ...key.publicJwk, alg: "RS256", kid: "application-key" }] },
      },
    });
    expect(created.status).toBe(201);
    const client = (await created.json()) as any;
    const now = Math.floor(Date.now() / 1000);
    const cases: [string, string, number, number, number, string?][] = [
      ["short", "short", 90, 0, 400, "client assertion exp is too far in the future (max 30s)"],
      [
        "short-past",
        "short",
        20,
        -90,
        400,
        "client assertion iat is too far in the past (max 30s)",
      ],
      ["short-future", "short", 20, 90, 200],
      ["zero", "zero", 20, 0, 400, "client assertion exp is too far in the future (max 0s)"],
      [
        "negative",
        "negative",
        20,
        0,
        400,
        "client assertion exp is too far in the future (max -1s)",
      ],
      ["nan", "nan", 600, -600, 200],
      ["infinite", "infinite", 600, -600, 200],
      [
        "negative-infinite",
        "negative-infinite",
        20,
        0,
        400,
        "client assertion exp is too far in the future (max -Infinitys)",
      ],
    ];
    const results = [];
    for (const [name, mode, exp, iat, status, detail] of cases) {
      const assertion = await new SignJWT({
        iss: client.client_id,
        sub: client.client_id,
        aud: `${ctx.baseURL}/api/auth/oauth2/introspect`,
        exp: now + exp,
        iat: now + iat,
        jti: randomUUID(),
      })
        .setProtectedHeader({ alg: "RS256", kid: "application-key" })
        .sign(signingKey);
      const body = {
        token: "not-issued",
        client_id: client.client_id,
        client_assertion: assertion,
        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      };
      const response = await control({ mode: `assertion-${mode}`, action: "introspect", body });
      expect(response.status, name).toBe(status);
      const payload = await response.json();
      expect(payload).toEqual(
        detail ? { error: "invalid_client", error_description: detail } : { active: false },
      );
      if (status !== 200) {
        const retry = await control({ mode: "assertion-infinite", action: "introspect", body });
        expect(retry.status, `${name} must not consume jti`).toBe(200);
        expect(await retry.json()).toEqual({ active: false });
      }
      results.push({ name, status: response.status, body: payload });
    }
    return ctx.snapshot({ client, results });
  },
);
