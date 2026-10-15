import { expect } from "bun:test";
import { randomUUID } from "node:crypto";

import { importJWK, SignJWT } from "jose";
import { Cookie } from "tough-cookie";

import { compatScenario } from "../../../support/scenario";

compatScenario(
  "Registered asymmetric client keys authenticate signed assertions with durable replay protection",
  async (ctx) => {
    const actor = ctx.actor();
    const control = (input: unknown) =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/oauth-provider-clients`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(input),
      });
    const signup = await control({
      action: "signup",
      body: { email: ctx.uniqueEmail("private-jwt-owner"), name: "Owner", password: "password123" },
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
    const results = [];
    for (const [algorithm, family] of [
      ["RS256", "RSA"],
      ["RS384", "RSA"],
      ["RS512", "RSA"],
      ["PS256", "RSA"],
      ["PS384", "RSA"],
      ["PS512", "RSA"],
      ["ES256", "P-256"],
      ["ES384", "P-384"],
      ["ES512", "P-521"],
      ["EdDSA", "Ed25519"],
    ] as const) {
      const key = fixture.keys.find((key: any) => key.family === family);
      const publicJwk = { ...key.publicJwk, alg: algorithm, kid: "application-key" };
      const created = await control({
        headers: { cookie },
        body: {
          client_name: algorithm,
          redirect_uris: ["https://app.fixture.test/callback"],
          token_endpoint_auth_method: "private_key_jwt",
          jwks: { keys: [publicJwk] },
        },
      });
      expect(created.status).toBe(201);
      const client = (await created.json()) as any;
      expect(client.client_secret).toBeUndefined();
      const now = Math.floor(Date.now() / 1000);
      const assertion = await new SignJWT({
        iss: client.client_id,
        sub: client.client_id,
        aud: `${ctx.baseURL}/oauth2/introspect`,
        iat: now,
        exp: now + 90,
        jti: randomUUID(),
      })
        .setProtectedHeader({ alg: algorithm, kid: "application-key", typ: "JWT" })
        .sign(await importJWK(key.privateJwk, algorithm));
      const body = {
        token: "not-issued",
        client_id: client.client_id,
        client_assertion: assertion,
        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      };
      const response = await control({ action: "introspect", body });
      expect(response.status).toBe(200);
      expect(await response.json()).toEqual({ active: false });
      // A separate auth instance shares only the durable database, not process-local replay state.
      const replay = await control({ mode: "reuse", action: "introspect", body });
      expect(replay.status).toBe(400);
      const replayBody = await replay.json();
      expect(replayBody).toEqual({
        error: "invalid_client",
        error_description: "client assertion jti has already been used",
      });
      if (algorithm === "RS256") {
        const signingKey = await importJWK(key.privateJwk, algorithm);
        const sign = (claims: any) =>
          new SignJWT(claims)
            .setProtectedHeader({ alg: algorithm, kid: "application-key" })
            .sign(signingKey);
        const claimCases: [string, string, unknown, number, string?][] = [
          ["issuer audience", "aud", ctx.baseURL, 200],
          ["future iat", "iat", now + 600, 200],
          ["whitespace jti", "jti", " ", 200],
          ["missing exp", "exp", undefined, 400, "client assertion must include exp claim"],
          [
            "long exp",
            "exp",
            now + 600,
            400,
            "client assertion exp is too far in the future (max 300s)",
          ],
          [
            "old iat",
            "iat",
            now - 600,
            400,
            "client assertion iat is too far in the past (max 300s)",
          ],
          ["missing jti", "jti", undefined, 400, "client assertion must include jti claim"],
          ["empty jti", "jti", "", 400, "client assertion must include jti claim"],
          ["expired", "exp", now - 60, 401],
          ["wrong audience", "aud", "https://other.example.test/", 401],
          ["wrong issuer", "iss", "other-client", 401],
          ["future nbf", "nbf", now + 600, 401],
          ["wrong exp type", "exp", "future", 401],
          ["wrong signature", "signature", true, 401],
        ];
        const claimsResults = [];
        for (const [name, field, value, status, detail] of claimCases) {
          const original = {
            iss: client.client_id,
            sub: client.client_id,
            aud: `${ctx.baseURL}/oauth2/introspect`,
            iat: now,
            exp: now + 90,
            jti: randomUUID(),
          };
          const claims: any = { ...original };
          if (field !== "signature") {
            if (value === undefined) {
              delete claims[field];
            } else {
              claims[field] = value;
            }
          }
          let signed = await sign(claims);
          if (field === "signature") {
            const parts = signed.split(".");
            const bytes = Buffer.from(parts[2]!, "base64url");
            bytes[0] = bytes[0]! ^ 1;
            signed = `${parts[0]}.${parts[1]}.${bytes.toString("base64url")}`;
          }
          const result = await control({
            action: "introspect",
            body: { ...body, client_assertion: signed },
          });
          expect(result.status, name).toBe(status);
          const resultBody = await result.json();
          expect(resultBody).toEqual(
            status === 200
              ? { active: false }
              : {
                  error: "invalid_client",
                  error_description: detail ?? "client assertion signature verification failed",
                },
          );
          if (status !== 200) {
            const repaired = await control({
              mode: "reuse",
              action: "introspect",
              body: { ...body, client_assertion: await sign(original) },
            });
            expect(repaired.status, `${name} must not consume jti`).toBe(200);
            expect(await repaired.json()).toEqual({ active: false });
          }
          claimsResults.push({ name, status: result.status, body: resultBody });
        }
        results.push({ claims: claimsResults });
      }
      results.push({
        algorithm,
        client,
        status: response.status,
        replay: { status: replay.status, body: replayBody },
      });
    }
    return ctx.snapshot({ results });
  },
);
