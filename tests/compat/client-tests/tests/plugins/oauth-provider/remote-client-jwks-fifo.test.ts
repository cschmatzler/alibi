import { randomUUID } from "node:crypto";
import { readFile as readFixtureFile } from "node:fs/promises";

import { importJWK, SignJWT } from "jose";
import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "Remote client JWKS evicts the oldest URI despite cache reads and rotation",
  async (ctx) => {
    const actor = ctx.actor();
    const control = (input: object) =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/oauth-provider-clients`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ mode: "remote-jwks", ...input }),
      });
    const keys = JSON.parse(
      await readFixtureFile(
        new URL("../../../../../fixtures/oauth/client-assertion-keys.json", import.meta.url),
        "utf8",
      ),
    ).keys;
    const rsa = await importJWK(keys.find((key: any) => key.family === "RSA").privateJwk, "RS256");
    const ec = await importJWK(keys.find((key: any) => key.family === "P-256").privateJwk, "ES256");
    const clientId = "https://client.fixture.test/client.json";
    const uri = "https://client.fixture.test/jwks";
    const proof = async (rotation: boolean) => {
      const now = Math.floor(Date.now() / 1000);
      return new SignJWT({
        iss: clientId,
        sub: clientId,
        aud: `${ctx.baseURL}/api/auth/oauth2/introspect`,
        iat: now,
        exp: now + 90,
        jti: randomUUID(),
      })
        .setProtectedHeader({
          alg: rotation ? "ES256" : "RS256",
          kid: rotation ? "second" : "first",
        })
        .sign(rotation ? ec : rsa);
    };
    const inspect = async (index: number, rotation: boolean, expected: number) => {
      expect(
        (
          await control({
            action: "remote-jwks-response",
            responseMode: "valid",
            uri: `${uri}?entry=${index}`,
          })
        ).status,
      ).toBe(200);
      const response = await control({
        action: "introspect",
        body: {
          token: "not-issued",
          client_assertion: await proof(rotation),
          client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        },
      });
      expect(response.status, `entry ${index}`).toBe(200);
      expect(await response.json()).toEqual({ active: false });
      const fetches = await (await control({ action: "remote-jwks-fetches" })).json();
      expect(fetches.length, `entry ${index}`).toBe(expected);
      return { index, status: response.status, fetches };
    };
    const document = async (rotation: boolean) =>
      expect(
        (
          await control({
            action: "remote-jwks-document",
            family: rotation ? "P-256" : "RSA",
            algorithm: rotation ? "ES256" : "RS256",
            kid: rotation ? "second" : "first",
          })
        ).status,
      ).toBe(200);
    await document(false);
    for (let index = 0; index < 500; index++) await inspect(index, false, 1);
    const results = [];
    results.push({ phase: "read", ...(await inspect(0, false, 0)) });
    await document(true);
    results.push({ phase: "rotate", ...(await inspect(0, true, 1)) });
    results.push({ phase: "overflow", ...(await inspect(500, true, 1)) });
    results.push({ phase: "evicted", ...(await inspect(0, true, 1)) });
    await document(false);
    results.push({ phase: "retained", ...(await inspect(3, false, 0)) });
    results.push({ phase: "next-evicted", ...(await inspect(1, false, 1)) });
    results.push({ phase: "retained-again", ...(await inspect(3, false, 0)) });
    return ctx.snapshot({ filled: 500, results });
  },
);
