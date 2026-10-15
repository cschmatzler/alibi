import { randomUUID } from "node:crypto";
import { readFile as readFixtureFile } from "node:fs/promises";

import { importJWK, SignJWT } from "jose";
import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "Remote client JWKS cache spans shared provider instances and refetches only on key misses",
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
    const rsa = keys.find((key: any) => key.family === "RSA");
    const ec = keys.find((key: any) => key.family === "P-256");
    const clientId = "https://client.fixture.test/client.json";
    const proof = async (key: any, algorithm: string, kid: string) => {
      const now = Math.floor(Date.now() / 1000);
      return new SignJWT({
        iss: clientId,
        sub: clientId,
        aud: `${ctx.baseURL}/api/auth/oauth2/introspect`,
        iat: now,
        exp: now + 90,
        jti: randomUUID(),
      })
        .setProtectedHeader({ alg: algorithm, kid })
        .sign(await importJWK(key.privateJwk, algorithm));
    };
    const inspect = (assertion: string, mode = "remote-jwks") =>
      control({
        mode,
        action: "introspect",
        body: {
          token: "not-issued",
          client_assertion: assertion,
          client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        },
      });
    const fetches = async () =>
      (await (await control({ action: "remote-jwks-fetches" })).json()) as unknown[];
    const results = [];
    for (const [phase, mode] of [
      ["initial", "remote-jwks"],
      ["cached", "remote-jwks"],
      ["cached-peer", "remote-jwks-peer"],
    ]) {
      const response = await inspect(await proof(rsa, "RS256", "first"), mode);
      expect(response.status, phase).toBe(200);
      const body = await response.json();
      expect(body).toEqual({ active: false });
      const calls = await fetches();
      expect(calls.length, phase).toBe(1);
      results.push({ phase, status: response.status, body, fetches: calls });
    }
    const update = await control({
      action: "remote-jwks-document",
      family: "P-256",
      algorithm: "ES256",
      kid: "second",
    });
    expect(update.status).toBe(200);
    const rotated = await inspect(await proof(ec, "ES256", "second"));
    expect(rotated.status).toBe(200);
    const rotatedBody = await rotated.json();
    expect(rotatedBody).toEqual({ active: false });
    expect((await fetches()).length).toBe(2);
    results.push({
      phase: "rotated",
      status: rotated.status,
      body: rotatedBody,
      fetches: await fetches(),
    });
    const assertion = await proof(ec, "ES256", "second");
    const parts = assertion.split(".");
    const signature = Buffer.from(parts[2]!, "base64url");
    signature[0] = signature[0]! ^ 1;
    const invalid = `${parts[0]}.${parts[1]}.${signature.toString("base64url")}`;
    const denied = await inspect(invalid);
    expect(denied.status).toBe(401);
    const deniedBody = await denied.json();
    expect(deniedBody).toEqual({
      error: "invalid_client",
      error_description: "client assertion signature verification failed",
    });
    expect((await fetches()).length).toBe(2);
    results.push({
      phase: "bad-signature",
      status: denied.status,
      body: deniedBody,
      fetches: await fetches(),
    });
    const repaired = await inspect(assertion, "remote-jwks-peer");
    expect(repaired.status).toBe(200);
    const repairedBody = await repaired.json();
    expect(repairedBody).toEqual({ active: false });
    results.push({
      phase: "repaired",
      status: repaired.status,
      body: repairedBody,
      fetches: await fetches(),
    });
    expect(await fetches()).toEqual(
      Array(2).fill({
        url: "https://client.fixture.test/jwks",
        accept: "application/json",
        redirect: "error",
        aborted: false,
      }),
    );
    return ctx.snapshot({ results });
  },
);
