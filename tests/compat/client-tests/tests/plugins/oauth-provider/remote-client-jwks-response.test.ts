import { randomUUID } from "node:crypto";
import { readFile as readFixtureFile } from "node:fs/promises";

import { importJWK, SignJWT } from "jose";
import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";

compatScenario(
  "Remote client JWKS response and URI admission preserves rejected proof identifiers",
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
    const signing = await importJWK(rsa.privateJwk, "RS256");
    const clientId = "https://client.fixture.test/client.json";
    const uri = "https://client.fixture.test/jwks";
    const proof = async () => {
      const now = Math.floor(Date.now() / 1000);
      return new SignJWT({
        iss: clientId,
        sub: clientId,
        aud: `${ctx.baseURL}/api/auth/oauth2/introspect`,
        iat: now,
        exp: now + 90,
        jti: randomUUID(),
      })
        .setProtectedHeader({ alg: "RS256", kid: "first" })
        .sign(signing);
    };
    const inspect = (assertion: string) =>
      control({
        action: "introspect",
        body: {
          token: "not-issued",
          client_assertion: assertion,
          client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        },
      });
    const configure = async (responseMode: string, uri: string) => {
      const response = await control({ action: "remote-jwks-response", responseMode, uri });
      expect(response.status).toBe(200);
    };
    const fetches = async () =>
      (await (await control({ action: "remote-jwks-fetches" })).json()) as unknown[];
    expect(
      (
        await control({
          action: "remote-jwks-document",
          family: "RSA",
          algorithm: "RS256",
          kid: "first",
        })
      ).status,
    ).toBe(200);
    await configure("valid", `${uri}?seed=response-admission`);
    expect((await inspect(await proof())).status).toBe(200);
    const cases: [string, number, number, string][] = [
      ["status", 400, 1, "failed to fetch client JWKS"],
      ["redirect", 400, 1, "failed to fetch client JWKS"],
      ["type", 400, 1, "failed to fetch client JWKS"],
      ["no-type", 400, 1, "failed to fetch client JWKS"],
      ["length", 400, 1, "failed to fetch client JWKS"],
      ["hex-length", 400, 1, "failed to fetch client JWKS"],
      ["invalid-length", 200, 1, ""],
      ["exact-body", 200, 1, ""],
      ["over-body", 400, 1, "failed to fetch client JWKS"],
      ["bad-json", 400, 1, "failed to fetch client JWKS"],
      ["empty-keys", 400, 1, "failed to fetch client JWKS"],
      ["symmetric", 400, 1, "failed to fetch client JWKS"],
      ["private-key", 400, 1, "failed to fetch client JWKS"],
      ["exception", 400, 1, "failed to fetch client JWKS"],
      ["bom", 200, 1, ""],
      ["nonfinite", 200, 1, ""],
      ["bad-utf8", 200, 1, ""],
      ["wrong-kid", 401, 2, "client assertion signature verification failed"],
      ["ambiguous", 401, 1, "client assertion signature verification failed"],
      ["no-transport", 400, 0, "client discovery does not provide a metadata resource transport"],
      ["protocol", 400, 0, "jwks_uri must use HTTPS"],
      ["credentials", 400, 0, "jwks_uri must not contain credentials"],
      ["fragment", 400, 0, "jwks_uri must not include a fragment component"],
      ["private-host", 400, 0, "jwks_uri must not point to a private or reserved address"],
      ["untrusted", 400, 0, "client jwks_uri is not trusted"],
      ["no-uri", 400, 0, "client has no JWKS configured"],
    ];
    const results = [];
    for (const [name, status, count, description] of cases) {
      let target = `${uri}?case=${name}`;
      if (name === "protocol") target = target.replace("https:", "http:");
      if (name === "credentials") target = target.replace("https://", "https://user:pass@");
      if (name === "fragment") target += "#fragment";
      if (name === "private-host") target = "https://10.0.0.1/jwks";
      if (name === "untrusted") target = "https://other.fixture.test/jwks";
      if (name === "no-uri") target = "";
      await configure(name, target);
      const assertion = await proof();
      const response = await inspect(assertion);
      const body = await response.json();
      expect(response.status, name).toBe(status);
      expect(body, name).toEqual(
        status === 200
          ? { active: false }
          : { error: "invalid_client", error_description: description },
      );
      const calls = await fetches();
      expect(calls.length, name).toBe(count);
      let retry = null;
      if (status !== 200) {
        await configure("valid", `${uri}?repaired=${name}`);
        const repaired = await inspect(assertion);
        const body = await repaired.json();
        expect(repaired.status, `${name} retry`).toBe(200);
        expect(body).toEqual({ active: false });
        const calls = await fetches();
        expect(calls.length).toBe(1);
        retry = { status: repaired.status, body, fetches: calls };
      }
      results.push({ name, status: response.status, body, fetches: calls, retry });
    }
    return ctx.snapshot({ results });
  },
);
