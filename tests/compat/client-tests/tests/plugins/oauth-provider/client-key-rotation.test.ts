import { randomUUID } from "node:crypto";
import { readFile as readFixtureFile } from "node:fs/promises";

import { importJWK, SignJWT } from "jose";
import { Cookie } from "tough-cookie";
import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";

compatScenario(
  "private_key_jwt clients rotate their own inline keys with an endpoint-bound single-use assertion",
  async (ctx) => {
    const actor = ctx.actor();
    const control = (input: object) =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/oauth-provider-clients`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ mode: "registration-key-rotation", ...input }),
      });
    const signup = await control({
      action: "signup",
      body: {
        email: ctx.uniqueEmail("key-rotation-owner"),
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
    const fixture = JSON.parse(
      await readFixtureFile(
        new URL("../../../../../fixtures/oauth/client-assertion-keys.json", import.meta.url),
        "utf8",
      ),
    );
    const rsa = fixture.keys.find((key: any) => key.family === "RSA");
    const ec = fixture.keys.find((key: any) => key.family === "P-256");
    const oldJwk = { ...rsa.publicJwk, alg: "RS256", kid: "old-key" };
    const newJwk = { ...ec.publicJwk, alg: "ES256", kid: "new-key" };
    const created = await control({
      action: "admin-create",
      headers: { cookie },
      body: {
        client_name: "Rotating client",
        redirect_uris: ["https://app.fixture.test/callback"],
        token_endpoint_auth_method: "private_key_jwt",
        jwks: { keys: [oldJwk] },
      },
    });
    expect(created.status).toBe(201);
    const client = (await created.json()) as any;
    const endpoint = `${ctx.baseURL}/api/auth/oauth2/client/rotate-keys`;
    const assertion = async (key: any, alg: string, kid: string, aud: string) => {
      const now = Math.floor(Date.now() / 1000);
      return new SignJWT({
        iss: client.client_id,
        sub: client.client_id,
        aud,
        iat: now,
        exp: now + 60,
        jti: randomUUID(),
      })
        .setProtectedHeader({ alg, kid })
        .sign(await importJWK(key.privateJwk, alg));
    };
    const type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
    const rotate = (body: object, mode?: string) =>
      control({
        ...(mode ? { mode } : {}),
        action: "protocol-http",
        path: "/oauth2/client/rotate-keys",
        method: "POST",
        contentType: "application/json",
        body,
      });
    const results: { name: string; status: number; cacheControl: string | null; value: unknown }[] =
      [];
    const record = async (name: string, response: Response) => {
      const value = await response.json();
      results.push({
        name,
        status: response.status,
        cacheControl: response.headers.get("cache-control"),
        value,
      });
      return value;
    };
    const valid = await assertion(rsa, "RS256", "old-key", endpoint);
    await record(
      "disabled",
      await rotate(
        { client_assertion: valid, client_assertion_type: type, jwks: { keys: [newJwk] } },
        "public",
      ),
    );
    await record(
      "missing-jwks",
      await rotate({ client_assertion: valid, client_assertion_type: type }),
    );
    await record(
      "missing-assertion",
      await rotate({ client_assertion_type: type, jwks: { keys: [newJwk] } }),
    );
    await record(
      "empty-keys",
      await rotate({ client_assertion: valid, client_assertion_type: type, jwks: { keys: [] } }),
    );
    await record(
      "private-key",
      await rotate({
        client_assertion: valid,
        client_assertion_type: type,
        jwks: { keys: [{ ...rsa.privateJwk, alg: "RS256", kid: "leak" }] },
      }),
    );
    await record(
      "token-audience",
      await rotate({
        client_assertion: await assertion(
          rsa,
          "RS256",
          "old-key",
          `${ctx.baseURL}/api/auth/oauth2/token`,
        ),
        client_assertion_type: type,
        jwks: { keys: [newJwk] },
      }),
    );
    await record(
      "issuer-audience",
      await rotate({
        client_assertion: await assertion(rsa, "RS256", "old-key", `${ctx.baseURL}/api/auth`),
        client_assertion_type: type,
        jwks: { keys: [newJwk] },
      }),
    );
    const rotated = await record(
      "rotated",
      await rotate({
        client_assertion: valid,
        client_assertion_type: type,
        jwks: { keys: [newJwk] },
      }),
    );
    expect(rotated).toEqual({ client_id: client.client_id, jwks: { keys: [newJwk] } });
    await record(
      "replayed",
      await rotate({
        client_assertion: valid,
        client_assertion_type: type,
        jwks: { keys: [oldJwk] },
      }),
    );
    await record(
      "retired-key",
      await rotate({
        client_assertion: await assertion(rsa, "RS256", "old-key", endpoint),
        client_assertion_type: type,
        jwks: { keys: [oldJwk] },
      }),
    );
    await record(
      "new-key",
      await rotate({
        client_assertion: await assertion(ec, "ES256", "new-key", endpoint),
        client_assertion_type: type,
        jwks: { keys: [newJwk, oldJwk] },
      }),
    );
    const row = await (await control({ action: "row", clientId: client.client_id })).json();
    expect(results.map(({ status }) => status)).toEqual([
      403, 400, 400, 400, 400, 401, 401, 200, 401, 401, 200,
    ]);
    return ctx.snapshot({ results, row });
  },
);
