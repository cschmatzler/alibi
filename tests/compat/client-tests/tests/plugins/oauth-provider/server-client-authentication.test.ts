import { randomUUID } from "node:crypto";
import { readFile as readFixtureFile } from "node:fs/promises";

import { importJWK, SignJWT } from "jose";
import { Cookie } from "tough-cookie";
import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "Server client authentication checks caller policy, scopes, grants and endpoint-bound proofs",
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
        email: ctx.uniqueEmail("authentication-helper"),
        name: "Owner",
        password: "password123",
      },
    });
    expect(signup.status).toBe(200);
    const owner = await signup.json();
    const cookie = signup.headers
      .getSetCookie()
      .filter((raw) => Boolean(Cookie.parse(raw)?.value))
      .map((raw) => raw.split(";")[0])
      .join("; ");
    const keys = JSON.parse(
      await readFixtureFile(
        new URL("../../../../../fixtures/oauth/client-assertion-keys.json", import.meta.url),
        "utf8",
      ),
    ).keys;
    const rsa = keys.find((key: any) => key.family === "RSA");
    const clients: Record<string, any> = {};
    for (const method of ["client_secret_post", "client_secret_basic", "none", "private_key_jwt"]) {
      const response = await control({
        headers: { cookie },
        body: {
          client_name: method,
          scope: "email profile",
          grant_types: ["authorization_code"],
          redirect_uris: ["https://app.fixture.test/callback"],
          token_endpoint_auth_method: method,
          ...(method === "private_key_jwt"
            ? { jwks: { keys: [{ ...rsa.publicJwk, alg: "RS256", kid: "first" }] } }
            : {}),
        },
      });
      expect(response.status).toBe(201);
      clients[method] = await response.json();
    }
    const post = clients.client_secret_post;
    const basic = clients.client_secret_basic;
    const pub = clients.none;
    const pk = clients.private_key_jwt;
    const posted = { client_id: post.client_id, client_secret: post.client_secret };
    const basicHeader = `Basic ${Buffer.from(`${basic.client_id}:${basic.client_secret}`).toString("base64")}`;
    const auth = (body: object, authorization?: string) =>
      control({
        action: "authenticate-client",
        body,
        ...(authorization ? { headers: { authorization } } : {}),
      });
    const results = [];
    const cases: [
      string,
      object,
      string | undefined,
      number,
      string,
      string,
      string | null,
      string | null,
    ][] = [
      ["missing", {}, undefined, 400, "invalid_request", "Missing required client_id", null, null],
      [
        "no-credentials",
        { client_id: post.client_id },
        undefined,
        400,
        "invalid_client",
        "Missing required client credentials",
        null,
        null,
      ],
      ["post", posted, undefined, 200, "", "", post.client_id, "client_secret_post"],
      [
        "wrong",
        { client_id: post.client_id, client_secret: "wrong" },
        undefined,
        400,
        "invalid_client",
        "invalid client_secret",
        null,
        null,
      ],
      [
        "unknown",
        { client_id: "missing-client", client_secret: "secret" },
        undefined,
        400,
        "invalid_client",
        "missing client",
        null,
        null,
      ],
      [
        "public-required",
        { client_id: pub.client_id },
        undefined,
        400,
        "invalid_client",
        "Missing required client credentials",
        null,
        null,
      ],
      [
        "public-optional",
        { client_id: pub.client_id, requireCredentials: false },
        undefined,
        200,
        "",
        "",
        pub.client_id,
        "none",
      ],
      [
        "confidential-optional",
        { client_id: post.client_id, requireCredentials: false },
        undefined,
        400,
        "invalid_client",
        "client registered for client_secret_post cannot use none",
        null,
        null,
      ],
      [
        "scope",
        { ...posted, requestedScopes: ["email", "bogus"] },
        undefined,
        400,
        "invalid_scope",
        "client does not allow scope bogus",
        null,
        null,
      ],
      [
        "scope-empty",
        { ...posted, requestedScopes: [""] },
        undefined,
        400,
        "invalid_scope",
        "client does not allow scope ",
        null,
        null,
      ],
      [
        "grant",
        { ...posted, boundGrant: "client_credentials" },
        undefined,
        400,
        "unauthorized_client",
        "client is not authorized to use grant type client_credentials",
        null,
        null,
      ],
      [
        "refresh-grant",
        { ...posted, boundGrant: "refresh_token" },
        undefined,
        200,
        "",
        "",
        post.client_id,
        "client_secret_post",
      ],
      ["basic", {}, basicHeader, 200, "", "", basic.client_id, "client_secret_basic"],
      [
        "basic-wrong",
        {},
        `Basic ${Buffer.from(`${basic.client_id}:wrong`).toString("base64")}`,
        401,
        "invalid_client",
        "invalid client_secret",
        null,
        null,
      ],
      [
        "mixed",
        posted,
        basicHeader,
        400,
        "invalid_request",
        "A request must use only one client authentication method",
        null,
        null,
      ],
    ];
    for (const [name, input, header, status, code, description, id, method] of cases) {
      const response = await auth(input, header);
      expect(response.status, name).toBe(status);
      const body = await response.json();
      if (status === 200) {
        expect(body).toEqual({
          clientId: id,
          method,
          confirmation: null,
          client: { clientId: id, clientName: method, userId: owner.user.id },
        });
      } else {
        expect(body).toEqual({ error: code, error_description: description });
      }
      expect(response.headers.get("www-authenticate")).toBe(
        name === "basic-wrong" ? "Basic" : null,
      );
      results.push({
        name,
        status: response.status,
        challenge: response.headers.get("www-authenticate"),
        body,
      });
    }
    const signing = await importJWK(rsa.privateJwk, "RS256");
    const proof = async (path: string) => {
      const now = Math.floor(Date.now() / 1000);
      return new SignJWT({
        iss: pk.client_id,
        sub: pk.client_id,
        aud: `${ctx.baseURL}/api/auth${path}`,
        iat: now,
        exp: now + 90,
        jti: randomUUID(),
      })
        .setProtectedHeader({ alg: "RS256", kid: "first" })
        .sign(signing);
    };
    const input = (proof: string) => ({
      client_assertion: proof,
      client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    });
    const valid = await proof("/fixture/authenticate-client");
    const success = await auth(input(valid));
    expect(success.status).toBe(200);
    const authenticated = await success.json();
    expect(authenticated).toEqual({
      clientId: pk.client_id,
      method: "private_key_jwt",
      confirmation: null,
      client: { clientId: pk.client_id, clientName: "private_key_jwt", userId: owner.user.id },
    });
    results.push({ name: "assertion", status: success.status, body: authenticated });
    const replay = await auth(input(valid));
    expect(replay.status).toBe(400);
    const replayBody = await replay.json();
    expect(replayBody).toEqual({
      error: "invalid_client",
      error_description: "client assertion jti has already been used",
    });
    results.push({ name: "replay", status: replay.status, body: replayBody });
    const wrong = await proof("/oauth2/introspect");
    const denied = await auth(input(wrong));
    expect(denied.status).toBe(401);
    const deniedBody = await denied.json();
    expect(deniedBody).toEqual({
      error: "invalid_client",
      error_description: "client assertion signature verification failed",
    });
    results.push({ name: "wrong-endpoint", status: denied.status, body: deniedBody });
    const repaired = await control({
      action: "introspect",
      body: { ...input(wrong), token: "not-issued" },
    });
    expect(repaired.status).toBe(200);
    const repairedBody = await repaired.json();
    expect(repairedBody).toEqual({ active: false });
    results.push({ name: "correct-endpoint-retry", status: repaired.status, body: repairedBody });
    const scoped = await proof("/fixture/authenticate-client");
    const scope = await auth({ ...input(scoped), requestedScopes: ["bogus"] });
    expect(scope.status).toBe(400);
    const scopeBody = await scope.json();
    expect(scopeBody).toEqual({
      error: "invalid_scope",
      error_description: "client does not allow scope bogus",
    });
    results.push({ name: "assertion-scope", status: scope.status, body: scopeBody });
    const scopeReplay = await auth({ ...input(scoped), requestedScopes: ["email"] });
    expect(scopeReplay.status).toBe(400);
    const scopeReplayBody = await scopeReplay.json();
    expect(scopeReplayBody).toEqual({
      error: "invalid_client",
      error_description: "client assertion jti has already been used",
    });
    results.push({
      name: "scope-proof-consumed",
      status: scopeReplay.status,
      body: scopeReplayBody,
    });
    return ctx.snapshot({ owner: owner.user, results });
  },
);
