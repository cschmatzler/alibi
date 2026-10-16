import { createHash } from "node:crypto";

import { Cookie } from "tough-cookie";
import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "OAuth client server creation admits the real owner and persists a protected one-time secret",
  async (ctx) => {
    const actor = ctx.actor();
    const control = async (input: unknown) =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/oauth-provider-clients`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(input),
      });
    const signup = await control({
      action: "signup",
      body: { email: ctx.uniqueEmail("oauth-client"), name: "Owner", password: "password123" },
    });
    expect(signup.status).toBe(200);
    const owner = (await signup.json()) as any;
    const cookie = signup.headers
      .getSetCookie()
      .filter((raw) => Boolean(Cookie.parse(raw)?.value))
      .map((raw) => raw.split(";")[0])
      .join("; ");
    const rejected = [];
    for (const [body, headers, status, code] of [
      [{ client_name: 42 }, { cookie }, 400, "VALIDATION_ERROR"],
      [
        { redirect_uris: ["https://app.fixture.test/callback"] },
        { cookie: "" },
        401,
        "UNAUTHORIZED",
      ],
      [
        { redirect_uris: ["https://app.fixture.test/callback"], scope: "forbidden" },
        { cookie },
        400,
        "invalid_scope",
      ],
      [{ client_name: "No redirect" }, { cookie }, 400, "invalid_redirect_uri"],
      [
        {
          redirect_uris: ["https://app.fixture.test/callback"],
          token_endpoint_auth_method: "private_key_jwt",
          jwks: { keys: [{ kty: "OKP", crv: "Ed448", x: "unsupported-curve", alg: "EdDSA" }] },
        },
        { cookie },
        400,
        "invalid_client_metadata",
      ],
      [
        { redirect_uris: ["https://app.fixture.test/callback#fragment"] },
        { cookie },
        400,
        "VALIDATION_ERROR",
      ],
      [
        { redirect_uris: ["http://app.fixture.test/callback"] },
        { cookie },
        400,
        "VALIDATION_ERROR",
      ],
      [
        {
          redirect_uris: ["http://127.1:3000/callback"],
          application_type: "native",
          token_endpoint_auth_method: "none",
        },
        { cookie },
        400,
        "invalid_redirect_uri",
      ],
    ] as const) {
      const response = await control({ body, headers });
      expect(response.status).toBe(status);
      const value = (await response.json()) as any;
      expect(value.code ?? value.error).toBe(code);
      rejected.push({ status, body: value });
    }
    const creationStart = Math.floor(Date.now() / 1000);
    const response = await control({
      headers: { cookie },
      body: {
        client_name: "Actual client",
        redirect_uris: ["\uFEFF \tHTTPS://APP.fixture.test:443/a/../callback \u00a0"],
        post_logout_redirect_uris: [" \uFEFFhttps://app.fixture.test/logout\u2029"],
        backchannel_logout_uri: "\uFEFFhttps://app.fixture.test/backchannel \uFEFF",
        client_uri: " https://app.fixture.test/about ",
        scope: "openid email",
        user_id: "forged-owner",
        client_id: "forged-client",
        client_secret: "forged-secret",
      },
    });
    expect(response.status).toBe(201);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(response.headers.get("pragma")).toBe("no-cache");
    const client = (await response.json()) as any;
    expect(client.client_id_issued_at).toBeGreaterThanOrEqual(creationStart);
    expect(client.client_id_issued_at).toBeLessThanOrEqual(Math.floor(Date.now() / 1000));
    expect(client.client_id).toMatch(/^[a-zA-Z]{32}$/);
    expect(client.client_secret).toMatch(/^[a-zA-Z]{32}$/);
    expect(client.user_id).toBe(owner.user.id);
    expect(client.client_name).toBe("Actual client");
    expect(client.token_endpoint_auth_method).toBe("client_secret_basic");
    expect(client.grant_types).toEqual(["authorization_code"]);
    const urls = {
      redirect_uris: ["HTTPS://APP.fixture.test:443/a/../callback"],
      post_logout_redirect_uris: ["https://app.fixture.test/logout"],
      backchannel_logout_uri: "https://app.fixture.test/backchannel",
      client_uri: " https://app.fixture.test/about ",
    };
    expect(client).toMatchObject(urls);
    const read = await control({
      action: "get",
      query: { client_id: client.client_id },
      headers: { cookie },
    });
    expect(read.status).toBe(200);
    const persisted = await read.json();
    expect(persisted).toMatchObject(urls);
    const rowResponse = await control({ action: "row", clientId: client.client_id });
    expect(rowResponse.status).toBe(200);
    const row = (await rowResponse.json()) as any;
    expect(row.userId).toBe(owner.user.id);
    expect(row.clientName).toBe("Actual client");
    expect(row.redirectUris).toEqual(urls.redirect_uris);
    expect(row.client_secret).toBe(
      createHash("sha256").update(client.client_secret).digest("base64url"),
    );
    const publicStart = Math.floor(Date.now() / 1000);
    const publicResponse = await control({
      headers: { cookie },
      body: {
        client_name: "Native public client",
        redirect_uris: [" \tcom.fixture.app:/callback\r\n "],
        token_endpoint_auth_method: "none",
        application_type: "native",
      },
    });
    expect(publicResponse.status).toBe(201);
    const publicClient = (await publicResponse.json()) as any;
    expect(publicClient.client_id_issued_at).toBeGreaterThanOrEqual(publicStart);
    expect(publicClient.client_id_issued_at).toBeLessThanOrEqual(Math.floor(Date.now() / 1000));
    expect(publicClient).not.toHaveProperty("client_secret");
    expect(publicClient).not.toHaveProperty("client_secret_expires_at");
    const publicRowResponse = await control({ action: "row", clientId: publicClient.client_id });
    const publicRow = (await publicRowResponse.json()) as any;
    expect(publicRow.client_secret).toBeNull();
    expect(publicRow.userId).toBe(owner.user.id);
    expect(publicRow.redirectUris).toEqual(["com.fixture.app:/callback"]);
    const authorization = await control({
      mode: "interaction",
      action: "authorize",
      headers: { accept: "application/json" },
      query: {
        client_id: publicClient.client_id,
        response_type: "code",
        redirect_uri: "com.fixture.app:/callback",
        scope: "email",
        code_challenge: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
        code_challenge_method: "S256",
      },
    });
    expect(authorization.status).toBe(200);
    const login = (await authorization.json()) as any;
    const loginURL = new URL(login.url, ctx.baseURL);
    expect(loginURL.pathname).toBe("/login");
    expect(loginURL.searchParams.get("redirect_uri")).toBe("com.fixture.app:/callback");
    return {
      rejected,
      client: ctx.snapshot(client),
      persisted: ctx.snapshot(persisted),
      login: ctx.snapshot(login),
      row: ctx.snapshot(row),
      publicClient: ctx.snapshot(publicClient),
      publicRow: ctx.snapshot(publicRow),
    };
  },
);
