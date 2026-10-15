import { createHash } from "node:crypto";
import { readFile as readFixtureFile } from "node:fs/promises";

import { SignJWT, importJWK } from "jose";
import { Cookie } from "tough-cookie";
import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";

compatScenario(
  "Trusted token issuance verifies proof context and reserves sender binding",
  async (ctx) => {
    const actor = ctx.actor();
    const control = (input: object) =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/oauth-provider-clients`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(input),
      });
    const registered = await control({
      action: "signup",
      body: { email: ctx.uniqueEmail("dpop-issuer"), name: "Owner", password: "password123" },
    });
    expect(registered.status).toBe(200);
    const owner = (await registered.json()) as any;
    const cookie = registered.headers
      .getSetCookie()
      .filter((raw) => Boolean(Cookie.parse(raw)?.value))
      .map((raw) => raw.split(";")[0])
      .join("; ");
    const create = async (required: boolean) => {
      const response = await control({
        action: "admin-create",
        headers: { cookie },
        body: {
          client_name: "DPoP issuer",
          redirect_uris: ["https://app.fixture.test/callback"],
          scope: "email offline_access",
          token_endpoint_auth_method: "none",
          grant_types: ["authorization_code"],
          skip_consent: true,
          dpop_bound_access_tokens: required,
        },
      });
      expect(response.status).toBe(201);
      return (await response.json()) as any;
    };
    const required = await create(true);
    const optional = await create(false);
    const keys = JSON.parse(
      await readFixtureFile(
        new URL("../../../../../fixtures/oauth/client-assertion-keys.json", import.meta.url),
        "utf8",
      ),
    ).keys;
    const key = keys.find((key: any) => key.family === "Ed25519");
    const jkt = createHash("sha256")
      .update(
        JSON.stringify({ crv: key.publicJwk.crv, kty: key.publicJwk.kty, x: key.publicJwk.x }),
      )
      .digest("base64url");
    const proof = async (label: string, payload: object = {}, signing = key, alg = "EdDSA") =>
      new SignJWT({
        htm: "POST",
        htu: `${ctx.baseURL}/api/auth/oauth2/token`,
        jti: label,
        iat: Math.floor(Date.now() / 1000),
        ...payload,
      })
        .setProtectedHeader({ typ: "dpop+jwt", alg, jwk: signing.publicJwk })
        .sign(await importJWK(signing.privateJwk, alg));
    const issue = (
      client: any,
      proofJwt?: string,
      params: object = {},
      originalRefreshToken?: string,
      dpop?: object,
    ) =>
      control({
        action: "issue-tokens",
        ...(proofJwt ? { headers: { dpop: proofJwt } } : {}),
        body: {
          clientId: client.client_id,
          userId: owner.user.id,
          grantType: "urn:fixture:dpop",
          ...(dpop ? { dpop } : {}),
          ...(originalRefreshToken ? { originalRefreshToken } : {}),
          params: { scopes: ["email", "offline_access"], ...params },
        },
      });
    const missing = await issue(required);
    expect(missing.status).toBe(400);
    expect(await missing.json()).toEqual({
      error: "invalid_dpop_proof",
      error_description: "DPoP proof header is required",
    });
    const invalid = await issue(optional, "bad-proof");
    expect(invalid.status).toBe(400);
    expect(await invalid.json()).toEqual({
      error: "invalid_dpop_proof",
      error_description: "DPoP proof must be a compact JWT",
    });
    const parts = (await proof("tampered-signature")).split(".");
    const signature = Buffer.from(parts[2]!, "base64url");
    signature[0] = signature[0]! ^ 1;
    parts[2] = signature.toString("base64url");
    const tampered = await issue(optional, parts.join("."));
    expect(tampered.status).toBe(400);
    expect(await tampered.json()).toEqual({
      error: "invalid_dpop_proof",
      error_description: "signature verification failed",
    });
    const wrongUri = await issue(
      optional,
      await proof("wrong-uri", { htu: "https://other.fixture.test/token" }),
    );
    expect(wrongUri.status).toBe(400);
    expect(await wrongUri.json()).toEqual({
      error: "invalid_dpop_proof",
      error_description: "DPoP proof htu does not match the request URL",
    });
    const tooOld = await issue(
      optional,
      await proof("short-age", { iat: Math.floor(Date.now() / 1000) - 5 }),
      {},
      undefined,
      { proofMaxAgeSeconds: 1 },
    );
    expect(tooOld.status).toBe(400);
    expect(await tooOld.json()).toEqual({
      error: "invalid_dpop_proof",
      error_description: "DPoP proof iat is outside the accepted window",
    });
    const algorithm = await issue(optional, await proof("configured-algorithm"), {}, undefined, {
      signingAlgorithms: ["ES256"],
    });
    expect(algorithm.status).toBe(400);
    expect(await algorithm.json()).toEqual({
      error: "invalid_dpop_proof",
      error_description: "DPoP proof uses an unsupported JWS algorithm",
    });
    const mintedProof = await proof("trusted-mint");
    const response = await issue(required, mintedProof);
    expect(response.status).toBe(200);
    const tokens = (await response.json()) as any;
    expect(tokens.token_type).toBe("DPoP");
    const validated = await control({
      action: "validate-access",
      body: { token: tokens.access_token, requireActive: true },
    });
    expect(validated.status).toBe(200);
    expect(((await validated.json()) as any).cnf).toEqual({ jkt });
    const duplicate = await issue(required, mintedProof);
    expect(duplicate.status).toBe(400);
    expect(await duplicate.json()).toEqual({
      error: "invalid_dpop_proof",
      error_description: "DPoP proof jti has already been used",
    });
    const refreshMissing = await issue(required, undefined, {}, tokens.refresh_token);
    expect(refreshMissing.status).toBe(400);
    const wrongKey = await issue(
      required,
      await proof(
        "wrong-refresh-key",
        {},
        keys.find((key: any) => key.family === "RSA"),
        "RS256",
      ),
      {},
      tokens.refresh_token,
    );
    expect(wrongKey.status).toBe(400);
    expect(await wrongKey.json()).toEqual({
      error: "invalid_dpop_proof",
      error_description: "DPoP proof key does not match the bound token",
    });
    const rotated = await issue(required, await proof("trusted-rotate"), {}, tokens.refresh_token);
    expect(rotated.status).toBe(200);
    const next = (await rotated.json()) as any;
    expect(next.token_type).toBe("DPoP");
    expect(next.refresh_token).not.toBe(tokens.refresh_token);
    const retained = await control({
      action: "token-row",
      kind: "refresh",
      token: next.refresh_token,
    });
    expect(((await retained.json()) as any).confirmation).toEqual({ jkt });
    const refreshBody = {
      grant_type: "refresh_token",
      client_id: required.client_id,
      refresh_token: next.refresh_token,
    };
    const protocolMissing = await control({ action: "token", body: refreshBody });
    expect(protocolMissing.status).toBe(400);
    const protocol = await control({
      action: "token",
      headers: { dpop: await proof("protocol-refresh") },
      body: refreshBody,
    });
    expect(protocol.status).toBe(200);
    expect(((await protocol.json()) as any).token_type).toBe("DPoP");
    const resource = "https://api.fixture.test/dpop/required";
    expect(
      (
        await control({
          action: "resource-create",
          headers: { cookie },
          body: { identifier: resource, dpopBoundAccessTokensRequired: true },
        })
      ).status,
    ).toBe(200);
    expect(
      (
        await control({
          action: "resource-link",
          headers: { cookie },
          params: { identifier: resource, client_id: optional.client_id },
        })
      ).status,
    ).toBe(200);
    const resourceMissing = await issue(optional, undefined, { resources: [resource] });
    expect(resourceMissing.status).toBe(400);
    expect(await resourceMissing.json()).toEqual({
      error: "invalid_dpop_proof",
      error_description: "DPoP proof header is required",
    });
    const resourceIssued = await issue(optional, await proof("resource-required"), {
      resources: [resource],
    });
    expect(resourceIssued.status).toBe(200);
    expect(((await resourceIssued.json()) as any).token_type).toBe("DPoP");
    const verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    const challenge = createHash("sha256").update(verifier).digest("base64url");
    const grant = async () => {
      const response = await control({
        action: "authorize",
        headers: { cookie, accept: "application/json" },
        query: {
          client_id: optional.client_id,
          response_type: "code",
          redirect_uri: "https://app.fixture.test/callback",
          scope: "email offline_access",
          state: "dpop-code",
          code_challenge: challenge,
          code_challenge_method: "S256",
          dpop_jkt: jkt,
        },
      });
      expect(response.status).toBe(200);
      const code = new URL(((await response.json()) as any).url).searchParams.get("code");
      expect(code).toBeTruthy();
      return {
        grant_type: "authorization_code",
        client_id: optional.client_id,
        redirect_uri: "https://app.fixture.test/callback",
        code_verifier: verifier,
        code,
      };
    };
    const codeMissing = await control({ action: "token", body: await grant() });
    expect(codeMissing.status).toBe(400);
    expect(await codeMissing.json()).toEqual({
      error: "invalid_dpop_proof",
      error_description: "DPoP proof header is required",
    });
    const code = await control({
      action: "token",
      headers: { dpop: await proof("authorization-code") },
      body: await grant(),
    });
    expect(code.status).toBe(200);
    expect(((await code.json()) as any).token_type).toBe("DPoP");
    // Explicit confirmation belongs to the trusted caller and bypasses proof resolution.
    const explicit = await issue(required, "bad-proof", {
      confirmation: { "x5t#S256": "caller-certificate" },
    });
    expect(explicit.status).toBe(200);
    expect(((await explicit.json()) as any).token_type).toBe("Bearer");
    return ctx.snapshot({ jkt, type: tokens.token_type, rotatedType: next.token_type });
  },
);
