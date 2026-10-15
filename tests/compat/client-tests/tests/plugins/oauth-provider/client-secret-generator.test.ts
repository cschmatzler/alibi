import { expect } from "bun:test";
import { createHash } from "node:crypto";

import { Cookie } from "tough-cookie";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "OAuth client secret policies govern creation, rotation and authentication",
  async (ctx) => {
    const actor = ctx.actor();
    const results = [];
    for (const mode of [
      "generated",
      "empty-generator",
      "encrypted-generator",
      "prefixed-generator",
      "encrypted-prefixed-generator",
      "custom-hash",
      "custom-prefixed-verify",
    ]) {
      const prefix = mode.includes("prefixed") ? "client_prefix_" : "";
      const control = (input: any) =>
        actor.fetch(`${ctx.baseURL}/__test/server-api/oauth-provider-clients`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ mode, ...input }),
        });
      const signup = await control({
        action: "signup",
        body: {
          email: ctx.uniqueEmail(`generator-${mode}`),
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
      const created = await control({
        headers: { cookie },
        body: {
          client_name: "Generated client",
          redirect_uris: ["https://app.fixture.test/callback"],
          token_endpoint_auth_method: "client_secret_post",
        },
      });
      expect(created.status).toBe(201);
      const client = (await created.json()) as any;
      if (mode !== "empty-generator") {
        expect(client.client_secret).toBe(`${prefix}operator-secret-1`);
      } else {
        expect(client.client_secret).toMatch(/^[a-zA-Z]{32}$/);
      }
      const publicResponse = await control({
        headers: { cookie },
        body: {
          client_name: "Public client",
          redirect_uris: ["https://app.fixture.test/callback"],
          token_endpoint_auth_method: "none",
        },
      });
      expect(publicResponse.status).toBe(201);
      const publicClient = (await publicResponse.json()) as any;
      expect(publicClient).not.toHaveProperty("client_secret");
      for (const [id, headers, status] of [
        [client.client_id, {}, 401],
        [publicClient.client_id, { cookie }, 400],
      ] as const) {
        const response = await control({ action: "rotate", body: { client_id: id }, headers });
        expect(response.status).toBe(status);
      }
      const old = (await (
        await control({ action: "row", clientId: client.client_id })
      ).json()) as any;
      const response = await control({
        action: "rotate",
        body: { client_id: client.client_id },
        headers: { cookie },
      });
      expect(response.status).toBe(200);
      const rotated = (await response.json()) as any;
      if (mode !== "empty-generator") {
        expect(rotated.client_secret).toBe(`${prefix}operator-secret-2`);
      } else {
        expect(rotated.client_secret).toMatch(/^[a-zA-Z]{32}$/);
      }
      expect(rotated.client_secret).not.toBe(client.client_secret);
      const row = (await (
        await control({ action: "row", clientId: client.client_id })
      ).json()) as any;
      const rawSecret = rotated.client_secret.slice(prefix.length);
      const hash = `${mode.startsWith("custom-") ? "custom:" : ""}${createHash("sha256").update(rawSecret).digest("base64url")}`;
      if (mode.includes("encrypted")) {
        expect(typeof row.client_secret).toBe("string");
        expect(row.client_secret.length).toBeGreaterThan(0);
        expect(row.client_secret).not.toBe(rotated.client_secret);
        expect(row.client_secret).not.toBe(hash);
      } else {
        expect(row.client_secret).toBe(hash);
      }
      expect(row.client_secret).not.toBe(old.client_secret);
      expect(row).toEqual({ ...old, client_secret: row.client_secret });
      const prefixDenials = [];
      if (prefix) {
        for (const secret of [rawSecret, `WRONG_${rawSecret}`]) {
          const result = await control({
            action: "introspect",
            body: { client_id: client.client_id, client_secret: secret, token: "not-issued" },
          });
          expect(result.status).toBe(401);
          expect(result.headers.get("www-authenticate")).toBeNull();
          const body = await result.json();
          expect(body).toEqual({
            error: "invalid_client",
            error_description: "invalid client_secret",
          });
          prefixDenials.push({ status: result.status, body });
        }
      }
      const authentication = [];
      for (const [secret, status] of [
        [client.client_secret, 400],
        [rotated.client_secret, 200],
        [`${rotated.client_secret}!`, mode === "custom-prefixed-verify" ? 200 : 400],
      ] as const) {
        const result = await control({
          action: "introspect",
          body: { client_id: client.client_id, client_secret: secret, token: "not-issued" },
        });
        expect(result.status).toBe(status);
        const body = await result.json();
        if (status === 200) {
          expect(body).toEqual({ active: false });
        } else {
          expect(body).toMatchObject({ error: "invalid_client" });
        }
        authentication.push({ status, body });
      }
      const { client_secret: protectedSecret, ...rowMetadata } = row;
      expect(protectedSecret).toBeTruthy();
      results.push({
        mode,
        client,
        publicClient,
        rotated,
        row: rowMetadata,
        authentication,
        prefixDenials,
      });
    }
    const invalid = await actor.fetch(`${ctx.baseURL}/__test/server-api/oauth-provider-clients`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ action: "secret-hash-validation" }),
    });
    expect(invalid.status).toBe(200);
    const validation = await invalid.json();
    expect(validation).toEqual({
      valid: false,
      message: "unable to store hashed secrets because id tokens will be signed with secret",
    });
    return ctx.snapshot({ results, validation });
  },
);
