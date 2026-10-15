import { expect } from "bun:test";
import { createHash } from "node:crypto";

import { Cookie } from "tough-cookie";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "OAuth client secret generators govern issuance, rotation and empty fallback",
  async (ctx) => {
    const actor = ctx.actor();
    const results = [];
    for (const mode of ["generated", "empty-generator"]) {
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
      if (mode === "generated") {
        expect(client.client_secret).toBe("operator-secret-1");
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
      if (mode === "generated") {
        expect(rotated.client_secret).toBe("operator-secret-2");
      } else {
        expect(rotated.client_secret).toMatch(/^[a-zA-Z]{32}$/);
      }
      expect(rotated.client_secret).not.toBe(client.client_secret);
      const row = (await (
        await control({ action: "row", clientId: client.client_id })
      ).json()) as any;
      expect(row.client_secret).toBe(
        createHash("sha256").update(rotated.client_secret).digest("base64url"),
      );
      expect(row.client_secret).not.toBe(old.client_secret);
      expect(row).toEqual({ ...old, client_secret: row.client_secret });
      const authentication = [];
      for (const [secret, status] of [
        [client.client_secret, 400],
        [rotated.client_secret, 200],
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
      results.push({ mode, client, publicClient, rotated, row, authentication });
    }
    return ctx.snapshot({ results });
  },
);
