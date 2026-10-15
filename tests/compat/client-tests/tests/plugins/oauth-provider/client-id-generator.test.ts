import { expect } from "bun:test";
import { createHash } from "node:crypto";

import { Cookie } from "tough-cookie";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "OAuth client ID generators control stored identifiers and preserve empty output",
  async (ctx) => {
    const actor = ctx.actor();
    const results = [];
    for (const mode of ["generated-id", "empty-id"]) {
      const control = (input: any) =>
        actor.fetch(`${ctx.baseURL}/__test/server-api/oauth-provider-clients`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ mode, ...input }),
        });
      const signup = await control({
        action: "signup",
        body: { email: ctx.uniqueEmail(`id-${mode}`), name: "Owner", password: "password123" },
      });
      expect(signup.status).toBe(200);
      const owner = (await signup.clone().json()) as any;
      const cookie = signup.headers
        .getSetCookie()
        .filter((raw) => Boolean(Cookie.parse(raw)?.value))
        .map((raw) => raw.split(";")[0])
        .join("; ");
      const input = {
        client_name: "Generated ID client",
        redirect_uris: ["https://app.fixture.test/callback"],
        client_id: "forged",
      };
      const denied = await control({ body: input });
      expect(denied.status).toBe(401);
      const created = await control({ body: input, headers: { cookie } });
      expect(created.status).toBe(201);
      const client = (await created.json()) as any;
      const expected = mode === "empty-id" ? "" : "operator-client-1";
      expect(client.client_id).toBe(expected);
      const row = (await (await control({ action: "row", clientId: expected })).json()) as any;
      expect(row.clientId).toBe(expected);
      expect(row.userId).toBe(owner.user.id);
      expect(row.client_secret).toBe(
        createHash("sha256").update(client.client_secret).digest("base64url"),
      );
      const response = await control({
        action: "get",
        query: { client_id: expected },
        headers: { cookie },
      });
      expect(response.status).toBe(200);
      const read = (await response.json()) as any;
      expect(read.client_id).toBe(expected);
      expect(read).not.toHaveProperty("client_secret");
      let publicClient;
      if (mode === "generated-id") {
        const response = await control({
          headers: { cookie },
          body: {
            redirect_uris: ["https://app.fixture.test/callback"],
            token_endpoint_auth_method: "none",
          },
        });
        expect(response.status).toBe(201);
        publicClient = (await response.json()) as any;
        expect(publicClient.client_id).toBe("operator-client-2");
        expect(publicClient).not.toHaveProperty("client_secret");
      }
      results.push({ mode, client, row, read, publicClient });
    }
    return ctx.snapshot({ results });
  },
);
