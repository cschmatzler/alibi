import { expect } from "bun:test";

import { Cookie } from "tough-cookie";

import { compatScenario } from "../../../support/scenario";
for (const mode of ["storage-schema", "storage-swap", "storage-domain-swap"]) {
  compatScenario(
    `${mode} SSO provider storage owns registration, DNS writes, updates and deletion`,
    async (ctx) => {
      const actor = ctx.actor();
      const control = (input: Record<string, unknown>) =>
        actor.fetch(`${ctx.baseURL}/__test/server-api/sso`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ mode, ...input }),
        });
      const owner = await control({
        action: "signup",
        body: {
          email: ctx.uniqueEmail("mapped-sso-owner"),
          name: "Owner",
          password: "password123",
        },
      });
      expect(owner.status).toBe(200);
      const ownerBody = (await owner.json()) as any;
      const cookie = owner.headers
        .getSetCookie()
        .filter((raw) => Boolean(Cookie.parse(raw)?.value))
        .map((raw) => raw.split(";")[0])
        .join("; ");
      const headers = { cookie };
      const body = {
        providerId: "mapped-provider",
        issuer: "https://idp.example.com",
        domain: "company.test",
        oidcConfig: {
          clientId: "enterprise-client",
          clientSecret: "durable-secret",
          skipDiscovery: true,
          pkce: true,
          authorizationEndpoint: "https://idp.example.com/authorize",
          tokenEndpoint: "https://idp.example.com/token",
          jwksEndpoint: "https://idp.example.com/jwks",
        },
      };
      const created = await control({ headers, body });
      expect(created.status).toBe(200);
      const registered = (await created.json()) as any;
      const physical = (await (await control({ action: "storage-state" })).json()) as any;
      expect(physical.customTableExists).toBe(true);
      expect(physical.defaultTableExists).toBe(false);
      expect(physical.rows).toHaveLength(1);
      expect(physical.rows[0].providerId).toBe(body.providerId);
      expect(physical.rows[0].userId).toBe(ownerBody.user.id);
      expect(physical.rows[0].domain).toBe(body.domain);
      expect(physical.rows[0].issuer).toBe(body.issuer);
      expect(physical.rows[0].organizationId).toBe(null);
      expect(physical.rows[0].samlConfig).toBe(null);
      expect(JSON.parse(physical.rows[0].oidcConfig).clientSecret).toBe("durable-secret");
      await control({
        action: "dns-records",
        records: [["_better-auth-token-mapped-provider=", registered.domainVerificationToken]],
      });
      const verified = await control({
        action: "verify-domain",
        headers,
        body: { providerId: body.providerId },
      });
      expect(verified.status).toBe(mode === "storage-domain-swap" ? 409 : 204);
      if (mode === "storage-domain-swap") {
        expect(await verified.json()).toEqual({
          code: "SSO_PROVIDER_CHANGED",
          message:
            "SSO provider changed while domain verification was in progress. Reload the provider and try again",
        });
      }
      const pending = (await (
        await control({ action: "proof", identifier: "_better-auth-token-mapped-provider" })
      ).json()) as any;
      expect(pending.value).toBe(registered.domainVerificationToken);
      const confirmed = (await (
        await control({ action: "row", providerId: body.providerId })
      ).json()) as any;
      expect(confirmed.domainVerified).toBe(mode !== "storage-domain-swap");
      const updated = await control({
        action: "update",
        headers,
        body: {
          providerId: body.providerId,
          domain: "new-company.test",
          oidcConfig: { clientId: "changed-client" },
        },
      });
      expect(updated.status).toBe(200);
      const row = (await (
        await control({ action: "row", providerId: body.providerId })
      ).json()) as any;
      expect(row.domain).toBe("new-company.test");
      expect(row.domainVerified).toBe(false);
      expect(JSON.parse(row.oidcConfig).clientId).toBe("changed-client");
      expect(JSON.parse(row.oidcConfig).clientSecret).toBe("durable-secret");
      const restart = await control({ action: "restart" });
      expect(restart.status).toBe(200);
      const read = await control({
        action: "get",
        headers,
        query: { providerId: body.providerId },
      });
      expect(read.status).toBe(200);
      const provider = (await read.json()) as any;
      expect(provider.domain).toBe("new-company.test");
      const listed = await control({ action: "list", headers });
      expect(listed.status).toBe(200);
      expect(((await listed.json()) as any).providers).toEqual([provider]);
      const removed = await control({
        action: "delete",
        headers,
        body: { providerId: body.providerId },
      });
      expect(removed.status).toBe(200);
      const final = (await (await control({ action: "storage-state" })).json()) as any;
      expect(final.customTableExists).toBe(true);
      expect(final.defaultTableExists).toBe(false);
      expect(final.rows).toEqual([]);
      expect(await (await control({ action: "row", providerId: body.providerId })).json()).toBe(
        null,
      );
      const session = (await (await control({ action: "session", headers })).json()) as any;
      expect(session.user.id).toBe(ownerBody.user.id);
      const project = (provider: any) => ({
        ...provider,
        oidcConfig: provider.oidcConfig ? JSON.parse(provider.oidcConfig) : null,
        samlConfig: provider.samlConfig ? JSON.parse(provider.samlConfig) : null,
      });
      return {
        physical: { ...physical, rows: physical.rows.map(project) },
        confirmed: project(confirmed),
        row: project(row),
        deleted: true,
        ownerRetained: true,
      };
    },
  );
}
