import { expect } from "bun:test";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "SCIM issued managed credentials authenticate reads and throttle last-used accounting",
  async (ctx) => {
    const actor = ctx.actor();
    const control = (operation: string, input: unknown = {}) =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/scim?operation=${operation}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(input),
      });
    const response = await control("createSCIMManagedConnection", {
      body: {
        creationRequestId: "managed-bearer-request-001",
        provisioningDomainId: "tenant-managed",
        actorId: "operator",
        scopes: ["scim.groups.read"],
        expiresAt: "2035-01-02T03:04:05.000Z",
      },
      sdkDate: true,
    });
    expect(response.status).toBe(200);
    const created = (await response.json()) as any;
    const { token } = created;
    const credentialId = created.credential.credentialId;
    const connectionId = created.connection.connectionId;
    expect(await (await control("seed-managed-group", { connectionId })).json()).toEqual({
      seeded: true,
    });
    const read = (candidate = token) =>
      control("getSCIMGroup", {
        params: { groupId: "managed-group" },
        query: {},
        token: candidate,
      });
    const storage = async () => (await (await control("managed-storage")).json()) as any;
    for (const candidate of [`${credentialId}.wrong-secret`, "ba_scim_credential_malformed"]) {
      expect((await read(candidate)).status).toBe(401);
    }
    expect((await storage()).credentials[0].lastUsedAt).toBe(null);
    expect(await (await control("binding-storage")).json()).toEqual([]);
    const group = await read();
    expect(group.status).toBe(200);
    expect(await group.json()).toEqual({
      schemas: ["urn:ietf:params:scim:schemas:core:2.0:Group"],
      id: "managed-group",
      displayName: "Managed Staff",
      members: [],
      meta: {
        resourceType: "Group",
        created: "2026-01-02T03:04:05.000Z",
        lastModified: "2026-01-02T03:04:05.000Z",
        location: `${ctx.baseURL}/__test/profiles/scim/api/auth/scim/v2/Groups/managed-group`,
      },
    });
    const used = await storage();
    expect(typeof used.credentials[0].lastUsedAt).toBe("string");
    expect((await read()).status).toBe(200);
    expect((await storage()).credentials).toEqual(used.credentials);
    const policy = async (input: unknown) =>
      expect(
        await (
          await control("managed-bearer-policy", {
            credentialId,
            connectionId,
            ...(input as object),
          })
        ).json(),
      ).toEqual({ changed: true });
    await policy({ serializedScopes: "not-json", lastUsedAt: null });
    const corrupt = await read();
    expect(corrupt.status).toBe(500);
    expect(((await corrupt.json()) as any).detail).toBe(
      "Managed SCIM credential scope policy is invalid",
    );
    expect(typeof (await storage()).credentials[0].lastUsedAt).toBe("string");
    await policy({ serializedScopes: JSON.stringify(["scim.groups.read"]), lastUsedAt: null });
    expect(await (await control("reject-managed-usage")).json()).toEqual({ installed: true });
    expect((await read()).status).toBe(200);
    expect((await storage()).credentials[0].lastUsedAt).toBe(null);
    expect(await (await control("accept-managed-usage")).json()).toEqual({ removed: true });
    expect((await read()).status).toBe(200);
    await policy({ serializedScopes: JSON.stringify(["scim.users.read"]) });
    const denied = await read();
    expect(denied.status).toBe(403);
    expect(denied.headers.get("www-authenticate")).toBe(null);
    await policy({ serializedScopes: JSON.stringify(["scim.groups.read"]), hashVersion: "v2" });
    expect((await read()).status).toBe(401);
    await policy({ hashVersion: "v1", status: "revoked" });
    expect((await read()).status).toBe(401);
    await policy({ status: "active", expiresAt: "2000-01-01T00:00:00.000Z" });
    expect((await read()).status).toBe(401);
    await policy({ expiresAt: "2035-01-02T03:04:05.000Z", connectionStatus: "decommissioned" });
    expect((await read()).status).toBe(401);
    return { authenticated: true, throttled: true, rejectedInvalid: true };
  },
);
