import { expect } from "bun:test";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "SCIM managed lookup redacts credentials and preserves expiry/domain/scope contracts",
  async (ctx) => {
    const actor = ctx.actor();
    const control = (operation: string, input: unknown) =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/scim?operation=${operation}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(input),
      });
    const input = {
      creationRequestId: "managed-get-request-001",
      provisioningDomainId: "tenant-a",
      actorId: "operator",
      scopes: ["scim.users.read", "scim.groups.write"],
      expiresAt: "2035-01-02T03:04:05.678Z",
    };
    const createdResponse = await control("createSCIMManagedConnection", {
      body: input,
      sdkDate: true,
    });
    expect(createdResponse.status).toBe(200);
    const created = (await createdResponse.json()) as any;
    const cid = created.connection.connectionId;
    const kid = created.credential.credentialId;
    const get = (id: string, domain: string) =>
      control("getSCIMManagedConnection", {
        body: { connectionId: id, provisioningDomainId: domain },
      });
    const response = await get(cid, "  tenant-a  ");
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      connection: created.connection,
      credentials: [created.credential],
    });
    const storage = () => control("managed-storage", {});
    const before = await (await storage()).json();
    for (const [id, domain] of [
      [cid, "tenant-b"],
      ["ba_scim_connection_missing", "tenant-a"],
    ]) {
      const response = await get(id, domain);
      expect(response.status).toBe(404);
      expect(await response.json()).toEqual({ message: "Managed SCIM connection not found" });
    }
    expect(await (await storage()).json()).toEqual(before);
    await control("credential-state", { credentialId: kid });
    await control("restart-managed", {});
    const expiredResponse = await get(cid, "tenant-a");
    expect(expiredResponse.status).toBe(200);
    const expired = (await expiredResponse.json()) as any;
    expect(expired.connection).toEqual(created.connection);
    expect(expired.credentials[0].status).toBe("expired");
    expect(expired.credentials[0].scopes).toEqual(input.scopes);
    expect(expired.credentials[0].credentialId).toBe(kid);
    for (const field of [
      "id",
      "connectionRecordId",
      "tokenDigest",
      "hashVersion",
      "activeSlotKey",
      "serializedScopes",
      "decommissionedAt",
      "token",
    ]) {
      expect(expired.credentials[0][field]).toBeUndefined();
    }
    for (const policy of [
      "not-json",
      JSON.stringify([]),
      JSON.stringify(["scim.users.read", "scim.users.read"]),
      JSON.stringify(["unknown"]),
    ]) {
      await control("credential-state", { credentialId: kid, policy });
      const response = await get(cid, "tenant-a");
      expect(response.status).toBe(500);
      expect(await response.json()).toEqual({
        message: "Managed SCIM credential scope policy is invalid",
      });
    }
    return {
      status: expired.credentials[0].status,
      scopes: expired.credentials[0].scopes,
      domain: "tenant-a",
      denialStatus: 404,
      invalidPolicyStatus: 500,
    };
  },
);
