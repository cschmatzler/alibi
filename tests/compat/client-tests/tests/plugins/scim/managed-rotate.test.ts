import { expect } from "bun:test";
import { createHmac } from "node:crypto";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "SCIM managed rotation enforces credential slots and recycles expired credentials",
  async (ctx) => {
    const actor = ctx.actor();
    const control = (operation: string, input: unknown) =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/scim?operation=${operation}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(input),
      });
    const createdResponse = await control("createSCIMManagedConnection", {
      sdkDate: true,
      body: {
        creationRequestId: "managed-rotate-request-001",
        provisioningDomainId: "tenant-a",
        actorId: "operator",
        scopes: ["scim.users.read"],
        expiresAt: "2035-01-02T03:04:05.678Z",
      },
    });
    expect(createdResponse.status).toBe(200);
    const created = (await createdResponse.json()) as any;
    const cid = created.connection.connectionId;
    const first = created.credential.credentialId;
    const rotate = (id: string, domain: string, operator = "operator") =>
      control("rotateSCIMManagedCredential", {
        body: {
          connectionId: id,
          provisioningDomainId: domain,
          actorId: operator,
          scopes: ["scim.groups.write"],
          expiresAt: "2035-01-02T03:04:05.678Z",
        },
      });
    const response = await rotate(cid, "  tenant-a  ", "  rotation-operator  ");
    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(response.headers.get("pragma")).toBe("no-cache");
    const rotated = (await response.json()) as any;
    expect(rotated.connection).toEqual(created.connection);
    expect(rotated.credential.createdBy).toBe("rotation-operator");
    expect(rotated.credential.scopes).toEqual(["scim.groups.write"]);
    expect(rotated.credential.credentialId).not.toBe(first);
    expect(rotated.token).not.toBe(created.token);
    const storage = async () => (await (await control("managed-storage", {})).json()) as any;
    const before = await storage();
    const full = await rotate(cid, "tenant-a");
    expect(full.status).toBe(409);
    expect(await full.json()).toEqual({
      message: "Managed SCIM connection has the maximum number of active credentials",
    });
    expect(await storage()).toEqual(before);
    for (const [id, domain] of [
      [cid, "tenant-b"],
      ["ba_scim_connection_missing", "tenant-a"],
    ]) {
      const response = await rotate(id, domain);
      expect(response.status).toBe(404);
      expect(await response.json()).toEqual({ message: "Managed SCIM connection not found" });
    }
    await control("credential-state", { credentialId: first });
    const recycledResponse = await rotate(cid, "tenant-a");
    expect(recycledResponse.status).toBe(200);
    const recycled = (await recycledResponse.json()) as any;
    const state = await storage();
    expect(state.credentials).toHaveLength(3);
    const retired = state.credentials.find((row: any) => row.credentialId === first);
    expect(retired.status).toBe("expired");
    expect(retired.activeSlotKey).toBe(`${first}:inactive`);
    const fresh = state.credentials.find(
      (row: any) => row.credentialId === recycled.credential.credentialId,
    );
    expect(fresh.activeSlotKey).toBe(`${fresh.connectionRecordId}:active:0`);
    expect(fresh.tokenDigest).toBe(
      createHmac("sha256", "managed-scim-credential-hmac-secret-32-chars")
        .update(recycled.token)
        .digest("base64url"),
    );
    expect(state.connections[0].revision).toBe(4);
    expect(state.events).toHaveLength(4);
    for (const sequence of [3, 4]) {
      expect(state.events.find((event: any) => event.sequence === sequence).type).toBe(
        "credential.rotated",
      );
    }
    await control("credential-state", { credentialId: rotated.credential.credentialId });
    const beforeFailure = await storage();
    const installed = await control("reject-rotation-event", {});
    expect(await installed.json()).toEqual({ installed: true });
    const failed = await control("rotation-failure", {
      body: {
        connectionId: cid,
        provisioningDomainId: "tenant-a",
        actorId: "rollback-operator",
        scopes: ["scim.groups.write"],
        expiresAt: "2035-01-02T03:04:05.678Z",
      },
    });
    expect(await failed.json()).toEqual({ failed: true, rejectedEvent: true });
    expect(await storage()).toEqual(beforeFailure);
    return {
      revision: 4,
      count: 3,
      status: retired.status,
      reusedSlot: 0,
      events: state.events.map((event: any) => ({ sequence: event.sequence, type: event.type })),
    };
  },
);
