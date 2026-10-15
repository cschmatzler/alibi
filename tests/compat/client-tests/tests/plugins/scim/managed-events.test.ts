import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";
compatScenario("SCIM managed event history is ordered, domain scoped and bounded", async (ctx) => {
  const actor = ctx.actor();
  const control = (operation: string, body: unknown) =>
    actor.fetch(`${ctx.baseURL}/__test/server-api/scim?operation=${operation}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ body, sdkDate: true }),
    });
  const createdResponse = await control("createSCIMManagedConnection", {
    creationRequestId: "managed-event-request-001",
    provisioningDomainId: "tenant-a",
    actorId: "creator",
    scopes: ["scim.users.read"],
    expiresAt: "2035-01-02T03:04:05.678Z",
  });
  expect(createdResponse.status).toBe(200);
  const created = (await createdResponse.json()) as any;
  const cid = created.connection.connectionId;
  const kid = created.credential.credentialId;
  const revoke = async (credentialId: string) => {
    const response = await control("revokeSCIMManagedCredential", {
      connectionId: cid,
      provisioningDomainId: "tenant-a",
      credentialId,
      actorId: "revoker",
    });
    expect(response.status).toBe(200);
  };
  await revoke(kid);
  const list = (id: string, domain: string) =>
    control("listSCIMManagedConnectionEvents", { connectionId: id, provisioningDomainId: domain });
  const storage = async () =>
    await (
      await actor.fetch(`${ctx.baseURL}/__test/server-api/scim?operation=managed-storage`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: "{}",
      })
    ).json();
  const before = await storage();
  const historyResponse = await list(cid, "  tenant-a  ");
  expect(historyResponse.status).toBe(200);
  const history = (await historyResponse.json()) as any;
  expect(history.events).toHaveLength(3);
  for (const [index, [type, actorId, credentialId]] of [
    ["connection.created", "creator", null],
    ["credential.issued", "creator", kid],
    ["credential.revoked", "revoker", kid],
  ].entries()) {
    const event = history.events[index];
    expect(event.sequence).toBe(index + 1);
    expect(event.type).toBe(type);
    expect(event.actorId).toBe(actorId);
    expect(event.credentialId).toBe(credentialId);
    expect(Object.keys(event).sort()).toEqual([
      "actorId",
      "createdAt",
      "credentialId",
      "sequence",
      "type",
    ]);
    expect(Number.isNaN(Date.parse(event.createdAt))).toBe(false);
  }
  for (const [id, domain] of [
    [cid, "tenant-b"],
    ["ba_scim_connection_missing", "tenant-a"],
  ]) {
    const denied = await list(id, domain);
    expect(denied.status).toBe(404);
    expect(await denied.json()).toEqual({ message: "Managed SCIM connection not found" });
  }
  expect(await storage()).toEqual(before);
  for (let index = 0; index < 51; index++) {
    const response = await control("rotateSCIMManagedCredential", {
      connectionId: cid,
      provisioningDomainId: "tenant-a",
      actorId: "rotator",
      scopes: ["scim.users.read"],
      expiresAt: "2035-01-02T03:04:05.678Z",
    });
    expect(response.status).toBe(200);
    const rotated = (await response.json()) as any;
    await revoke(rotated.credential.credentialId);
  }
  const limited = (await (await list(cid, "tenant-a")).json()) as any;
  expect(limited.events).toHaveLength(100);
  expect(limited.events.map((event: any) => event.sequence)).toEqual(
    Array.from({ length: 100 }, (_, index) => index + 6),
  );
  return {
    initial: history.events.map((event: any) => ({ sequence: event.sequence, type: event.type })),
    sequences: limited.events.map((event: any) => event.sequence),
  };
});
