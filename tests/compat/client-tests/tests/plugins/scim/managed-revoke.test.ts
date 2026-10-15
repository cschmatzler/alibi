import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";
compatScenario("SCIM managed revocation is idempotent and domain scoped", async (ctx) => {
  const actor = ctx.actor();
  const control = (operation: string, input: unknown) =>
    actor.fetch(`${ctx.baseURL}/__test/server-api/scim?operation=${operation}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(input),
    });
  const response = await control("createSCIMManagedConnection", {
    sdkDate: true,
    body: {
      creationRequestId: "managed-revoke-request-001",
      provisioningDomainId: "tenant-a",
      actorId: "operator",
      scopes: ["scim.users.read"],
      expiresAt: "2035-01-02T03:04:05.678Z",
    },
  });
  expect(response.status).toBe(200);
  const created = (await response.json()) as any;
  const cid = created.connection.connectionId;
  const kid = created.credential.credentialId;
  const revoke = (domain: string, credential: string) =>
    control("revokeSCIMManagedCredential", {
      body: {
        connectionId: cid,
        provisioningDomainId: domain,
        credentialId: credential,
        actorId: "  revocation-operator  ",
      },
    });
  await control("credential-state", { credentialId: kid });
  const revoked = await revoke("  tenant-a  ", kid);
  expect(revoked.status).toBe(200);
  const state = (await revoked.json()) as any;
  expect(state.connection).toEqual(created.connection);
  expect(state.credentials[0].status).toBe("revoked");
  expect(state.credentials[0].revokedBy).toBe("revocation-operator");
  expect(Number.isNaN(Date.parse(state.credentials[0].revokedAt))).toBe(false);
  const storage = async () => (await (await control("managed-storage", {})).json()) as any;
  const before = await storage();
  const row = before.credentials.find((row: any) => row.credentialId === kid);
  expect(row.activeSlotKey).toBe(`${kid}:inactive`);
  const event = before.events.find(
    (event: any) => event.sequence === 3 && event.credentialId === kid,
  );
  expect(event.type).toBe("credential.revoked");
  expect(event.credentialId).toBe(kid);
  expect(await (await revoke("tenant-a", kid)).json()).toEqual(state);
  for (const [domain, credential] of [
    ["tenant-b", kid],
    ["tenant-a", "ba_scim_credential_missing"],
  ]) {
    const denied = await revoke(domain, credential);
    expect(denied.status).toBe(404);
    expect(await denied.json()).toEqual({ message: "Managed SCIM connection not found" });
  }
  expect(await storage()).toEqual(before);
  const second = (await (
    await control("createSCIMManagedConnection", {
      sdkDate: true,
      body: {
        creationRequestId: "managed-revoke-request-002",
        provisioningDomainId: "tenant-a",
        actorId: "operator",
        scopes: ["scim.users.read"],
        expiresAt: "2035-01-02T03:04:05.678Z",
      },
    })
  ).json()) as any;
  const beforeFailure = await storage();
  expect(await (await control("reject-revocation-event", {})).json()).toEqual({ installed: true });
  const failed = await control("revocation-failure", {
    body: {
      connectionId: second.connection.connectionId,
      provisioningDomainId: "tenant-a",
      credentialId: second.credential.credentialId,
      actorId: "rollback-operator",
    },
  });
  expect(await failed.json()).toEqual({ failed: true, rejectedEvent: true });
  expect(await storage()).toEqual(beforeFailure);
  return {
    status: state.credentials[0].status,
    actor: state.credentials[0].revokedBy,
    event: event.type,
    idempotent: true,
  };
});
