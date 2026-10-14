import { expect } from "bun:test";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "SCIM managed listing isolates domains, orders metadata and survives restart",
  async (ctx) => {
    const actor = ctx.actor();
    const control = (operation: string, input: unknown) =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/scim?operation=${operation}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(input),
      });
    const list = (domain: string) =>
      control("listSCIMManagedConnections", { body: { provisioningDomainId: domain } });
    const empty = await list("tenant-a");
    expect(empty.status).toBe(200);
    expect(await empty.json()).toEqual({ connections: [] });
    const created: any[] = [];
    for (const [requestId, domain] of [
      ["list-request-a-one", "tenant-a"],
      ["list-request-b-one", "tenant-b"],
      ["list-request-a-two", "tenant-a"],
    ]) {
      const response = await control("createSCIMManagedConnection", {
        sdkDate: true,
        body: {
          creationRequestId: requestId,
          provisioningDomainId: domain,
          actorId: "operator",
          scopes: ["scim.users.read"],
          expiresAt: "2035-01-02T03:04:05.678Z",
        },
      });
      expect(response.status).toBe(200);
      created.push(((await response.json()) as any).connection);
    }
    const aged = await control("age-connection", { connectionId: created[0].connectionId });
    expect(await aged.json()).toEqual({ aged: true });
    await control("restart-managed", {});
    const a = await list("  tenant-a  ");
    expect(a.status).toBe(200);
    const metadata = ((await a.json()) as any).connections;
    expect(metadata).toHaveLength(2);
    expect(metadata.map((row: any) => row.connectionId)).toEqual([
      created[2].connectionId,
      created[0].connectionId,
    ]);
    for (const row of metadata) {
      expect(row.provisioningDomainId).toBe("tenant-a");
      expect(row.status).toBe("active");
      expect(row.createdBy).toBe("operator");
      for (const field of ["id", "revision", "credentials", "token", "tokenDigest"]) {
        expect(row[field]).toBeUndefined();
      }
    }
    const b = await list("tenant-b");
    expect(await b.json()).toEqual({ connections: [created[1]] });
    const missing = await list("missing");
    expect(await missing.json()).toEqual({ connections: [] });
    return {
      domains: metadata.map((row: any) => row.provisioningDomainId),
      order: metadata.map((row: any) => row.creationRequestId),
      otherDomain: "tenant-b",
      missing: { connections: [] },
    };
  },
);
