import { expect } from "bun:test";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "SCIM configured projection supplies domain state and rolls back callback failure",
  async (ctx) => {
    const actor = ctx.actor();
    const control = (operation: string, input: unknown = {}) =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/scim?operation=${operation}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(input),
      });
    expect(await (await control("configure-projection")).json()).toEqual({ configured: true });
    const seeded = (await (
      await control("seed-projection", {
        sourceIds: ["scim-alias-ä", "scim-alias-Z", "scim-alias-c"],
      })
    ).json()) as any;
    const response = await control("reconcileSCIMProjection", {
      body: { provisioningDomainId: "  tenant-a  " },
    });
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      provisioningDomainId: "tenant-a",
      reconciledUsers: 1,
      batches: 1,
    });
    const states = (await (await control("projection-states")).json()) as any;
    expect(states).toHaveLength(1);
    expect(states[0]).toEqual({
      provisioningDomainId: "tenant-a",
      userId: seeded.userId,
      active: true,
      sources: [
        {
          id: "scim-alias-ä",
          connectionId: "conn-a",
          provisioningDomainId: "tenant-a",
          active: true,
        },
        {
          id: "scim-alias-Z",
          connectionId: "conn-b",
          provisioningDomainId: "tenant-a",
          active: false,
        },
      ],
      grants: [],
    });
    const retired = await control("decommissionSCIMConnection", {
      body: { connectionId: "conn-a", provisioningDomainId: "tenant-a" },
    });
    expect(retired.status).toBe(200);
    const inactive = await control("reconcileSCIMProjection", {
      body: { provisioningDomainId: "tenant-a" },
    });
    expect(inactive.status).toBe(200);
    expect(((await inactive.json()) as any).reconciledUsers).toBe(1);
    const observed = (await (await control("projection-states")).json()) as any;
    expect(observed).toHaveLength(2);
    expect(observed[1].active).toBe(false);
    expect(observed[1].sources).toEqual([
      {
        id: "scim-alias-Z",
        connectionId: "conn-b",
        provisioningDomainId: "tenant-a",
        active: false,
      },
    ]);
    const storage = async () => (await (await control("projection-storage")).json()) as any;
    const before = await storage();
    expect(before.users.find((user: any) => user.id === seeded.userId).name).toBe(
      "Projected inactive",
    );
    expect(before.subjects.find((subject: any) => subject.userId === seeded.userId).revision).toBe(
      2,
    );
    expect(before.grants).toEqual([]);
    expect(await (await control("projection-fails")).json()).toEqual({ failing: true });
    const beforeFailure = await storage();
    expect(beforeFailure.grants).toHaveLength(1);
    const failed = await control("reconcileSCIMProjection", {
      body: { provisioningDomainId: "tenant-a" },
    });
    expect(failed.status).toBe(500);
    expect(await failed.json()).toEqual({
      schemas: ["urn:ietf:params:scim:api:messages:2.0:Error"],
      status: "500",
      detail: "SCIM projection reconciliation failed",
    });
    expect(await storage()).toEqual(beforeFailure);
    return { state: states[0], name: "Projected inactive", revision: 2, rollback: true };
  },
);
