import { expect } from "bun:test";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "SCIM populated retirement reconciles access and global session lifecycle",
  async (ctx) => {
    const actor = ctx.actor();
    const control = (operation: string, input: unknown = {}) =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/scim?operation=${operation}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(input),
      });
    expect(await (await control("configure-projection")).json()).toEqual({ configured: true });
    const owner = (await (await control("seed-projection")).json()) as any;
    expect(await (await control("prepare-active-bindings")).json()).toEqual({ prepared: true });
    const storage = async () => (await (await control("projection-storage")).json()) as any;
    const before = await storage();
    expect(before.sessions).toHaveLength(1);
    const retire = (id: string, domain: string) =>
      control("decommissionSCIMConnection", {
        body: { connectionId: id, provisioningDomainId: domain },
      });
    expect(await (await control("projection-toggle-failure", { fail: true })).json()).toEqual({
      failing: true,
    });
    const failed = await retire("conn-a", "tenant-a");
    expect(failed.status).toBe(500);
    expect(await failed.json()).toEqual({
      schemas: ["urn:ietf:params:scim:api:messages:2.0:Error"],
      status: "500",
      detail: "SCIM projection reconciliation failed",
    });
    expect(await storage()).toEqual(before);
    const bindings = (await (await control("binding-storage")).json()) as any;
    const binding = bindings.find((row: any) => row.connectionId === "conn-a");
    expect(binding.decommissionStatus).toBe("reconciling");
    expect(binding.decommissionLeaseId).toBe(null);
    expect(binding.decommissionLeaseExpiresAt).toBe(null);
    expect(binding.decommissionRevision).toBe(2);
    expect(binding.decommissionReconciledUserCount).toBe(0);
    expect(await (await control("projection-toggle-failure", { fail: false })).json()).toEqual({
      failing: false,
    });
    const first = await retire("conn-a", "tenant-a");
    expect(first.status).toBe(200);
    const result = (await first.json()) as any;
    expect(result.status).toBe("complete");
    expect(result.reconciledUsers).toBe(1);
    expect(result.batches).toBe(1);
    const afterFirst = await storage();
    expect(afterFirst.sessions).toEqual(before.sessions);
    expect(afterFirst.grants).toEqual([]);
    const states = (await (await control("projection-states")).json()) as any;
    const state = states.at(-1);
    expect(state.userId).toBe(owner.userId);
    expect(state.active).toBe(false);
    expect(state.sources).toEqual([
      {
        id: "scim-alias-b",
        connectionId: "conn-b",
        provisioningDomainId: "tenant-a",
        active: false,
      },
    ]);
    const second = await retire("conn-c", "tenant-b");
    expect(second.status).toBe(200);
    expect(((await second.json()) as any).status).toBe("complete");
    const afterSecond = await storage();
    expect(afterSecond.sessions).toEqual([]);
    expect(afterSecond.subjects.find((row: any) => row.userId === owner.userId).revision).toBe(2);
    return {
      status: "complete",
      retainedAcrossDomain: true,
      retiredAfterLastSource: true,
      rollback: true,
    };
  },
);
