import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "SCIM retirement preserves terminal bindings and active reconciliation leases",
  async (ctx) => {
    const actor = ctx.actor();
    const control = (operation: string, input: unknown) =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/scim?operation=${operation}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(input),
      });
    const response = await control("decommissionSCIMConnection", {
      body: { connectionId: "  external-provisioning  ", provisioningDomainId: "  tenant-a  " },
    });
    expect(response.status).toBe(200);
    const state = (await response.json()) as any;
    expect(state.connectionId).toBe("external-provisioning");
    expect(state.provisioningDomainId).toBe("tenant-a");
    expect(state.status).toBe("complete");
    expect(state.retryAfter).toBe(null);
    expect(state.reconciledUsers).toBe(0);
    expect(state.batches).toBe(0);
    expect(state.completedAt).toBe(state.decommissionedAt);
    expect(Number.isNaN(Date.parse(state.completedAt))).toBe(false);
    expect(await (await control("restart-managed", {})).json()).toEqual({ restarted: true });
    const again = await control("decommissionSCIMConnection", {
      body: { connectionId: "external-provisioning" },
    });
    expect(again.status).toBe(200);
    expect(await again.json()).toEqual(state);
    expect(
      await (await control("binding-lease", { connectionId: "external-provisioning" })).json(),
    ).toEqual({ leased: true });
    const before = await (await control("binding-storage", {})).json();
    const pendingResponse = await control("decommissionSCIMConnection", {
      body: { connectionId: "external-provisioning", provisioningDomainId: "tenant-a" },
    });
    expect(pendingResponse.status).toBe(200);
    const pending = (await pendingResponse.json()) as any;
    expect(pending.status).toBe("reconciling");
    expect(pending.retryAfter).toBe("2035-02-03T04:05:06.789Z");
    expect(pending.completedAt).toBe(null);
    expect(pending.decommissionedAt).toBe(state.decommissionedAt);
    expect(pending.reconciledUsers).toBe(7);
    expect(pending.batches).toBe(2);
    expect(await (await control("binding-storage", {})).json()).toEqual(before);
    expect(
      await (
        await control("expire-binding-lease", { connectionId: "external-provisioning" })
      ).json(),
    ).toEqual({ expired: true });
    const recoveredResponse = await control("decommissionSCIMConnection", {
      body: { connectionId: "external-provisioning" },
    });
    expect(recoveredResponse.status).toBe(200);
    const recovered = (await recoveredResponse.json()) as any;
    expect(recovered.status).toBe("complete");
    expect(recovered.retryAfter).toBe(null);
    expect(recovered.reconciledUsers).toBe(7);
    expect(recovered.batches).toBe(2);
    expect(recovered.decommissionedAt).toBe(state.decommissionedAt);
    expect(Number.isNaN(Date.parse(recovered.completedAt))).toBe(false);
    const rows = (await (await control("binding-storage", {})).json()) as any;
    const row = rows.find((row: any) => row.connectionId === "external-provisioning");
    expect(row.decommissionRevision).toBe(2);
    expect(row.decommissionLeaseId).toBe(null);
    expect(row.decommissionLeaseExpiresAt).toBe(null);
    expect(
      await (
        await control("reject-binding-completion", { connectionId: "external-provisioning" })
      ).json(),
    ).toEqual({ installed: true });
    expect(
      await (
        await control("binding-completion-failure", {
          body: { connectionId: "external-provisioning" },
        })
      ).json(),
    ).toEqual({ failed: true, rejectedCompletion: true });
    const failedRows = (await (await control("binding-storage", {})).json()) as any;
    const failed = failedRows.find((row: any) => row.connectionId === "external-provisioning");
    expect(failed.decommissionRevision).toBe(4);
    expect(failed.decommissionStatus).toBe("reconciling");
    expect(failed.decommissionCompletedAt).toBe(null);
    expect(failed.decommissionLeaseId).toBe(null);
    expect(failed.decommissionLeaseExpiresAt).toBe(null);
    expect(await (await control("accept-binding-completion", {})).json()).toEqual({
      removed: true,
    });
    const retried = await control("decommissionSCIMConnection", {
      body: { connectionId: "external-provisioning" },
    });
    expect(retried.status).toBe(200);
    expect(((await retried.json()) as any).status).toBe("complete");
    const finalRows = (await (await control("binding-storage", {})).json()) as any;
    expect(
      finalRows.find((row: any) => row.connectionId === "external-provisioning")
        .decommissionRevision,
    ).toBe(6);
    return {
      connectionId: state.connectionId,
      provisioningDomainId: state.provisioningDomainId,
      status: state.status,
      reconciledUsers: state.reconciledUsers,
      batches: state.batches,
    };
  },
);
