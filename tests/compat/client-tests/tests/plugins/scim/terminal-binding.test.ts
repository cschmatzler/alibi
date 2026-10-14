import { expect } from "bun:test";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "SCIM retirement persists an unused connection domain across restart",
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
    return {
      connectionId: state.connectionId,
      provisioningDomainId: state.provisioningDomainId,
      status: state.status,
      reconciledUsers: state.reconciledUsers,
      batches: state.batches,
    };
  },
);
