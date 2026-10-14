import { expect } from "bun:test";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "SCIM identity reconciliation receives global state before session retirement",
  async (ctx) => {
    const actor = ctx.actor();
    const control = (operation: string, input: unknown = {}) =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/scim?operation=${operation}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(input),
      });
    expect(await (await control("configure-identity")).json()).toEqual({ configured: true });
    const owner = (await (
      await control("seed-projection", {
        sourceIds: ["scim-alias-a", "scim-alias-ä", "scim-alias-Z"],
      })
    ).json()) as any;
    expect(await (await control("prepare-active-bindings")).json()).toEqual({ prepared: true });
    expect(await (await control("claim-profile-source")).json()).toEqual({ claimed: true });
    const storage = async () => (await (await control("projection-storage")).json()) as any;
    const before = await storage();
    expect(before.sessions).toHaveLength(1);
    const retire = (id: string, domain: string) =>
      control("decommissionSCIMConnection", {
        body: { connectionId: id, provisioningDomainId: domain },
      });
    expect((await retire("conn-a", "tenant-a")).status).toBe(200);
    const states = (await (await control("identity-states")).json()) as any;
    expect(states).toHaveLength(1);
    expect(states[0]).toEqual({
      userId: owner.userId,
      active: true,
      sources: [
        {
          id: "scim-alias-ä",
          connectionId: "conn-b",
          provisioningDomainId: "tenant-a",
          active: false,
        },
        {
          id: "scim-alias-Z",
          connectionId: "conn-c",
          provisioningDomainId: "tenant-b",
          active: true,
        },
      ],
    });
    const afterFirst = await storage();
    expect(afterFirst.sessions).toEqual(before.sessions);
    expect(afterFirst.users.find((row: any) => row.id === owner.userId).name).toBe(
      "Identity active",
    );
    expect(
      afterFirst.subjects.find((row: any) => row.userId === owner.userId).profileSourceId,
    ).toBe(null);
    expect(await (await control("identity-toggle-failure", { fail: true })).json()).toEqual({
      failing: true,
    });
    const beforeFailure = await storage();
    const failed = await retire("conn-c", "tenant-b");
    expect(failed.status).toBe(500);
    expect(await failed.json()).toEqual({
      schemas: ["urn:ietf:params:scim:api:messages:2.0:Error"],
      status: "500",
      detail: "SCIM identity reconciliation failed",
    });
    expect(await storage()).toEqual(beforeFailure);
    expect(await (await control("identity-toggle-failure", { fail: false })).json()).toEqual({
      failing: false,
    });
    expect((await retire("conn-c", "tenant-b")).status).toBe(200);
    const afterSecond = await storage();
    expect(afterSecond.sessions).toEqual([]);
    expect(afterSecond.users.find((row: any) => row.id === owner.userId).name).toBe(
      "Identity inactive",
    );
    return { clearedProfile: true, preservedSessions: true, retiredSessions: true, rollback: true };
  },
);
