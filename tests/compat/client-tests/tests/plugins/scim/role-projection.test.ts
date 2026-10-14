import { expect } from "bun:test";
import { createHash } from "node:crypto";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "SCIM role projection normalizes, validates and persists source-aware grants",
  async (ctx) => {
    const actor = ctx.actor();
    const control = (operation: string, input: unknown = {}) =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/scim?operation=${operation}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(input),
      });
    expect(await (await control("configure-role-projection")).json()).toEqual({ configured: true });
    const seeded = (await (await control("seed-projection")).json()) as any;
    expect(await (await control("seed-role-groups")).json()).toEqual({ seeded: true });
    const reconcile = () =>
      control("reconcileSCIMProjection", { body: { provisioningDomainId: "tenant-a" } });
    const response = await reconcile();
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      provisioningDomainId: "tenant-a",
      reconciledUsers: 1,
      batches: 1,
    });
    const states = (await (await control("projection-states")).json()) as any;
    const grants = [
      {
        source: {
          type: "group",
          id: "group-b",
          externalId: "administrators-b",
          displayName: "Admin backups",
        },
        role: "admin",
      },
      {
        source: {
          type: "group",
          id: "group-a",
          externalId: "administrators",
          displayName: "Admins",
        },
        role: "admin",
      },
      {
        source: { type: "group", id: "group-e", externalId: "editors", displayName: "Editors" },
        role: "admin",
      },
      {
        source: { type: "group", id: "group-g", externalId: "guests", displayName: "Guests" },
        role: "admin",
      },
    ];
    expect(states[0].grants).toEqual(grants);
    const observations = (await (await control("role-observations")).json()) as any;
    expect(observations.mapped.map((input: any) => input.source.id)).toEqual([
      "group-a",
      "group-b",
      "group-e",
      "group-g",
    ]);
    expect(observations.checked.map((input: any) => input.role)).toEqual(["admin", "missing"]);
    for (const input of observations.mapped) {
      expect(input.connectionId).toBe("conn-a");
      expect(input.provisioningDomainId).toBe("tenant-a");
      expect(input.scimUserId).toBe("scim-alias-a");
      expect(input.userId).toBe(seeded.userId);
    }
    const storage = async () => (await (await control("projection-storage")).json()) as any;
    const before = await storage();
    expect(before.grants).toHaveLength(4);
    for (const grant of before.grants) {
      expect(grant.role).toBe("admin");
      expect(grant.scimUserId).toBe("scim-alias-a");
      expect(grant.grantKey).toBe(
        createHash("sha256")
          .update(
            JSON.stringify([
              "scim-projection-grant",
              "conn-a",
              "scim-alias-a",
              "group",
              grant.sourceId,
              "admin",
            ]),
          )
          .digest("base64url"),
      );
    }
    expect(await (await control("rename-role-source")).json()).toEqual({ renamed: true });
    expect((await reconcile()).status).toBe(200);
    expect((await storage()).grants).toEqual(before.grants);
    const renamed = (await (await control("projection-states")).json()) as any;
    expect(renamed[1].grants[1].source.externalId).toBe("administrators-renamed");
    for (const [stage, detail] of [
      [1, "SCIM role mapping failed"],
      [2, "SCIM role validation failed"],
    ]) {
      expect(await (await control("role-failure-stage", { stage })).json()).toEqual({ stage });
      const beforeFailure = await storage();
      const failed = await reconcile();
      expect(failed.status).toBe(500);
      expect(await failed.json()).toEqual({
        schemas: ["urn:ietf:params:scim:api:messages:2.0:Error"],
        status: "500",
        detail,
      });
      expect(await storage()).toEqual(beforeFailure);
    }
    return { grants, checked: ["admin", "missing"], preservedMetadata: true, rollback: true };
  },
);
