import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "SCIM managed retirement disables active credentials and records lifecycle events",
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
        creationRequestId: "managed-decommission-request-001",
        provisioningDomainId: "tenant-a",
        actorId: "creator",
        scopes: ["scim.users.read"],
        expiresAt: "2035-01-02T03:04:05.678Z",
      },
    });
    expect(createdResponse.status).toBe(200);
    const created = (await createdResponse.json()) as any;
    const cid = created.connection.connectionId;
    const first = created.credential.credentialId;
    const rotatedResponse = await control("rotateSCIMManagedCredential", {
      body: {
        connectionId: cid,
        provisioningDomainId: "tenant-a",
        actorId: "rotator",
        scopes: ["scim.groups.write"],
        expiresAt: "2035-01-02T03:04:05.678Z",
      },
    });
    expect(rotatedResponse.status).toBe(200);
    const rotated = (await rotatedResponse.json()) as any;
    const second = rotated.credential.credentialId;
    expect(
      (
        await control("revokeSCIMManagedCredential", {
          body: {
            connectionId: cid,
            provisioningDomainId: "tenant-a",
            credentialId: first,
            actorId: "revoker",
          },
        })
      ).status,
    ).toBe(200);
    const retire = (domain: string) =>
      control("decommissionSCIMManagedConnection", {
        body: {
          connectionId: cid,
          provisioningDomainId: domain,
          actorId: "  retirement-operator  ",
        },
      });
    const response = await retire("  tenant-a  ");
    expect(response.status).toBe(200);
    const state = (await response.json()) as any;
    expect(state.connection.status).toBe("decommissioned");
    expect(state.connection.decommissionStartedBy).toBe("retirement-operator");
    expect(state.connection.decommissionedBy).toBe("retirement-operator");
    expect(state.decommission.status).toBe("complete");
    expect(state.decommission.retryAfter).toBe(null);
    expect(
      state.credentials.find((credential: any) => credential.credentialId === first).status,
    ).toBe("revoked");
    expect(
      state.credentials.find((credential: any) => credential.credentialId === second).status,
    ).toBe("decommissioned");
    const storage = async () => (await (await control("managed-storage", {})).json()) as any;
    const before = await storage();
    const row = before.credentials.find((row: any) => row.credentialId === second);
    expect(row.activeSlotKey).toBe(`${second}:inactive`);
    expect(Number.isNaN(Date.parse(row.decommissionedAt))).toBe(false);
    for (const [sequence, type] of [
      [5, "connection.decommissioning"],
      [6, "connection.decommissioned"],
    ]) {
      const event = before.events.find(
        (event: any) =>
          event.connectionRecordId === row.connectionRecordId && event.sequence === sequence,
      );
      expect(event.type).toBe(type);
      expect(event.actorId).toBe("retirement-operator");
      expect(event.credentialId).toBe(null);
    }
    const again = (await (await retire("tenant-a")).json()) as any;
    expect(again.connection).toEqual(state.connection);
    expect(again.credentials).toEqual(state.credentials);
    expect(again.decommission).toEqual({ status: "complete", retryAfter: null });
    expect((await retire("tenant-b")).status).toBe(404);
    expect(await storage()).toEqual(before);
    expect(await (await control("reject-decommission-events", {})).json()).toEqual({
      installed: true,
    });
    for (const actorId of ["reject-begin", "reject-complete"]) {
      const fresh = (await (
        await control("createSCIMManagedConnection", {
          sdkDate: true,
          body: {
            creationRequestId: `managed-decommission-${actorId}-request`,
            provisioningDomainId: "tenant-a",
            actorId: "creator",
            scopes: ["scim.users.read"],
            expiresAt: "2035-01-02T03:04:05.678Z",
          },
        })
      ).json()) as any;
      const id = fresh.connection.connectionId;
      const before = await storage();
      const failed = await control("decommission-failure", {
        body: { connectionId: id, provisioningDomainId: "tenant-a", actorId },
      });
      expect(await failed.json()).toEqual({ failed: true, rejectedEvent: true });
      if (actorId === "reject-begin") {
        expect(await storage()).toEqual(before);
      } else {
        const pending = (await (
          await control("getSCIMManagedConnection", {
            body: { connectionId: id, provisioningDomainId: "tenant-a" },
          })
        ).json()) as any;
        expect(pending.connection.status).toBe("decommissioning");
        expect(pending.connection.decommissionedAt).toBe(null);
        expect(pending.credentials[0].status).toBe("decommissioned");
        expect(pending.credentials[0].credentialId).toBe(fresh.credential.credentialId);
        const history = async () =>
          (await (
            await control("listSCIMManagedConnectionEvents", {
              body: { connectionId: id, provisioningDomainId: "tenant-a" },
            })
          ).json()) as any;
        expect((await history()).events).toHaveLength(3);
        const resumed = (await (
          await control("decommissionSCIMManagedConnection", {
            body: {
              connectionId: id,
              provisioningDomainId: "tenant-a",
              actorId: "resume-operator",
            },
          })
        ).json()) as any;
        expect(resumed.connection.status).toBe("decommissioned");
        expect(resumed.connection.decommissionStartedBy).toBe("reject-complete");
        expect(resumed.connection.decommissionedBy).toBe("resume-operator");
        const events = (await history()).events;
        expect(events).toHaveLength(4);
        expect(events[3].actorId).toBe("resume-operator");
      }
    }
    return {
      status: state.connection.status,
      credentials: state.credentials.map((credential: any) => credential.status).sort(),
      events: ["connection.decommissioning", "connection.decommissioned"],
      idempotent: true,
    };
  },
);
