import { createHmac } from "node:crypto";

import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";
const HASH_SECRET = "managed-scim-credential-hmac-secret-32-chars";
compatScenario(
  "SCIM managed creation persists a digest and ordered events and rejects request reuse",
  async (ctx) => {
    const actor = ctx.actor();
    const call = (body: unknown, sdkDate = true) =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/scim?operation=createSCIMManagedConnection`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ body, sdkDate }),
      });
    const storage = async () =>
      (await (
        await actor.fetch(`${ctx.baseURL}/__test/server-api/scim?operation=managed-storage`, {
          method: "POST",
        })
      ).json()) as any;
    const body = {
      creationRequestId: "  request-creation-001  ",
      provisioningDomainId: "  tenant-one  ",
      actorId: "  operator  ",
      scopes: ["scim.users.read", "scim.users.write"],
      expiresAt: "2035-01-02T03:04:05.678Z",
    };
    const began = Date.now();
    const response = await call(body);
    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(response.headers.get("pragma")).toBe("no-cache");
    const created = (await response.json()) as any;
    const connection = created.connection;
    const credential = created.credential;
    expect(new Date(connection.createdAt).getTime()).toBeGreaterThanOrEqual(began - 1000);
    expect(new Date(connection.createdAt).getTime()).toBeLessThanOrEqual(Date.now());
    expect(credential.createdAt).toBe(connection.createdAt);
    expect(connection.creationRequestId).toBe("request-creation-001");
    expect(connection.provisioningDomainId).toBe("tenant-one");
    expect(connection.createdBy).toBe("operator");
    expect(connection.status).toBe("active");
    expect(connection.id).toBeUndefined();
    expect(connection.revision).toBeUndefined();
    expect(connection.connectionId).toMatch(/^ba_scim_connection_[A-Za-z0-9_-]{32}$/);
    expect(credential.credentialId).toMatch(/^ba_scim_credential_[A-Za-z0-9_-]{32}$/);
    expect(credential.scopes).toEqual(body.scopes);
    expect(credential.expiresAt).toBe(body.expiresAt);
    expect(credential.createdBy).toBe("operator");
    expect(credential.status).toBe("active");
    expect(created.token).toMatch(new RegExp(`^${credential.credentialId}\\.[A-Za-z0-9_-]{48}$`));
    const state = await storage();
    expect(state.connections).toHaveLength(1);
    expect(state.credentials).toHaveLength(1);
    expect(state.events).toHaveLength(2);
    const row = state.connections[0];
    const stored = state.credentials[0];
    expect(row.connectionId).toBe(connection.connectionId);
    expect(row.revision).toBe(2);
    expect(stored.connectionRecordId).toBe(row.id);
    expect(stored.credentialId).toBe(credential.credentialId);
    expect(stored.hashVersion).toBe("v1");
    expect(stored.activeSlotKey).toBe(`${row.id}:active:0`);
    expect(stored.tokenDigest).toBe(
      createHmac("sha256", HASH_SECRET).update(created.token).digest("base64url"),
    );
    expect(credential.tokenDigest).toBeUndefined();
    expect(JSON.parse(stored.serializedScopes)).toEqual(body.scopes);
    for (const [index, kind] of ["connection.created", "credential.issued"].entries()) {
      const event = state.events[index];
      expect(event.sequence).toBe(index + 1);
      expect(event.type).toBe(kind);
      expect(event.actorId).toBe("operator");
      expect(event.connectionRecordId).toBe(row.id);
      expect(event.eventKey).toBe(`${row.id}:${index + 1}`);
    }
    expect(state.events[0].credentialId).toBeNull();
    expect(state.events[1].credentialId).toBe(credential.credentialId);
    const reused = await call(body);
    expect(reused.status).toBe(409);
    expect(await reused.json()).toEqual({
      code: "SCIM_MANAGED_CREATION_REQUEST_ID_CONFLICT",
      message: "Managed SCIM connection creation request ID already exists",
    });
    expect(await storage()).toEqual(state);
    for (const [candidate, sdkDate, message] of [
      [
        {
          ...body,
          creationRequestId: "another-request-001",
          scopes: ["scim.users.read", "scim.users.read"],
        },
        true,
        "Managed SCIM credential scopes must be unique",
      ],
      [
        {
          ...body,
          creationRequestId: "another-request-002",
          expiresAt: "2000-01-01T00:00:00.000Z",
        },
        true,
        "Managed SCIM credential expiry must be in the future",
      ],
      [
        { ...body, creationRequestId: "another-request-003" },
        false,
        "[body.expiresAt] Invalid input: expected date, received string",
      ],
    ] as const) {
      const denied = await call(candidate, sdkDate);
      expect(denied.status).toBe(400);
      expect(((await denied.json()) as any).message).toBe(message);
      expect(await storage()).toEqual(state);
    }
    const installed = await actor.fetch(
      `${ctx.baseURL}/__test/server-api/scim?operation=reject-late-event`,
      { method: "POST" },
    );
    expect(await installed.json()).toEqual({ installed: true });
    const failed = await actor.fetch(
      `${ctx.baseURL}/__test/server-api/scim?operation=managed-failure`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          body: {
            ...body,
            creationRequestId: "rollback-request-001",
            actorId: "rollback-operator",
          },
        }),
      },
    );
    expect(await failed.json()).toEqual({ failed: true, rejectedLateEvent: true });
    expect(await storage()).toEqual(state);
    const { createdAt: connectionTime, ...observedConnection } = connection;
    const { createdAt: credentialTime, ...observedCredential } = credential;
    return {
      connection: { ...observedConnection, connectionId: "[generated]" },
      credential: { ...observedCredential, credentialId: "[generated]" },
      events: state.events.map((event: any) => ({
        sequence: event.sequence,
        type: event.type,
        actorId: event.actorId,
      })),
      digestStored: true,
      reuseStatus: 409,
    };
  },
);
