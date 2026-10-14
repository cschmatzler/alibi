import { expect } from "bun:test";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "SCIM Group reads authenticate, isolate connections and project owned members",
  async (ctx) => {
    const actor = ctx.actor();
    const control = (operation: string, input: unknown = {}) =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/scim?operation=${operation}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(input),
      });
    const read = (id: string, query: unknown = {}, token?: string) =>
      control("getSCIMGroup", {
        params: { groupId: id },
        query,
        ...(token === undefined ? {} : { token }),
      });
    const unauthenticated = await read("staff");
    expect(unauthenticated.status).toBe(401);
    expect(await unauthenticated.json()).toEqual({
      schemas: ["urn:ietf:params:scim:api:messages:2.0:Error"],
      status: "401",
      detail: "SCIM bearer token is required",
    });
    expect(unauthenticated.headers.get("www-authenticate")).toBe('Bearer realm="SCIM"');
    for (const token of ["invalid-reader", "expired-reader"]) {
      const denied = await read("staff", {}, token);
      expect(denied.status).toBe(401);
      expect(((await denied.json()) as any).detail).toBe("Invalid SCIM bearer token");
    }
    const forbidden = await read("staff", {}, "users-reader");
    expect(forbidden.status).toBe(403);
    expect(((await forbidden.json()) as any).detail).toBe(
      "The SCIM bearer token is missing the scim.groups.read scope",
    );
    expect(forbidden.headers.get("www-authenticate")).toBe(null);
    expect(await (await control("binding-storage")).json()).toEqual([]);
    const invalidShape = await read("staff", { attributes: 1, excludedAttributes: false });
    expect(invalidShape.status).toBe(400);
    expect(((await invalidShape.json()) as any).detail).toBe(
      "[query.attributes] Invalid input; [query.excludedAttributes] Invalid input",
    );
    expect(await (await control("seed-group-read")).json()).toEqual({ seeded: true });
    const response = await read("staff", {}, "group-reader");
    expect(response.status).toBe(200);
    const expected = {
      schemas: ["urn:ietf:params:scim:schemas:core:2.0:Group"],
      id: "staff",
      externalId: "external-staff",
      displayName: "Staff",
      meta: {
        resourceType: "Group",
        created: "2026-01-02T03:04:05.000Z",
        lastModified: "2026-01-02T03:04:05.000Z",
        location: `${ctx.baseURL}/__test/profiles/scim/api/auth/scim/v2/Groups/staff`,
      },
      members: [
        {
          value: "member-a",
          $ref: `${ctx.baseURL}/__test/profiles/scim/api/auth/scim/v2/Users/member-a`,
          display: "Inactive member",
          type: "User",
        },
        {
          value: "member-c",
          $ref: `${ctx.baseURL}/__test/profiles/scim/api/auth/scim/v2/Users/member-c`,
          display: "Other domain member",
          type: "User",
        },
      ],
    };
    expect(await response.json()).toEqual(expected);
    const selected = await read(
      "staff",
      { attributes: [" DISPLAYNAME ", "members.value,meta.location"] },
      "group-reader",
    );
    expect(await selected.json()).toEqual({
      schemas: expected.schemas,
      id: "staff",
      displayName: "Staff",
      meta: { location: expected.meta.location },
      members: [{ value: "member-a" }, { value: "member-c" }],
    });
    const excluded = await read(
      "staff",
      { excludedAttributes: "id,schemas,members.display,meta" },
      "group-reader",
    );
    expect(await excluded.json()).toEqual({
      schemas: expected.schemas,
      id: "staff",
      externalId: "external-staff",
      displayName: "Staff",
      members: expected.members.map(({ display, ...member }) => member),
    });
    const dateProjection = await read(
      "staff",
      { excludedAttributes: "members,meta.created.fake" },
      "group-reader",
    );
    expect(await dateProjection.json()).toEqual({
      schemas: expected.schemas,
      id: "staff",
      externalId: "external-staff",
      displayName: "Staff",
      meta: { ...expected.meta, created: {} },
    });
    for (const id of ["missing", "other"]) {
      expect((await read(id, {}, "group-reader")).status).toBe(404);
    }
    const drift = await read("drift", {}, "group-reader");
    expect(drift.status).toBe(409);
    expect(((await drift.json()) as any).detail).toBe(
      "The connection provisioningDomainId changed after resources were created",
    );
    const invalid = await read(
      "staff",
      { attributes: "displayName", excludedAttributes: "members" },
      "group-reader",
    );
    expect(invalid.status).toBe(400);
    expect(((await invalid.json()) as any).scimType).toBe("invalidValue");
    expect(
      (
        await read(
          "missing",
          { attributes: "displayName", excludedAttributes: "members" },
          "group-reader",
        )
      ).status,
    ).toBe(404);
    const http = await actor.fetch(
      `${ctx.baseURL}/__test/profiles/scim/api/auth/scim/v2/Groups/staff`,
      { headers: { authorization: "Bearer group-reader" } },
    );
    expect(http.status).toBe(200);
    expect(await http.json()).toEqual(expected);
    expect(http.headers.get("content-type")).toBe("application/scim+json");
    expect(http.headers.get("x-better-auth-scim-response")).toBe(null);
    const bindings = (await (await control("binding-storage")).json()) as any;
    expect(bindings).toHaveLength(1);
    expect(bindings[0].decommissionStatus).toBe("active");
    expect(await (await control("oversize-group-read")).json()).toEqual({ oversized: true });
    const oversized = await read("staff", {}, "group-reader");
    expect(oversized.status).toBe(500);
    expect(((await oversized.json()) as any).detail).toBe(
      "Persisted SCIM Group membership exceeds the server limit",
    );
    const withoutMembers = await read("staff", { attributes: "displayName" }, "group-reader");
    expect(withoutMembers.status).toBe(200);
    expect(await withoutMembers.json()).toEqual({
      schemas: expected.schemas,
      id: "staff",
      displayName: "Staff",
    });
    expect(await (await control("drift-read-binding")).json()).toEqual({ changed: true });
    const changed = await read("staff", {}, "group-reader");
    expect(changed.status).toBe(409);
    expect(((await changed.json()) as any).detail).toBe(
      "The connection provisioningDomainId changed after the connection was first used",
    );
    expect(await (await control("retire-read-binding")).json()).toEqual({ retired: true });
    const retired = await read("staff", {}, "group-reader");
    expect(retired.status).toBe(401);
    expect(((await retired.json()) as any).detail).toBe("SCIM connection is decommissioned");

    return { authenticated: true, isolated: true, projected: true, http: true };
  },
);
