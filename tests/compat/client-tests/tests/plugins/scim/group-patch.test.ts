import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "SCIM Group PATCH handles noops nulls and transactional member changes",
  async (ctx) => {
    const actor = ctx.actor();
    const control = (operation: string, input: unknown = {}) =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/scim?operation=${operation}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(input),
      });
    const patch = (id: string, Operations: unknown, token?: string) =>
      control("patchSCIMGroup", {
        params: { groupId: id },
        body: { schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], Operations },
        ...(token === undefined ? {} : { token }),
      });
    expect((await patch("missing", [])).status).toBe(401);
    expect(await (await control("seed-group-create")).json()).toEqual({ seeded: true });
    const initial = (await (
      await control("createSCIMGroup", {
        body: {
          schemas: ["urn:ietf:params:scim:schemas:core:2.0:Group"],
          displayName: "Original",
          externalId: "old-external",
          members: [{ value: "member-a" }, { value: "member-c" }],
        },
        query: {},
        token: "group-reader",
      })
    ).json()) as any;
    expect((await patch(initial.id, [], "users-reader")).status).toBe(403);
    expect((await patch(initial.id, [], "other-reader")).status).toBe(404);
    expect(await (await control("configure-group-create-projection")).json()).toEqual({
      configured: true,
    });
    expect(await (await control("group-create-projection-fails")).json()).toEqual({
      failing: true,
    });
    for (const operations of [
      [],
      [
        { op: "ADD", path: "members", value: [{ value: "member-a" }] },
        { op: "remove", path: 'members[value eq "missing-member"]' },
      ],
    ]) {
      const noop = await patch(initial.id, operations, "group-reader");
      expect(noop.status).toBe(200);
      expect(await noop.json()).toEqual(initial);
    }
    const state = (await (await control("group-create-state")).json()) as any;
    expect(state.subject.revision).toBe(2);
    const contradictory = await patch(
      initial.id,
      [
        { op: "add", path: "members", value: [{ value: "member-b" }] },
        { op: "remove", path: "members", value: [{ value: "member-b" }] },
      ],
      "group-reader",
    );
    expect(contradictory.status).toBe(400);
    expect(((await contradictory.json()) as any).detail).toBe(
      "One or more Group members are invalid",
    );
    const mixed = [
      {
        value: {
          id: initial.id,
          schemas: [],
          meta: null,
          displayName: [" Renamed "],
          members: [{ value: "member-a", type: 123 }],
        },
      },
      { op: "remove", path: "externalId" },
    ];
    const failed = await patch(initial.id, mixed, "group-reader");
    expect(failed.status).toBe(500);
    expect(((await failed.json()) as any).detail).toBe("SCIM projection reconciliation failed");
    expect(await (await control("group-create-state")).json()).toEqual(state);
    expect(await (await control("group-create-projection-fails", { fail: false })).json()).toEqual({
      failing: false,
    });
    const changed = await patch(initial.id, mixed, "group-reader");
    expect(changed.status).toBe(200);
    const value = (await changed.json()) as any;
    expect(value.displayName).toBe("Renamed");
    expect(value.externalId).toBeUndefined();
    expect(value.members.map((member: any) => member.value)).toEqual(["member-a"]);
    for (const [Operations, detail, kind] of [
      [
        [{ op: "remove", path: "displayName" }],
        "displayName is required and cannot be removed",
        "mutability",
      ],
      [[{ op: "replace", path: "id", value: "other" }], "id is read-only", "mutability"],
      [[{ op: "remove" }], "A pathless remove operation has no target", "noTarget"],
      [[{ value: 12 }], "A pathless Group PATCH value must be an object", "invalidValue"],
      [[{ path: "unknown", value: "value" }], "Unsupported Group PATCH path", "invalidPath"],
      [
        [{ op: "remove", path: 'memberſ[value eq "member-a"]' }],
        "Unsupported Group PATCH path",
        "invalidPath",
      ],
      [
        [{ path: "externalId", value: null }],
        "externalId must be a non-empty string",
        "invalidValue",
      ],
      [[{ path: "members", value: null }], "members must be an array", "invalidValue"],
    ] as const) {
      const denied = await patch(initial.id, Operations, "group-reader");
      expect(denied.status).toBe(400);
      const error = (await denied.json()) as any;
      expect(error.detail).toBe(detail);
      expect(error.scimType).toBe(kind);
    }
    const removed = await patch(
      initial.id,
      [
        {
          op: "remove",
          path: 'urn:ietf:params:scim:schemas:core:2.0:Group:members\uFEFF[ value eq "member-a"]',
        },
      ],
      "group-reader",
    );
    expect(removed.status).toBe(200);
    expect(((await removed.json()) as any).members).toEqual([]);
    const http = await actor.fetch(
      `${ctx.baseURL}/__test/profiles/scim/api/auth/scim/v2/Groups/${initial.id}`,
      {
        method: "PATCH",
        headers: { authorization: "Bearer group-reader", "content-type": "application/scim+json" },
        body: JSON.stringify({
          schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
          Operations: [{ op: "ADD", path: "members", value: [{ value: "member-a" }] }],
        }),
      },
    );
    expect(http.status).toBe(200);
    expect(((await http.json()) as any).members[0].value).toBe("member-a");
    const cleared = await patch(initial.id, [{ op: "remove", path: "members" }], "group-reader");
    expect(cleared.status).toBe(200);
    expect(((await cleared.json()) as any).members).toEqual([]);
    expect(await (await control("drift-created-group", { id: initial.id })).json()).toEqual({
      changed: true,
    });
    expect((await patch(initial.id, [], "group-reader")).status).toBe(409);
    return { patched: true, noops: true, nulls: true, rollback: true };
  },
);
