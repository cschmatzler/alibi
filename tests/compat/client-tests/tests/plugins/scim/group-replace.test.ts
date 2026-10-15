import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "SCIM Group replacement preserves retained members and clears omitted fields",
  async (ctx) => {
    const actor = ctx.actor();
    const control = (operation: string, input: unknown = {}) =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/scim?operation=${operation}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(input),
      });
    const replace = (id: string, body: unknown, query: unknown = {}, token?: string) =>
      control("replaceSCIMGroup", {
        params: { groupId: id },
        body,
        query,
        ...(token === undefined ? {} : { token }),
      });
    const create = (body: unknown) =>
      control("createSCIMGroup", { body, query: {}, token: "group-reader" });
    const schema = "urn:ietf:params:scim:schemas:core:2.0:Group";
    const update = {
      schemas: [schema],
      displayName: " Renamed ",
      members: [{ value: "member-c" }],
    };
    expect((await replace("missing", update)).status).toBe(401);
    expect(await (await control("seed-group-create")).json()).toEqual({ seeded: true });
    const initial = (await (
      await create({
        schemas: [schema],
        displayName: "Original",
        externalId: "old-external",
        members: [{ value: "member-a" }, { value: "member-c" }],
      })
    ).json()) as any;
    const memberships = (await (
      await control("group-replace-members", { id: initial.id })
    ).json()) as any[];
    const retained = memberships.find((member) => member.scimUserId === "member-c");
    expect((await replace(initial.id, update, {}, "users-reader")).status).toBe(403);
    expect((await replace(initial.id, update, {}, "other-reader")).status).toBe(404);
    const renamed = await replace(initial.id, update, {}, "group-reader");
    expect(renamed.status).toBe(200);
    const value = (await renamed.json()) as any;
    expect(value.id).toBe(initial.id);
    expect(value.displayName).toBe("Renamed");
    expect(value.externalId).toBeUndefined();
    expect(value.members.map((member: any) => member.value)).toEqual(["member-c"]);
    expect(value.meta.created).toBe(initial.meta.created);
    expect(renamed.headers.get("content-location")).toBeNull();
    expect(await (await control("group-replace-members", { id: initial.id })).json()).toEqual([
      retained,
    ]);
    expect(
      (await create({ schemas: [schema], displayName: "Occupied", externalId: "taken" })).status,
    ).toBe(201);
    const state = await (await control("group-create-state")).json();
    for (const [body, status, detail] of [
      [
        { schemas: [schema], displayName: "OCCUPIED" },
        409,
        "SCIM Group displayName already exists",
      ],
      [
        { schemas: [schema], displayName: "Else", externalId: "taken" },
        409,
        "SCIM Group externalId already exists",
      ],
      [
        { schemas: [schema], displayName: "Invalid", members: [{ value: "member-b" }] },
        400,
        "One or more Group members are invalid",
      ],
    ] as const) {
      const failure = await replace(initial.id, body, {}, "group-reader");
      expect(failure.status).toBe(status);
      expect(((await failure.json()) as any).detail).toBe(detail);
      expect(await (await control("group-create-state")).json()).toEqual(state);
    }
    expect(await (await control("configure-group-create-projection")).json()).toEqual({
      configured: true,
    });
    expect(await (await control("group-create-projection-fails")).json()).toEqual({
      failing: true,
    });
    const input = {
      schemas: [schema],
      displayName: "Callback success",
      members: [{ value: "member-a" }],
    };
    const failed = await replace(initial.id, input, {}, "group-reader");
    expect(failed.status).toBe(500);
    expect(((await failed.json()) as any).detail).toBe("SCIM projection reconciliation failed");
    expect(await (await control("group-create-state")).json()).toEqual(state);
    expect(await (await control("group-replace-members", { id: initial.id })).json()).toEqual([
      retained,
    ]);
    expect(await (await control("group-create-projection-fails", { fail: false })).json()).toEqual({
      failing: false,
    });
    const projected = await replace(
      initial.id,
      input,
      { attributes: "displayName" },
      "group-reader",
    );
    expect(projected.status).toBe(200);
    const selected = (await projected.json()) as any;
    expect(selected.displayName).toBe("Callback success");
    expect(selected.members).toBeUndefined();
    expect(await (await control("group-create-owner")).json()).toEqual({
      name: "Projected inactive",
    });
    const http = await actor.fetch(
      `${ctx.baseURL}/__test/profiles/scim/api/auth/scim/v2/Groups/${initial.id}`,
      {
        method: "PUT",
        headers: { authorization: "Bearer group-reader", "content-type": "application/scim+json" },
        body: JSON.stringify({ schemas: [schema], displayName: "HTTP replaced" }),
      },
    );
    expect(http.status).toBe(200);
    const replaced = (await http.json()) as any;
    expect(replaced.displayName).toBe("HTTP replaced");
    expect(replaced.members).toEqual([]);
    expect(await (await control("group-replace-members", { id: initial.id })).json()).toEqual([]);
    expect(await (await control("drift-created-group", { id: initial.id })).json()).toEqual({
      changed: true,
    });
    expect((await replace(initial.id, update, {}, "group-reader")).status).toBe(409);
    return { replaced: true, retained: true, cleared: true, callbackRollback: true };
  },
);
