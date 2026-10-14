import { expect } from "bun:test";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "SCIM Group creation persists members and rolls back invalid ownership",
  async (ctx) => {
    const actor = ctx.actor();
    const control = (operation: string, input: unknown = {}) =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/scim?operation=${operation}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(input),
      });
    const create = (body: unknown, query: unknown = {}, token?: string) =>
      control("createSCIMGroup", { body, query, ...(token === undefined ? {} : { token }) });
    const schema = "urn:ietf:params:scim:schemas:core:2.0:Group";
    const input = {
      schemas: [schema],
      displayName: " Staff ",
      externalId: "external-staff",
      members: [{ value: "member-a" }, { value: "member-a", type: "USER" }, { value: "member-c" }],
    };
    for (const body of [{}, { schemas: [schema], displayName: " " }]) {
      expect((await create(body)).status).toBe(400);
    }
    const whitespaceMember = {
      schemas: [schema],
      displayName: "Whitespace",
      members: [{ value: " " }],
    };
    expect((await create(whitespaceMember)).status).toBe(401);
    const whitespace = await create(whitespaceMember, {}, "group-reader");
    expect(whitespace.status).toBe(400);
    expect(((await whitespace.json()) as any).detail).toBe(
      "Group members must reference a SCIM User",
    );
    expect((await create(input)).status).toBe(401);
    expect((await create(input, {}, "users-reader")).status).toBe(403);
    expect(await (await control("seed-group-create")).json()).toEqual({ seeded: true });
    const response = await create(input, {}, "group-reader");
    expect(response.status).toBe(201);
    const resource = (await response.json()) as any;
    expect(resource.displayName).toBe("Staff");
    expect(resource.externalId).toBe("external-staff");
    expect(resource.members.map((member: any) => member.value)).toEqual(["member-a", "member-c"]);
    expect(response.headers.get("location")).toBe(
      `${ctx.baseURL}/__test/profiles/scim/api/auth/scim/v2/Groups/${resource.id}`,
    );
    expect(response.headers.get("content-location")).toBe(response.headers.get("location"));
    const state = await (await control("group-create-state")).json();
    for (const [body, status, detail] of [
      [{ schemas: [schema], displayName: "STAFF" }, 409, "SCIM Group displayName already exists"],
      [
        { schemas: [schema], displayName: "Second", externalId: "external-staff" },
        409,
        "SCIM Group externalId already exists",
      ],
      [
        { schemas: [schema], displayName: "Invalid", members: [{ value: "member-b" }] },
        400,
        "One or more Group members are invalid",
      ],
    ] as const) {
      const denied = await create(body, {}, "group-reader");
      expect(denied.status).toBe(status);
      expect(((await denied.json()) as any).detail).toBe(detail);
      expect(await (await control("group-create-state")).json()).toEqual(state);
    }
    const foreign = await create(
      { schemas: [schema], displayName: "Staff", externalId: "external-staff" },
      {},
      "other-reader",
    );
    expect(foreign.status).toBe(201);
    expect(((await foreign.json()) as any).members).toEqual([]);
    const projected = await create(
      { schemas: [schema], displayName: "Projected", members: [{ value: "member-a" }] },
      { attributes: "displayName" },
      "group-reader",
    );
    expect(projected.status).toBe(201);
    const value = (await projected.json()) as any;
    expect(value.members).toBeUndefined();
    expect(value.meta).toBeUndefined();
    const read = await control("getSCIMGroup", {
      params: { groupId: value.id },
      query: {},
      token: "group-reader",
    });
    expect(read.status).toBe(200);
    expect(((await read.json()) as any).members[0].value).toBe("member-a");
    const http = await actor.fetch(`${ctx.baseURL}/__test/profiles/scim/api/auth/scim/v2/Groups`, {
      method: "POST",
      headers: { authorization: "Bearer group-reader", "content-type": "application/scim+json" },
      body: JSON.stringify({ schemas: [schema], displayName: "HTTP group" }),
    });
    expect(http.status).toBe(201);
    expect(((await http.json()) as any).displayName).toBe("HTTP group");
    expect(http.headers.get("content-type")).toBe("application/scim+json");
    expect(await (await control("configure-group-create-projection")).json()).toEqual({
      configured: true,
    });
    const callbackBody = {
      schemas: [schema],
      displayName: "Callback success",
      members: [{ value: "member-a" }],
    };
    expect((await create(callbackBody, {}, "group-reader")).status).toBe(201);
    expect(await (await control("group-create-owner")).json()).toEqual({
      name: "Projected inactive",
    });
    const beforeFailure = await (await control("group-create-state")).json();
    expect(await (await control("group-create-projection-fails")).json()).toEqual({
      failing: true,
    });
    const callbackFailure = await create(
      { ...callbackBody, displayName: "Callback failure" },
      {},
      "group-reader",
    );
    expect(callbackFailure.status).toBe(500);
    expect(((await callbackFailure.json()) as any).detail).toBe(
      "SCIM projection reconciliation failed",
    );
    expect(await (await control("group-create-state")).json()).toEqual(beforeFailure);
    expect(await (await control("group-create-owner")).json()).toEqual({
      name: "Projected inactive",
    });
    expect(await (await control("drift-created-group", { id: resource.id })).json()).toEqual({
      changed: true,
    });
    expect(
      (await create({ schemas: [schema], displayName: "After drift" }, {}, "group-reader")).status,
    ).toBe(409);
    return { created: true, isolated: true, rollback: true, projection: true };
  },
);
