import { expect } from "bun:test";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "SCIM User replacement preserves identity and replaces managed profile",
  async (ctx) => {
    const actor = ctx.actor();
    const control = (operation: string, input: unknown = {}) =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/scim?operation=${operation}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(input),
      });
    const input = {
      schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
      userName: "new@example.com",
      displayName: "New Name",
      active: false,
    };
    const replace = (userId: string, body: unknown, token?: string) =>
      control("replaceSCIMUser", {
        params: { userId },
        body,
        ...(token === undefined ? {} : { token }),
      });
    expect((await replace("missing", input)).status).toBe(401);
    const created = await control("createSCIMUser", {
      body: {
        schemas: input.schemas,
        userName: "old@example.com",
        externalId: "old-external",
        name: { givenName: "Old", familyName: "Name" },
        roles: [{ value: "admin" }],
      },
      token: "group-reader",
    });
    expect(created.status).toBe(201);
    const initial = (await created.json()) as any;
    expect((await replace(initial.id, input, "users-reader")).status).toBe(403);
    expect((await replace(initial.id, input, "other-reader")).status).toBe(404);
    expect((await control("prepare-user-replace", { id: initial.id })).status).toBe(200);
    expect(((await (await control("user-replace-state")).json()) as any).sessions).toBe(1);
    const response = await replace(initial.id, input, "group-reader");
    expect(response.status).toBe(200);
    const value = (await response.json()) as any;
    expect(value.id).toBe(initial.id);
    expect(value.userName).toBe("new@example.com");
    expect(value.displayName).toBe("New Name");
    expect(value.name).toEqual({ formatted: "New Name" });
    expect(value.externalId).toBeUndefined();
    expect(value.roles).toBeUndefined();
    expect(value.active).toBe(false);
    expect(value.meta.created).toBe(initial.meta.created);
    const state = (await (await control("user-create-state")).json()) as any;
    expect(state).toMatchObject({
      users: [{ email: "new@example.com", name: "New Name", emailVerified: false }],
      sources: 1,
      subjects: 1,
      tombstones: 0,
    });

    for (const [email, total] of [
      ["new@example.com", 1],
      ["old@example.com", 0],
    ] as const) {
      const listed = await control("listSCIMUsers", {
        query: { filter: `emails.value eq "${email}"` },
        token: "group-reader",
      });
      expect(listed.status).toBe(200);
      expect(((await listed.json()) as any).totalResults).toBe(total);
    }
    const identity = (await (await control("user-replace-state")).json()) as any;
    expect(identity).toEqual({
      sessions: 0,
      subjects: [{ revision: 3, profileSourceId: initial.id }],
    });
    expect((await control("configure-group-create-projection")).status).toBe(200);
    expect((await control("group-create-projection-fails")).status).toBe(200);
    const failed = await replace(
      initial.id,
      { ...input, userName: "rolled-back@example.com", active: true },
      "group-reader",
    );
    expect(failed.status).toBe(500);
    expect(((await failed.json()) as any).detail).toBe("SCIM projection reconciliation failed");
    expect(await (await control("user-create-state")).json()).toEqual(state);
    expect(await (await control("user-replace-state")).json()).toEqual(identity);
    expect((await control("group-create-projection-fails", { fail: false })).status).toBe(200);
    expect((await control("detach-user-profile", { id: initial.id })).status).toBe(200);
    const http = await actor.fetch(
      `${ctx.baseURL}/__test/profiles/scim/api/auth/scim/v2/Users/${initial.id}`,
      {
        method: "PUT",
        headers: { authorization: "Bearer group-reader", "content-type": "application/scim+json" },
        body: JSON.stringify({
          schemas: input.schemas,
          userName: "preserved@example.com",
          displayName: "Provider name",
        }),
      },
    );
    expect(http.status).toBe(200);
    const preserved = (await http.json()) as any;
    expect(preserved.active).toBe(true);
    expect(preserved.displayName).toBe("Provider name");
    expect(preserved.emails[0].value).toBe("preserved@example.com");
    expect(await (await control("user-create-state")).json()).toMatchObject({
      users: [{ email: "new@example.com", name: "Projected active" }],
      sources: 1,
      subjects: 1,
      tombstones: 0,
    });
    expect(
      (
        await control("createSCIMUser", {
          body: { schemas: input.schemas, userName: "other@example.com", externalId: "collision" },
          token: "group-reader",
        })
      ).status,
    ).toBe(201);
    for (const [body, detail] of [
      [
        { schemas: input.schemas, userName: "OTHER@example.com" },
        "SCIM User userName already exists",
      ],
      [
        { schemas: input.schemas, userName: "unique@example.com", externalId: "collision" },
        "SCIM User externalId already exists",
      ],
    ] as const) {
      const denied = await replace(initial.id, body, "group-reader");
      expect(denied.status).toBe(409);
      const failure = (await denied.json()) as any;
      expect(failure.detail).toBe(detail);
      expect(failure.scimType).toBe("uniqueness");
    }
    expect((await control("drift-user-replace", { id: initial.id })).status).toBe(200);
    expect((await replace(initial.id, input, "group-reader")).status).toBe(409);
    return { replaced: true, rollback: true, profileOwnership: true };
  },
);
