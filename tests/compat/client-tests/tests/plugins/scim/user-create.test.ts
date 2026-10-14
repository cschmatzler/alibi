import { expect } from "bun:test";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "SCIM User creation persists canonical identity and reuses tombstones",
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
      userName: " Alice@example.com ",
      externalId: "directory-alice",
      name: { givenName: " Alice ", familyName: " Example " },
      emails: [
        { value: "personal@example.com", type: "home" },
        { value: "Work@example.com", type: "WORK" },
      ],
      title: [" Engineer "],
    };
    expect((await control("createSCIMUser", { body: input })).status).toBe(401);
    expect((await control("createSCIMUser", { body: input, token: "users-reader" })).status).toBe(
      403,
    );
    const created = await control("createSCIMUser", { body: input, token: "group-reader" });
    expect(created.status).toBe(201);
    const resource = (await created.json()) as any;
    expect(resource.userName).toBe("Alice@example.com");
    expect(resource.displayName).toBe("Alice Example");
    expect(resource.emails[1].primary).toBe(true);
    expect(resource.title).toBe("Engineer");
    expect(resource.active).toBe(true);
    const duplicate = await control("createSCIMUser", { body: input, token: "group-reader" });
    expect(duplicate.status).toBe(409);
    expect(((await duplicate.json()) as any).scimType).toBe("uniqueness");

    const state = (await (await control("user-create-state")).json()) as any;
    expect(state).toMatchObject({
      users: [{ email: "work@example.com", name: "Alice Example", emailVerified: false }],
      sources: 1,
      subjects: 1,
      tombstones: 0,
    });
    for (const body of [
      { ...input, userName: "Other", emails: [{ value: "other@example.com" }] },
      { ...input, userName: "Other", externalId: "other" },
    ]) {
      const collision = await control("createSCIMUser", { body, token: "group-reader" });
      expect(collision.status).toBe(409);
      expect(((await collision.json()) as any).scimType).toBe("uniqueness");
    }
    expect((await control("configure-group-create-projection")).status).toBe(200);
    expect((await control("group-create-projection-fails")).status).toBe(200);
    const failed = await control("createSCIMUser", {
      body: { schemas: input.schemas, userName: "rolled-back@example.com" },
      token: "group-reader",
    });
    expect(failed.status).toBe(500);
    expect(await (await control("user-create-state")).json()).toEqual(state);
    const deleted = await control("deleteSCIMUser", {
      params: { userId: resource.id },
      token: "group-reader",
    });
    expect(deleted.status).toBe(500);
    expect(await (await control("user-create-state")).json()).toEqual(state);
    expect((await control("group-create-projection-fails", { fail: false })).status).toBe(200);
    expect(
      (await control("deleteSCIMUser", { params: { userId: resource.id }, token: "group-reader" }))
        .status,
    ).toBe(204);
    const retired = (await (await control("user-create-state")).json()) as any;
    expect(retired).toMatchObject({ sources: 0, subjects: 1, tombstones: 1 });
    expect(retired.users[0].id).toBe(state.users[0].id);
    const restored = await control("createSCIMUser", {
      body: { ...input, emails: [{ value: "new-work@example.com", type: "work" }] },
      token: "group-reader",
    });
    expect(restored.status).toBe(201);
    const replacement = (await restored.json()) as any;
    expect(replacement.id).not.toBe(resource.id);
    expect(replacement.emails[0].value).toBe("new-work@example.com");
    const revived = (await (await control("user-create-state")).json()) as any;
    expect(revived).toMatchObject({
      sources: 1,
      subjects: 1,
      tombstones: 0,
      users: [{ email: "new-work@example.com", name: "Projected active", emailVerified: false }],
    });
    expect(revived.users[0].id).toBe(state.users[0].id);
    const http = await actor.fetch(`${ctx.baseURL}/__test/profiles/scim/api/auth/scim/v2/Users`, {
      method: "POST",
      headers: { authorization: "Bearer group-reader", "content-type": "application/scim+json" },
      body: JSON.stringify({ schemas: input.schemas, userName: "http@example.com", active: false }),
    });
    expect(http.status).toBe(201);
    expect(((await http.json()) as any).active).toBe(false);

    expect((await control("configure-user-create")).status).toBe(200);
    const alias = {
      schemas: input.schemas,
      userName: " Alias ",
      emails: [{ value: "Alias@example.com" }],
    };
    for (const [externalId, status, detail] of [
      ["resolve-fails", 500, "SCIM identity resolution failed"],
      ["link-missing", 409, "The resolved Better Auth User does not exist"],
      ["link-manage", 409, "Another SCIM source already manages this User profile"],
    ] as const) {
      const denied = await control("createSCIMUser", {
        body: { ...alias, externalId },
        token: "other-reader",
      });
      expect(denied.status).toBe(status);
      expect(((await denied.json()) as any).detail).toBe(detail);
    }
    const linked = await control("createSCIMUser", {
      body: { ...alias, externalId: "link-preserve" },
      token: "other-reader",
    });
    expect(linked.status).toBe(201);
    expect(((await linked.json()) as any).userName).toBe("Alias");
    const linkedState = (await (await control("user-create-state")).json()) as any;
    expect(linkedState).toMatchObject({ sources: 3, subjects: 2, tombstones: 0 });
    expect(linkedState.users).toHaveLength(2);
    expect(linkedState.users.find((user: any) => user.id === state.users[0].id).email).toBe(
      "new-work@example.com",
    );
    const repeated = await control("createSCIMUser", {
      body: { ...alias, userName: "Alias2", externalId: "link-preserve-2" },
      token: "other-reader",
    });
    expect(repeated.status).toBe(409);
    expect(((await repeated.json()) as any).detail).toBe(
      "This connection already provisions the resolved Better Auth User",
    );
    return { created: true, tombstones: true, rollback: true, resolution: true };
  },
);
