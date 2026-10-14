import { expect } from "bun:test";

import { compatScenario } from "../../../support/scenario";
compatScenario("SCIM User PATCH handles noops and ordered canonical changes", async (ctx) => {
  const actor = ctx.actor();
  const control = (operation: string, input: unknown = {}) =>
    actor.fetch(`${ctx.baseURL}/__test/server-api/scim?operation=${operation}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(input),
    });
  const patch = (userId: string, Operations: unknown, token?: string) =>
    control("patchSCIMUser", {
      params: { userId },
      body: { schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], Operations },
      ...(token === undefined ? {} : { token }),
    });
  expect((await patch("missing", [])).status).toBe(401);
  const initialResponse = await control("createSCIMUser", {
    token: "group-reader",
    body: {
      schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
      userName: "alice@example.com",
      externalId: "old-external",
      name: { givenName: "Alice", familyName: "Example" },
      emails: [
        { value: "work@example.com", type: "work" },
        { value: "home@example.com", type: "home" },
      ],
    },
  });
  expect(initialResponse.status).toBe(201);
  const initial = (await initialResponse.json()) as any;
  expect((await patch(initial.id, [], "users-reader")).status).toBe(403);
  expect((await patch(initial.id, [], "other-reader")).status).toBe(404);
  expect((await control("configure-group-create-projection")).status).toBe(200);
  expect((await control("group-create-projection-fails")).status).toBe(200);
  for (const operations of [[], [{ path: "active", value: true }]]) {
    const noop = await patch(initial.id, operations, "group-reader");
    expect(noop.status).toBe(200);
    expect(await noop.json()).toEqual(initial);
  }
  const subject = (await (await control("user-replace-state")).json()) as any;
  expect(subject.subjects[0].revision).toBe(4);
  const changed = [
    { path: 'emails[type eq "work"].value', value: "new-work@example.com" },
    { op: "add", path: "name", value: { givenName: ["New"] } },
    { path: "name.formatted", value: "New Name" },
    { op: "add", path: "roles", value: [{ value: "admin", type: "access", primary: true }] },
    {
      path: "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:manager",
      value: [{ value: "manager-id" }],
    },
    { path: "active", value: [false] },
    { op: "remove", path: "externalId" },
    { path: "title", value: [" Principal "] },
  ];
  const before = await (await control("user-create-state")).json();
  const failed = await patch(initial.id, changed, "group-reader");
  expect(failed.status).toBe(500);
  expect(await (await control("user-create-state")).json()).toEqual(before);
  expect(await (await control("user-replace-state")).json()).toEqual(subject);
  expect((await control("group-create-projection-fails", { fail: false })).status).toBe(200);
  const response = await patch(initial.id, changed, "group-reader");
  expect(response.status).toBe(200);
  const value = (await response.json()) as any;
  expect(value.displayName).toBe("New Name");
  expect(value.name.givenName).toBe("New");
  expect(value.title).toBe("Principal");
  expect(value.roles[0].value).toBe("admin");
  expect(value["urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"].manager).toEqual({
    value: "manager-id",
  });
  expect(value.active).toBe(false);
  expect(value.externalId).toBeUndefined();

  const extras = [
    { op: "replace", path: 'roles[type eq "access"]', value: { value: "editor" } },
    { path: "roles[primary eq true].display", value: "Editor" },
    { op: "add", path: "phoneNumbers", value: { value: "+1", type: "work", primary: true } },
    { op: "add", path: 'phoneNumbers[type eq "home"].value', value: "+2" },
    { path: 'phoneNumbers[type eq "home"].primary', value: true },
    { op: "remove", path: 'phoneNumbers[type eq "work"]' },
    { op: "remove", path: 'roles[type eq "missing"]' },
    {
      op: "add",
      path: "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User",
      value: {
        employeeNumber: ["42"],
        manager: { displayName: "Ignored", $ref: "https://idp.example/manager" },
      },
    },
    { op: "remove", path: "manager.value" },
    { op: "remove", path: "active" },
    {
      op: "add",
      path: "emails",
      value: [{ value: "primary@example.com", type: "other", primary: true }],
    },
    { path: 'emails[primary eq "true"].value', value: "promoted@example.com" },
    { op: "remove", path: 'emails[type eq "home"].value' },
  ];
  const complex = await patch(initial.id, extras, "group-reader");
  expect(complex.status).toBe(200);
  const updated = (await complex.json()) as any;
  expect(updated.roles).toEqual([
    { value: "editor", display: "Editor", type: "access", primary: true },
  ]);
  expect(updated.phoneNumbers).toEqual([{ value: "+2", type: "home", primary: true }]);
  expect(updated.emails).toEqual([
    { value: "new-work@example.com", type: "work", primary: false },
    { value: "promoted@example.com", type: "other", primary: true },
  ]);
  expect(updated.active).toBe(true);
  expect(updated["urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"]).toEqual({
    employeeNumber: "42",
    manager: { $ref: "https://idp.example/manager" },
  });
  for (const [operations, detail, kind] of [
    [[{ op: "remove", path: "emails" }], "emails cannot be removed", "invalidValue"],
    [[{ op: "remove" }], "A remove User PATCH operation requires a path", "noTarget"],
    [[{ path: "id", value: "other" }], "id is read-only", "mutability"],
    [
      [{ path: "unsupported", value: 1 }],
      "User PATCH path unsupported is not supported",
      "invalidPath",
    ],
    [[{ path: "active", value: "false" }], "active must be a boolean", "invalidValue"],
  ] as const) {
    const rejected = await patch(initial.id, operations, "group-reader");
    expect(rejected.status).toBe(400);
    expect(await rejected.json()).toMatchObject({ detail, scimType: kind });
  }
  const http = await actor.fetch(
    `${ctx.baseURL}/__test/profiles/scim/api/auth/scim/v2/Users/${initial.id}`,
    {
      method: "PATCH",
      headers: { authorization: "Bearer group-reader", "content-type": "application/scim+json" },
      body: JSON.stringify({
        schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        Operations: [{ path: "active", value: false }],
      }),
    },
  );
  expect(http.status).toBe(200);
  expect(((await http.json()) as any).active).toBe(false);
  return { patched: true, noops: true, rollback: true, multivalue: true };
});
