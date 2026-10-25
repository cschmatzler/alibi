import { expect } from "vitest";

import type { ScenarioContext } from "../../../support/scenario";
import { compatScenario } from "../../../support/scenario";

const USER = "urn:ietf:params:scim:schemas:core:2.0:User";
const GROUP = "urn:ietf:params:scim:schemas:core:2.0:Group";
const ENTERPRISE = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";
const PATCH = "urn:ietf:params:scim:api:messages:2.0:PatchOp";

function client(ctx: ScenarioContext) {
  const actor = ctx.actor();
  const base = `${ctx.baseURL}/__test/profiles/scim/api/auth/scim/v2`;
  const send = async (method: string, path: string, body?: unknown, token = "group-reader") => {
    const response = await actor.fetch(`${base}/${path}`, {
      method,
      headers: {
        authorization: `Bearer ${token}`,
        ...(body === undefined ? {} : { "content-type": "application/scim+json" }),
      },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    const text = await response.text();
    return { status: response.status, resource: (text ? JSON.parse(text) : null) as any };
  };
  const patch = (path: string, Operations: unknown[]) =>
    send("PATCH", path, { schemas: [PATCH], Operations });
  return { send, patch };
}

compatScenario("SCIM HTTP requests match attribute names case-insensitively", async (ctx) => {
  const { send, patch } = client(ctx);
  const observed: unknown[] = [];
  const userName = ctx.uniqueEmail("case-user");
  const created = await send("POST", "Users", {
    schemas: [USER, ENTERPRISE],
    UserName: userName,
    Name: { GivenName: "Ada", FamilyName: "Lovelace" },
    Emails: [{ Value: userName, Type: "work", Primary: true }],
    Addresses: [{ Type: "work", Locality: "London" }],
    Title: "Engineer",
    "URN:IETF:PARAMS:SCIM:SCHEMAS:EXTENSION:ENTERPRISE:2.0:USER": {
      Department: "R&D",
      Manager: { Value: "manager-1" },
    },
  });
  expect(created.status, JSON.stringify(created.resource)).toBe(201);
  expect(created.resource.addresses).toEqual([{ type: "work", locality: "London" }]);
  expect(created.resource[ENTERPRISE]).toEqual({
    department: "R&D",
    manager: { value: "manager-1" },
  });
  observed.push(created);
  const id = created.resource.id;
  const deactivated = await send("PUT", `Users/${id}`, {
    schemas: [USER],
    userName,
    Active: false,
  });
  expect(deactivated.status).toBe(200);
  expect(deactivated.resource.active).toBe(false);
  observed.push(deactivated);
  for (const [method, body] of [
    ["PUT", { schemas: [USER], userName, Active: null }],
    ["PUT", { schemas: [USER], userName, active: false, Active: true }],
    ["PATCH", { schemas: [PATCH], Operations: [{ op: "Replace", value: { title: "A", Title: "B" } }] }],
    [
      "PATCH",
      {
        schemas: [PATCH],
        Operations: [{ op: "Add", path: "emails", value: [{ value: userName, Value: userName }] }],
      },
    ],
  ] as const) {
    const rejected = await send(method, `Users/${id}`, body);
    expect(rejected.status).toBe(400);
    observed.push(rejected);
  }
  // Duplicate keys are rejected before authentication.
  const unauthenticated = await send(
    "POST",
    "Users",
    { schemas: [USER], userName, USERNAME: userName },
    "missing-token",
  );
  expect(unauthenticated.status).toBe(400);
  observed.push(unauthenticated);
  const patched = await patch(`Users/${id}`, [
    { op: "Replace", value: { Title: "Countess", Active: true } },
    { op: "Replace", path: 'addresses[type eq "work"]', value: { Country: "FR" } },
    { op: "Replace", path: "emails", value: [{ Value: userName, Primary: true }] },
    { op: "Replace", value: { enterprise: { Department: "Finance" } } },
    { op: "Replace", value: { manager: { Value: "manager-2" } } },
    { op: "Replace", value: { [`${ENTERPRISE}:costCenter`]: "CC-1", "name.GivenName": "Augusta" } },
  ]);
  expect(patched.status, JSON.stringify(patched.resource)).toBe(200);
  expect(patched.resource.title).toBe("Countess");
  expect(patched.resource.addresses).toEqual([{ type: "work", locality: "London", country: "FR" }]);
  expect(patched.resource[ENTERPRISE]).toEqual({
    department: "Finance",
    costCenter: "CC-1",
    manager: { value: "manager-2" },
  });
  observed.push(patched);
  const member = await send("POST", "Users", { schemas: [USER], userName: ctx.uniqueEmail("m") });
  expect(member.status).toBe(201);
  const group = await send("POST", "Groups", {
    schemas: [GROUP],
    DisplayName: `Case ${ctx.uniqueToken("group")}`,
    Members: [{ Value: id, Type: "User" }],
  });
  expect(group.status, JSON.stringify(group.resource)).toBe(201);
  observed.push(group);
  const grown = await patch(`Groups/${group.resource.id}`, [
    { op: "Add", path: "members", value: [{ Value: member.resource.id }] },
  ]);
  expect(grown.status, JSON.stringify(grown.resource)).toBe(200);
  expect(grown.resource.members.map((entry: any) => entry.value).sort()).toEqual(
    [id, member.resource.id].sort(),
  );
  observed.push(grown);
  return observed;
});

compatScenario("SCIM HTTP requests treat JSON null as an unassigned attribute", async (ctx) => {
  const { send, patch } = client(ctx);
  const observed: unknown[] = [];
  const userName = ctx.uniqueEmail("null-user");
  const full = {
    schemas: [USER, ENTERPRISE],
    userName,
    externalId: ctx.uniqueToken("null-external"),
    title: "Engineer",
    name: { formatted: "Ada Lovelace", givenName: "Ada", familyName: "Lovelace", middleName: "C" },
    emails: [{ value: userName, type: "work", primary: true }],
    addresses: [
      { type: "work", streetAddress: "1 Main St", country: "GB" },
      { type: "home", locality: "Bath", region: "Somerset" },
    ],
    [ENTERPRISE]: { department: "R&D", manager: { value: "manager-1", displayName: "Charles" } },
  };
  const entra = await send("POST", "Users", {
    schemas: [USER],
    userName: ctx.uniqueEmail("entra"),
    active: true,
    addresses: null,
    phoneNumbers: null,
    preferredLanguage: null,
    title: null,
    meta: { resourceType: "User" },
    name: { familyName: "Young", givenName: "Joy", middleName: null },
    emails: [{ value: ctx.uniqueEmail("entra-mail"), type: null, primary: null }],
    [ENTERPRISE]: { department: null, manager: { value: "m", $ref: null, displayName: null } },
  });
  expect(entra.status, JSON.stringify(entra.resource)).toBe(201);
  observed.push(entra);
  for (const body of [
    { schemas: [USER], userName: ctx.uniqueEmail("x"), active: null },
    { schemas: [USER], userName: null },
    { schemas: [USER], userName: ctx.uniqueEmail("y"), emails: [null] },
  ]) {
    const rejected = await send("POST", "Users", body);
    expect(rejected.status).toBe(400);
    observed.push(rejected);
  }
  const created = await send("POST", "Users", full);
  expect(created.status, JSON.stringify(created.resource)).toBe(201);
  const id = created.resource.id;
  const patched = await patch(`Users/${id}`, [
    { op: "Replace", path: "title", value: null },
    { op: "Add", path: "externalId", value: null },
    { op: "Replace", path: "name", value: { familyName: "King", middleName: null, formatted: null } },
    { op: "Replace", path: `${ENTERPRISE}:manager`, value: { displayName: null } },
    { op: "Replace", path: 'addresses[type eq "work"].country', value: null },
    { op: "Replace", path: 'addresses[type eq "home"]', value: { locality: "Bristol", region: null } },
    { op: "Replace", path: 'addresses[type eq "other"]', value: { country: null } },
    { op: "Replace", path: "emails", value: [{ value: userName, type: null, primary: null }] },
    { op: "Replace", path: "enterprise", value: { department: null } },
  ]);
  expect(patched.status, JSON.stringify(patched.resource)).toBe(200);
  expect(patched.resource.name).toEqual({
    formatted: "Ada King",
    givenName: "Ada",
    familyName: "King",
  });
  expect(patched.resource.addresses).toEqual([
    { type: "work", streetAddress: "1 Main St" },
    { type: "home", locality: "Bristol" },
  ]);
  expect(patched.resource[ENTERPRISE]).toEqual({ manager: { value: "manager-1" } });
  observed.push(patched);
  for (const operations of [
    [{ op: "Replace", path: "active", value: null }],
    [{ op: "Replace", value: { title: "Gone", active: null } }],
    [{ op: "Replace", path: "userName", value: null }],
    [{ op: "Replace", path: "emails", value: null }],
  ]) {
    const rejected = await patch(`Users/${id}`, operations);
    expect(rejected.status).toBe(400);
    observed.push(rejected);
  }
  const pathless = await patch(`Users/${id}`, [
    {
      op: "Replace",
      value: { "name.givenName": null, displayName: "Ada L", [ENTERPRISE]: { manager: null } },
    },
  ]);
  expect(pathless.status, JSON.stringify(pathless.resource)).toBe(200);
  expect(pathless.resource[ENTERPRISE]).toBeUndefined();
  observed.push(pathless);
  const replaced = await send("PUT", `Users/${id}`, {
    ...full,
    title: null,
    name: { ...full.name, middleName: null },
    [ENTERPRISE]: { department: null, manager: { value: null, $ref: null } },
  });
  expect(replaced.status, JSON.stringify(replaced.resource)).toBe(200);
  expect(replaced.resource.title).toBeUndefined();
  expect(replaced.resource[ENTERPRISE]).toBeUndefined();
  observed.push(replaced);
  const group = await send("POST", "Groups", {
    schemas: [GROUP],
    displayName: `Null ${ctx.uniqueToken("group")}`,
    externalId: null,
    members: [{ value: id, display: null }],
  });
  expect(group.status, JSON.stringify(group.resource)).toBe(201);
  observed.push(group);
  const cleared = await patch(`Groups/${group.resource.id}`, [
    { op: "Replace", value: { externalId: null, schemas: null, meta: null } },
    { op: "Replace", path: "members", value: null },
  ]);
  expect(cleared.status, JSON.stringify(cleared.resource)).toBe(200);
  observed.push(cleared);
  const rejected = await patch(`Groups/${group.resource.id}`, [
    { op: "Replace", path: "displayName", value: null },
  ]);
  expect(rejected.status).toBe(400);
  observed.push(rejected);
  const emptied = await send("PUT", `Groups/${group.resource.id}`, {
    schemas: [GROUP],
    displayName: group.resource.displayName,
    members: null,
  });
  expect(emptied.status, JSON.stringify(emptied.resource)).toBe(200);
  observed.push(emptied);
  return observed;
});

compatScenario("SCIM create reprovisions an inactive User with the same externalId", async (ctx) => {
  const { send } = client(ctx);
  const externalId = ctx.uniqueToken("okta");
  const first = await send("POST", "Users", {
    schemas: [USER],
    userName: ctx.uniqueEmail("okta-first"),
    externalId,
    active: false,
  });
  expect(first.status).toBe(201);
  const reprovisioned = await send("POST", "Users", {
    schemas: [USER],
    userName: ctx.uniqueEmail("okta-again"),
    externalId,
    displayName: "Reprovisioned",
  });
  expect(reprovisioned.status, JSON.stringify(reprovisioned.resource)).toBe(201);
  expect(reprovisioned.resource.id).toBe(first.resource.id);
  expect(reprovisioned.resource.active).toBe(true);
  const duplicate = await send("POST", "Users", {
    schemas: [USER],
    userName: ctx.uniqueEmail("okta-duplicate"),
    externalId,
  });
  expect(duplicate.status).toBe(409);
  const other = await send("POST", "Users", {
    schemas: [USER],
    userName: ctx.uniqueEmail("okta-other"),
    externalId: ctx.uniqueToken("okta-other"),
    active: false,
  });
  expect(other.status).toBe(201);
  const taken = await send("POST", "Users", {
    schemas: [USER],
    userName: reprovisioned.resource.userName,
    externalId: other.resource.externalId,
  });
  expect(taken.status).toBe(409);
  const listed = await send("GET", `Users?filter=${encodeURIComponent(`externalId eq "${externalId}"`)}`);
  expect(listed.resource.totalResults).toBe(1);
  return [first, reprovisioned, duplicate, other, taken, listed];
});
