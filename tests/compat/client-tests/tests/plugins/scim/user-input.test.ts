import { expect } from "bun:test";

import { compatScenario } from "../../../support/scenario";
compatScenario("SCIM User input reports field errors before authentication", async (ctx) => {
  const actor = ctx.actor();
  const schema = "urn:ietf:params:scim:schemas:core:2.0:User";
  const valid = { schemas: [schema], userName: "owner@example.com" };
  const cases: [unknown, string][] = [
    [
      {},
      "[body.schemas] Invalid input: expected array, received undefined; [body.userName] Invalid input: expected string, received undefined",
    ],
    [{ schemas: [schema] }, "[body.userName] Invalid input: expected string, received undefined"],
    [{ ...valid, userName: null }, "[body.userName] Invalid input: expected string, received null"],
    [
      { ...valid, userName: " " },
      "[body.userName] Too small: expected string to have >=1 characters; [body.emails] emails must contain an email when userName is not an email address",
    ],
    [
      { ...valid, userName: "x".repeat(513) },
      "[body.userName] Too big: expected string to have <=512 characters; [body.emails] emails must contain an email when userName is not an email address",
    ],
    [{ ...valid, active: null }, "[body.active] Invalid input: expected boolean, received null"],
    [
      { ...valid, active: "false" },
      "[body.active] Invalid input: expected boolean, received string",
    ],
    [
      { ...valid, userName: "not-email" },
      "[body.emails] emails must contain an email when userName is not an email address",
    ],
    [
      { ...valid, schemas: [] },
      `[body.schemas] Too small: expected array to have >=1 items; [body.schemas] schemas must contain ${schema}`,
    ],
    [
      { ...valid, schemas: ["bad"] },
      `[body.schemas] Unsupported SCIM User schema bad; [body.schemas] schemas must contain ${schema}`,
    ],
    [{ ...valid, schemas: null }, "[body.schemas] Invalid input: expected array, received null"],
    [
      { ...valid, schemas: [schema, schema] },
      `[body.schemas] SCIM User schema ${schema} must not be duplicated; [body.schemas] SCIM User schema ${schema} must not be duplicated`,
    ],
    [
      { ...valid, externalId: null },
      "[body.externalId] Invalid input: expected string, received null",
    ],
    [
      { ...valid, displayName: 42 },
      "[body.displayName] Invalid input: expected string, received number",
    ],
    [{ ...valid, name: null }, "[body.name] Invalid input: expected object, received null"],
    [{ ...valid, emails: null }, "[body.emails] Invalid input: expected array, received null"],
    [{ ...valid, emails: [{ value: "bad" }] }, "[body.emails.0.value] Invalid email address"],
    [
      { ...valid, emails: [{ value: "a@example.com", primary: null }] },
      "[body.emails.0.primary] Invalid input: expected boolean, received null",
    ],
  ];
  cases.push(
    [
      { ...valid, userName: 123 },
      "[body.userName] Invalid input: expected string, received number",
    ],
    [
      { ...valid, schemas: [1] },
      "[body.schemas.0] Invalid input: expected string, received number",
    ],
    [
      { ...valid, name: { givenName: " " } },
      "[body.name.givenName] Too small: expected string to have >=1 characters",
    ],
    [
      { ...valid, title: [] },
      "[body.title] Invalid input: expected string, received array; [body.title] Too small: expected array to have >=1 items",
    ],
    [
      { ...valid, title: ["a", "b"] },
      "[body.title] Invalid input: expected string, received array",
    ],
    [{ ...valid, title: [null] }, "[body.title] Invalid input: expected string, received null"],
    [
      { ...valid, emails: [{}] },
      "[body.emails.0.value] Invalid input: expected string, received undefined",
    ],
    [
      { ...valid, emails: [{ value: "a@example.com", type: " " }] },
      "[body.emails.0.type] Too small: expected string to have >=1 characters",
    ],
  );
  cases.push(
    [
      {
        schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
        userName: "owner@example.com",
        emails: [
          { value: "a@example.com", primary: true },
          { value: "b@example.com", primary: true },
        ],
      },
      "[body.emails] emails cannot contain multiple primary values",
    ],
    [
      {
        schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
        userName: "owner@example.com",
        emails: [
          { value: "a@example.com", type: "WORK" },
          { value: "a@example.com", type: "work" },
        ],
      },
      "[body.emails] emails cannot contain duplicate type and value pairs; [body.emails] emails cannot contain duplicate defined types",
    ],
    [
      {
        schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
        userName: "owner@example.com",
        emails: [
          { value: "a@example.com", type: "WORK" },
          { value: "b@example.com", type: "work" },
        ],
      },
      "[body.emails] emails cannot contain duplicate defined types",
    ],
    [
      {
        schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
        userName: "owner@example.com",
        emails: [
          { value: "a0@example.com" },
          { value: "a1@example.com" },
          { value: "a2@example.com" },
          { value: "a3@example.com" },
          { value: "a4@example.com" },
          { value: "a5@example.com" },
          { value: "a6@example.com" },
          { value: "a7@example.com" },
          { value: "a8@example.com" },
          { value: "a9@example.com" },
          { value: "a10@example.com" },
          { value: "a11@example.com" },
          { value: "a12@example.com" },
          { value: "a13@example.com" },
          { value: "a14@example.com" },
          { value: "a15@example.com" },
          { value: "a16@example.com" },
          { value: "a17@example.com" },
          { value: "a18@example.com" },
          { value: "a19@example.com" },
          { value: "a20@example.com" },
        ],
      },
      "[body.emails] Too big: expected array to have <=20 items",
    ],
    [
      {
        schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
        userName: "owner@example.com",
        phoneNumbers: null,
      },
      "[body.phoneNumbers] Invalid input: expected array, received null",
    ],
    [
      {
        schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
        userName: "owner@example.com",
        phoneNumbers: [null],
      },
      "[body.phoneNumbers.0] Invalid input: expected object, received null",
    ],
    [
      {
        schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
        userName: "owner@example.com",
        phoneNumbers: [{}],
      },
      "[body.phoneNumbers.0.value] Invalid input: expected string, received undefined",
    ],
    [
      {
        schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
        userName: "owner@example.com",
        phoneNumbers: [{ value: 42 }],
      },
      "[body.phoneNumbers.0.value] Invalid input: expected string, received number",
    ],
    [
      {
        schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
        userName: "owner@example.com",
        phoneNumbers: [{ value: "123", primary: null }],
      },
      "[body.phoneNumbers.0.primary] Invalid input: expected boolean, received null",
    ],
    [
      {
        schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
        userName: "owner@example.com",
        phoneNumbers: [
          { value: "123", type: "WORK" },
          { value: "456", type: "work" },
        ],
      },
      "[body.phoneNumbers] phoneNumbers cannot contain duplicate defined types",
    ],
    [
      {
        schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
        userName: "owner@example.com",
        phoneNumbers: [
          { value: "123", primary: true },
          { value: "456", primary: true },
        ],
      },
      "[body.phoneNumbers] phoneNumbers cannot contain multiple primary values",
    ],
    [
      {
        schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
        userName: "owner@example.com",
        phoneNumbers: [
          { value: "0" },
          { value: "1" },
          { value: "2" },
          { value: "3" },
          { value: "4" },
          { value: "5" },
          { value: "6" },
          { value: "7" },
          { value: "8" },
          { value: "9" },
          { value: "10" },
        ],
      },
      "[body.phoneNumbers] Too big: expected array to have <=10 items",
    ],
    [
      {
        schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
        userName: "owner@example.com",
        addresses: [{}],
      },
      "[body.addresses.0] addresses must contain at least one address value",
    ],
    [
      {
        schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
        userName: "owner@example.com",
        addresses: [{ type: "home", primary: true }],
      },
      "[body.addresses.0] addresses must contain at least one address value",
    ],
    [
      {
        schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
        userName: "owner@example.com",
        addresses: [{ locality: 42 }],
      },
      "[body.addresses.0.locality] Invalid input: expected string, received number",
    ],
    [
      {
        schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
        userName: "owner@example.com",
        addresses: [
          { formatted: "a", type: "HOME" },
          { formatted: "b", type: "home" },
        ],
      },
      "[body.addresses] addresses cannot contain duplicate defined types",
    ],
    [
      {
        schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
        userName: "owner@example.com",
        roles: [{}],
      },
      "[body.roles.0.value] Invalid input: expected string, received undefined",
    ],
    [
      {
        schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
        userName: "owner@example.com",
        roles: [{ value: "a", display: null }],
      },
      "[body.roles.0.display] Invalid input: expected string, received null",
    ],
    [
      {
        schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
        userName: "owner@example.com",
        roles: [
          { value: "a", primary: true },
          { value: "b", primary: true },
        ],
      },
      "[body.roles] roles cannot contain multiple primary values",
    ],
    [
      {
        schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
        userName: "owner@example.com",
        roles: [
          { value: "a", type: "WORK" },
          { value: "b", type: "work" },
        ],
      },
      "[body.roles] roles cannot contain duplicate defined types",
    ],
    [
      {
        schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
        userName: "owner@example.com",
        entitlements: null,
      },
      "[body.entitlements] Invalid input: expected array, received null",
    ],
    [
      {
        schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
        userName: "owner@example.com",
        entitlements: [{ value: "" }],
      },
      "[body.entitlements.0.value] Too small: expected string to have >=1 characters",
    ],
    [
      {
        schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
        userName: "owner@example.com",
        entitlements: [
          { value: "a", type: "WORK" },
          { value: "b", type: "work" },
        ],
      },
      "[body.entitlements] entitlements cannot contain duplicate defined types",
    ],
    [
      {
        schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
        userName: "owner@example.com",
        "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {},
      },
      "[body.schemas] The Enterprise User extension requires urn:ietf:params:scim:schemas:extension:enterprise:2.0:User in schemas",
    ],
    [
      {
        schemas: [
          "urn:ietf:params:scim:schemas:core:2.0:User",
          "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User",
        ],
        userName: "owner@example.com",
        "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": null,
      },
      "[body.urn:ietf:params:scim:schemas:extension:enterprise:2.0:User] Invalid input: expected object, received null",
    ],
    [
      {
        schemas: [
          "urn:ietf:params:scim:schemas:core:2.0:User",
          "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User",
        ],
        userName: "owner@example.com",
        "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": { employeeNumber: 42 },
      },
      "[body.urn:ietf:params:scim:schemas:extension:enterprise:2.0:User.employeeNumber] Invalid input: expected string, received number",
    ],
    [
      {
        schemas: [
          "urn:ietf:params:scim:schemas:core:2.0:User",
          "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User",
        ],
        userName: "owner@example.com",
        "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": { employeeNumber: [] },
      },
      "[body.urn:ietf:params:scim:schemas:extension:enterprise:2.0:User.employeeNumber] Invalid input: expected string, received array; [body.urn:ietf:params:scim:schemas:extension:enterprise:2.0:User.employeeNumber] Too small: expected array to have >=1 items",
    ],
    [
      {
        schemas: [
          "urn:ietf:params:scim:schemas:core:2.0:User",
          "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User",
        ],
        userName: "owner@example.com",
        "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": { manager: 42 },
      },
      "[body.urn:ietf:params:scim:schemas:extension:enterprise:2.0:User.manager] Invalid input",
    ],
    [
      {
        schemas: [
          "urn:ietf:params:scim:schemas:core:2.0:User",
          "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User",
        ],
        userName: "owner@example.com",
        "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": { manager: { value: null } },
      },
      "[body.urn:ietf:params:scim:schemas:extension:enterprise:2.0:User.manager] Invalid input",
    ],
    [
      {
        schemas: [
          "urn:ietf:params:scim:schemas:core:2.0:User",
          "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User",
        ],
        userName: "owner@example.com",
        "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": { manager: [] },
      },
      "[body.urn:ietf:params:scim:schemas:extension:enterprise:2.0:User.manager] Too small: expected array to have exactly 1 items",
    ],
    [
      {
        schemas: [
          "urn:ietf:params:scim:schemas:core:2.0:User",
          "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User",
        ],
        userName: "owner@example.com",
        "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": { manager: [{}, {}] },
      },
      "[body.urn:ietf:params:scim:schemas:extension:enterprise:2.0:User.manager] Too big: expected array to have exactly 1 items",
    ],
  );
  cases.push(
    [
      {
        schemas: [
          "urn:ietf:params:scim:schemas:core:2.0:User",
          "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User",
        ],
        userName: "owner@example.com",
        emails: [
          { value: "bad", primary: true },
          { value: "bad", primary: true },
        ],
      },
      "[body.emails.0.value] Invalid email address; [body.emails.1.value] Invalid email address; [body.emails] emails cannot contain multiple primary values; [body.emails] emails cannot contain duplicate type and value pairs",
    ],
    [
      {
        schemas: [
          "urn:ietf:params:scim:schemas:core:2.0:User",
          "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User",
        ],
        userName: "owner@example.com",
        emails: [
          { value: "a@example.com", type: " ", primary: true },
          { value: "b@example.com", type: " ", primary: true },
        ],
      },
      "[body.emails.0.type] Too small: expected string to have >=1 characters; [body.emails.1.type] Too small: expected string to have >=1 characters; [body.emails] emails cannot contain multiple primary values; [body.emails] emails cannot contain duplicate defined types",
    ],
    [
      {
        schemas: [
          "urn:ietf:params:scim:schemas:core:2.0:User",
          "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User",
        ],
        userName: "owner@example.com",
        roles: [
          { value: " ", primary: true },
          { value: " ", primary: true },
        ],
      },
      "[body.roles.0.value] Too small: expected string to have >=1 characters; [body.roles.1.value] Too small: expected string to have >=1 characters; [body.roles] roles cannot contain multiple primary values",
    ],
    [
      {
        schemas: [
          "urn:ietf:params:scim:schemas:core:2.0:User",
          "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User",
        ],
        userName: "owner@example.com",
        "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": { manager: "" },
      },
      "[body.urn:ietf:params:scim:schemas:extension:enterprise:2.0:User.manager] Too small: expected string to have >=1 characters",
    ],
    [
      {
        schemas: [
          "urn:ietf:params:scim:schemas:core:2.0:User",
          "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User",
        ],
        userName: "owner@example.com",
        "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": { manager: { value: "" } },
      },
      "[body.urn:ietf:params:scim:schemas:extension:enterprise:2.0:User.manager.value] Too small: expected string to have >=1 characters",
    ],
    [
      {
        schemas: [
          "urn:ietf:params:scim:schemas:core:2.0:User",
          "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User",
        ],
        userName: "owner@example.com",
        "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": { manager: [{ value: "" }] },
      },
      "[body.urn:ietf:params:scim:schemas:extension:enterprise:2.0:User.manager.0.value] Too small: expected string to have >=1 characters",
    ],
    [
      {
        schemas: [
          "urn:ietf:params:scim:schemas:core:2.0:User",
          "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User",
        ],
        userName: "owner@example.com",
        "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": { manager: { value: 42 } },
      },
      "[body.urn:ietf:params:scim:schemas:extension:enterprise:2.0:User.manager] Invalid input",
    ],
    [
      {
        schemas: [
          "urn:ietf:params:scim:schemas:core:2.0:User",
          "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User",
        ],
        userName: "owner@example.com",
        "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {
          manager: { displayName: 42 },
        },
      },
      "[body.urn:ietf:params:scim:schemas:extension:enterprise:2.0:User.manager] Invalid input",
    ],
    [
      {
        schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
        userName: "owner@example.com",
        emails: [
          { value: "bad" },
          { value: "a1@example.com" },
          { value: "a2@example.com" },
          { value: "a3@example.com" },
          { value: "a4@example.com" },
          { value: "a5@example.com" },
          { value: "a6@example.com" },
          { value: "a7@example.com" },
          { value: "a8@example.com" },
          { value: "a9@example.com" },
          { value: "a10@example.com" },
          { value: "a11@example.com" },
          { value: "a12@example.com" },
          { value: "a13@example.com" },
          { value: "a14@example.com" },
          { value: "a15@example.com" },
          { value: "a16@example.com" },
          { value: "a17@example.com" },
          { value: "a18@example.com" },
          { value: "a19@example.com" },
          { value: "a20@example.com" },
        ],
      },
      "[body.emails.0.value] Invalid email address; [body.emails] Too big: expected array to have <=20 items",
    ],
    [
      {
        schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
        userName: "owner@example.com",
        phoneNumbers: [
          { value: null },
          { value: "1" },
          { value: "2" },
          { value: "3" },
          { value: "4" },
          { value: "5" },
          { value: "6" },
          { value: "7" },
          { value: "8" },
          { value: "9" },
          { value: "10" },
        ],
      },
      "[body.phoneNumbers.0.value] Invalid input: expected string, received null; [body.phoneNumbers] Too big: expected array to have <=10 items",
    ],
    [
      {
        schemas: ["urn:ietf:params:scim:schemas:core:2.0:User", 1, "bad"],
        userName: "owner@example.com",
      },
      "[body.schemas.1] Invalid input: expected string, received number; [body.schemas] Too big: expected array to have <=2 items",
    ],
  );
  for (const [body, detail] of cases) {
    for (const operation of ["createSCIMUser", "replaceSCIMUser"]) {
      const response = await actor.fetch(
        `${ctx.baseURL}/__test/server-api/scim?operation=${operation}`,
        {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ body, params: { userId: "missing" } }),
        },
      );
      expect(response.status).toBe(400);
      expect(await response.json()).toEqual({
        schemas: ["urn:ietf:params:scim:api:messages:2.0:Error"],
        status: "400",
        detail,
        scimType: "invalidValue",
      });
    }
  }
  for (const replace of [false, true]) {
    const response = await actor.fetch(
      `${ctx.baseURL}/__test/profiles/scim/api/auth/scim/v2/Users${replace ? "/missing" : ""}`,
      {
        method: replace ? "PUT" : "POST",
        headers: { "content-type": "application/scim+json" },
        body: JSON.stringify({ ...valid, userName: null }),
      },
    );
    expect(response.status).toBe(400);
    expect(await response.json()).toMatchObject({
      detail: "[body.userName] Invalid input: expected string, received null",
      scimType: "invalidValue",
    });
  }
  const state = await actor.fetch(
    `${ctx.baseURL}/__test/server-api/scim?operation=user-create-state`,
    { method: "POST", headers: { "content-type": "application/json" }, body: "{}" },
  );
  expect(await state.json()).toMatchObject({ users: [], sources: 0, subjects: 0, tombstones: 0 });
  const enterprise = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";
  const rejected = await actor.fetch(
    `${ctx.baseURL}/__test/server-api/scim?operation=createSCIMUser`,
    {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        token: "group-reader",
        body: {
          schemas: [schema, enterprise],
          userName: "invalid-manager@example.com",
          [enterprise]: { manager: 42 },
        },
      }),
    },
  );
  expect(rejected.status).toBe(400);
  expect(await rejected.json()).toMatchObject({ scimType: "invalidValue" });
  const unchanged = await actor.fetch(
    `${ctx.baseURL}/__test/server-api/scim?operation=user-create-state`,
    { method: "POST", headers: { "content-type": "application/json" }, body: "{}" },
  );
  expect(await unchanged.json()).toMatchObject({
    users: [],
    sources: 0,
    subjects: 0,
    tombstones: 0,
  });
  const managers: [unknown, unknown][] = [
    ["manager-a", { value: "manager-a" }],
    [
      { $ref: "https://directory.example/Users/manager-b" },
      { $ref: "https://directory.example/Users/manager-b" },
    ],
    [[{ value: "manager-c", displayName: "Ignored" }], { value: "manager-c" }],
  ];
  for (const [index, [manager, normalized]] of managers.entries()) {
    const response = await actor.fetch(
      `${ctx.baseURL}/__test/server-api/scim?operation=createSCIMUser`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          token: "group-reader",
          body: {
            schemas: [schema, enterprise],
            userName: ctx.uniqueEmail(`valid-manager-${index}`),
            [enterprise]: { manager },
          },
        }),
      },
    );
    expect(response.status).toBe(201);
    expect(((await response.json()) as any)[enterprise].manager).toEqual(normalized);
  }
  return { fieldErrors: true, authenticationPrecedence: true };
});
