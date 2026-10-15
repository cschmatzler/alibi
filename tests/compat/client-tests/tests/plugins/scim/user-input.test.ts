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
  return { fieldErrors: true, authenticationPrecedence: true };
});
