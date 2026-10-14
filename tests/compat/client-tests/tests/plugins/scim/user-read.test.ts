import { expect } from "bun:test";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "SCIM User reads validate canonical state, reconstruct mirrors and project Enterprise attributes",
  async (ctx) => {
    const actor = ctx.actor();
    const control = (operation: string, input: unknown = {}) =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/scim?operation=${operation}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(input),
      });
    const read = (id: string, query: unknown = {}, token?: string) =>
      control("getSCIMUser", {
        params: { userId: id },
        query,
        ...(token === undefined ? {} : { token }),
      });
    expect((await read("rich")).status).toBe(401);
    expect(await (await control("seed-user-read")).json()).toEqual({ seeded: true });
    const response = await read("rich", {}, "users-reader");
    expect(response.status).toBe(200);
    const expected = {
      schemas: [
        "urn:ietf:params:scim:schemas:core:2.0:User",
        "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User",
      ],
      id: "rich",
      externalId: "external-alice",
      userName: "alice",
      displayName: "Alice from row",
      active: false,
      name: { formatted: "Alice Example", givenName: "Alice" },
      emails: [{ value: "Alice@example.com", primary: true, type: "work" }],
      title: "Principal",
      phoneNumbers: [{ value: "+1 555", type: "work", primary: true }],
      addresses: [{ streetAddress: "1 Road", type: "work", primary: true }],
      roles: [{ value: "admin", display: "Admin", type: "custom", primary: true }],
      "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {
        employeeNumber: "42",
        organization: "Example",
        manager: { value: "manager" },
      },
      meta: {
        resourceType: "User",
        created: "2026-01-02T03:04:05.000Z",
        lastModified: "2026-01-02T03:04:05.000Z",
        location: `${ctx.baseURL}/__test/profiles/scim/api/auth/scim/v2/Users/rich`,
      },
    };
    expect(await response.json()).toEqual(expected);
    const selected = await read(
      "rich",
      {
        attributes:
          "userName,emails.value,urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:manager.value",
      },
      "users-reader",
    );
    expect(await selected.json()).toEqual({
      schemas: expected.schemas,
      id: "rich",
      userName: "alice",
      emails: [{ value: "Alice@example.com" }],
      "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {
        manager: { value: "manager" },
      },
    });
    const legacy = await read("legacy", {}, "users-reader");
    expect(legacy.status).toBe(200);
    const mirrors = (await legacy.json()) as any;
    expect(mirrors.name).toEqual({ formatted: "Legacy Name", givenName: "Legacy" });
    expect(mirrors.emails).toEqual([{ value: "legacy@example.com", primary: true }]);
    for (const id of ["missing", "foreign"]) {
      expect((await read(id, {}, "users-reader")).status).toBe(404);
    }
    expect((await read("drift", {}, "users-reader")).status).toBe(409);
    const corrupt = await read("corrupt", { attributes: "id" }, "users-reader");
    expect(corrupt.status).toBe(500);
    expect(((await corrupt.json()) as any).detail).toBe(
      "Stored SCIM User attribute state is invalid",
    );
    const base = {
      schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
      name: { formatted: "Valid Name" },
      emails: [{ value: "valid@example.com", primary: true }],
    };
    const invalid = [
      { ...base, emails: [] },
      { ...base, emails: [{ value: "valid@example.com", primary: false }] },
      {
        ...base,
        emails: [
          { value: "one@example.com", primary: true, type: "WORK" },
          { value: "two@example.com", primary: false, type: "work" },
        ],
      },
      {
        ...base,
        emails: [
          { value: "valid@example.com", primary: true },
          { value: "VALID@example.com", primary: false },
        ],
      },
      { ...base, schemas: ["urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"] },
      { ...base, enterprise: {} },
      { ...base, addresses: [{ type: "work" }] },
      { ...base, title: ["Title"] },
      {
        ...base,
        phoneNumbers: Array.from({ length: 11 }, (_, index) => ({ value: `phone-${index}` })),
      },
    ].map((value) => JSON.stringify(value));
    invalid.push(" ".repeat(65536) + JSON.stringify(base));
    for (const serializedAttributes of invalid) {
      expect(
        await (await control("user-read-attributes", { serializedAttributes })).json(),
      ).toEqual({ changed: true });
      const denied = await read("rich", { attributes: "id" }, "users-reader");
      expect(denied.status).toBe(500);
      expect(((await denied.json()) as any).detail).toBe(
        "Stored SCIM User attribute state is invalid",
      );
    }
    expect(await (await control("user-read-attributes", { restore: true })).json()).toEqual({
      changed: true,
    });
    const http = await actor.fetch(
      `${ctx.baseURL}/__test/profiles/scim/api/auth/scim/v2/Users/rich`,
      { headers: { authorization: "Bearer users-reader" } },
    );
    expect(http.status).toBe(200);
    expect(await http.json()).toEqual(expected);
    return { canonical: true, legacy: true, extension: true, corrupt: true };
  },
);
