import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "SCIM User collections filter scoped email indexes and validate only returned resources",
  async (ctx) => {
    const actor = ctx.actor();
    const control = (operation: string, input: unknown = {}) =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/scim?operation=${operation}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(input),
      });
    const list = (query: unknown = {}, token?: string) =>
      control("listSCIMUsers", { query, ...(token === undefined ? {} : { token }) });
    expect((await list()).status).toBe(401);
    expect(await (await control("seed-user-list")).json()).toEqual({ seeded: true });
    const page = await list({ startIndex: 2, count: 1, attributes: "userName" }, "users-reader");
    expect(page.status).toBe(200);
    expect(await page.json()).toEqual({
      schemas: ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
      totalResults: 3,
      startIndex: 2,
      itemsPerPage: 1,
      Resources: [
        { schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"], id: "bob", userName: "Bob" },
      ],
    });
    for (const [filter, total, id] of [
      [`userName eq "ALICE"`, 1, "alice"],
      [`userName eq " Alice "`, 0, null],
      [`externalId eq "external-bob"`, 1, "bob"],
      [`emails.value eq " HOME-ALICE@EXAMPLE.COM "`, 1, "alice"],
      [`emails[type eq "work"].value eq "work-bob@example.com" and userName eq "BOB"`, 1, "bob"],
      [`emails[type eq "work"].value eq "home-bob@example.com"`, 0, null],
      [`id eq "foreign"`, 0, null],
    ] as const) {
      const response = await list({ filter, attributes: "userName" }, "users-reader");
      expect(response.status).toBe(200);
      const value = (await response.json()) as any;
      expect(value.totalResults).toBe(total);
      if (id) {
        expect(value.Resources[0].id).toBe(id);
      }
    }
    const bom = await list(
      { filter: `emails[\uFEFFtype eq "work"].value eq "work-bob@example.com"`, attributes: "id" },
      "users-reader",
    );
    expect(bom.status).toBe(200);
    expect(((await bom.json()) as any).Resources[0].id).toBe("bob");
    const nel = await list(
      { filter: `emails[\u0085type eq "work"].value eq "work-bob@example.com"` },
      "users-reader",
    );
    expect(nel.status).toBe(400);
    const unsupported = await list(
      { filter: `emails.work.value eq "work-bob@example.com"` },
      "users-reader",
    );
    expect(unsupported.status).toBe(400);
    expect(((await unsupported.json()) as any).detail).toBe(
      "filter attribute emails.work.value is not supported for User",
    );
    const http = await actor.fetch(`${ctx.baseURL}/__test/profiles/scim/api/auth/scim/v2/Users`, {
      headers: { authorization: "Bearer users-reader" },
    });
    expect(http.status).toBe(200);
    expect(((await http.json()) as any).itemsPerPage).toBe(3);
    expect(await (await control("corrupt-user-list")).json()).toEqual({ corrupt: true });
    const invalid = await list({ attributes: "id" }, "users-reader");
    expect(invalid.status).toBe(500);
    expect(((await invalid.json()) as any).detail).toBe(
      "Stored SCIM User attribute state is invalid",
    );
    const count = await list({ count: 0 }, "users-reader");
    expect(count.status).toBe(200);
    const counted = (await count.json()) as any;
    expect(counted.totalResults).toBe(3);
    expect(counted.Resources).toEqual([]);
    const skipped = await list({ count: 1, attributes: "id" }, "users-reader");
    expect(skipped.status).toBe(200);
    expect(((await skipped.json()) as any).Resources[0].id).toBe("alice");
    expect(await (await control("drift-user-list")).json()).toEqual({ changed: true });
    expect((await list({ count: "bad" }, "users-reader")).status).toBe(409);
    return { filtered: true, typedEmail: true, paged: true, validated: true };
  },
);
