import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "SCIM Group collections filter, paginate and check immutable domains before query semantics",
  async (ctx) => {
    const actor = ctx.actor();
    const control = (operation: string, input: unknown = {}) =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/scim?operation=${operation}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(input),
      });
    const list = (query: unknown = {}, token?: string) =>
      control("listSCIMGroups", { query, ...(token === undefined ? {} : { token }) });
    expect((await list()).status).toBe(401);
    expect(await (await control("seed-group-list")).json()).toEqual({ seeded: true });
    const page = await list(
      { startIndex: "2", count: "1", attributes: "displayName" },
      "group-reader",
    );
    expect(page.status).toBe(200);
    expect(await page.json()).toEqual({
      schemas: ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
      totalResults: 3,
      startIndex: 2,
      itemsPerPage: 1,
      Resources: [
        {
          schemas: ["urn:ietf:params:scim:schemas:core:2.0:Group"],
          id: "group-b",
          displayName: "Second",
        },
      ],
    });
    for (const [filter, total, id] of [
      [`displayName eq "STAFF AND CREW"`, 1, "group-a"],
      [`externalId eq "EXTERNAL-B" and id eq "group-b"`, 1, "group-b"],
      [`displayName eq " Staff and Crew "`, 0, null],
      [`id eq "foreign"`, 0, null],
    ] as const) {
      const response = await list({ filter, attributes: "displayName" }, "group-reader");
      expect(response.status).toBe(200);
      const result = (await response.json()) as any;
      expect(result.totalResults).toBe(total);
      if (id) {
        expect(result.Resources[0].id).toBe(id);
      }
    }
    const empty = await list({ startIndex: -5, count: -1 }, "group-reader");
    expect(await empty.json()).toEqual({
      schemas: ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
      totalResults: 3,
      startIndex: 1,
      itemsPerPage: 0,
      Resources: [],
    });
    const full = await list({}, "group-reader");
    const all = (await full.json()) as any;
    expect(all.Resources[0].members).toEqual([]);
    expect(all.itemsPerPage).toBe(3);
    for (const [query, kind, detail] of [
      [{ count: "1.5" }, "invalidValue", "count must be an integer"],
      [{ count: "+2" }, "invalidValue", "count must be an integer"],
      [{ startIndex: "9007199254740992" }, "invalidValue", "startIndex must be an integer"],
      [
        { filter: `displayName co "Staff"` },
        "invalidFilter",
        "filter operator co is not supported",
      ],
      [
        { filter: `active eq "true"` },
        "invalidFilter",
        "filter attribute active is not supported for Group",
      ],
      [{ filter: "id eq 5" }, "invalidFilter", "filter equality value must be a quoted string"],
    ] as const) {
      const response = await list(query, "group-reader");
      expect(response.status).toBe(400);
      const error = (await response.json()) as any;
      expect(error.scimType).toBe(kind);
      expect(error.detail).toBe(detail);
    }
    const http = await actor.fetch(`${ctx.baseURL}/__test/profiles/scim/api/auth/scim/v2/Groups`, {
      headers: { authorization: "Bearer group-reader" },
    });
    expect(http.status).toBe(200);
    expect(await http.json()).toEqual(all);
    expect(await (await control("grow-group-list")).json()).toEqual({ grown: true });
    const bounded = await list({ count: 1000, attributes: "id" }, "group-reader");
    const boundedBody = (await bounded.json()) as any;
    expect(boundedBody.totalResults).toBe(104);
    expect(boundedBody.itemsPerPage).toBe(100);
    expect(boundedBody.Resources).toHaveLength(100);
    const beyond = await list({ startIndex: 500, count: 2 }, "group-reader");
    const beyondBody = (await beyond.json()) as any;
    expect(beyondBody.totalResults).toBe(104);
    expect(beyondBody.startIndex).toBe(500);
    expect(beyondBody.itemsPerPage).toBe(0);
    const shape = await list({ count: [] });
    expect(shape.status).toBe(400);
    expect(((await shape.json()) as any).detail).toBe("[query.count] Invalid input");
    expect(await (await control("drift-group-list")).json()).toEqual({ changed: true });
    expect((await list({ filter: `id eq "group-a"`, count: "bad" }, "group-reader")).status).toBe(
      409,
    );
    return { filtered: true, paged: true, isolated: true, domainFirst: true };
  },
);
