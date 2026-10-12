import { expect } from "bun:test";

import { compatScenario } from "../../../support/scenario";
import { readUserState } from "../../../support/verification";

compatScenario(
  "server admin listUsers preserves query types SQL filtering and authoritative permission",
  async (ctx) => {
    async function signup(name: string) {
      const actor = ctx.actor("listing-" + name, name === "Admin" ? "admin-standard" : undefined);
      let cookie = "";
      const result = await actor.client.signUp.email({
        email: ctx.uniqueEmail(name),
        name,
        password: "Password123!",
        fetchOptions: {
          onSuccess({ response }) {
            cookie = response.headers
              .getSetCookie()
              .map((raw) => raw.split(";")[0])
              .join("; ");
          },
        },
      });
      expect(result.error).toBeNull();
      return { result, headers: { cookie } };
    }
    const people: Array<Awaited<ReturnType<typeof signup>>> = [];
    for (const name of ["Admin", "Alpha", "Beta", "Foreign", "Gamma"]) {
      people.push(await signup(name));
    }
    const admin = people[0]!;
    const member = people[1]!;
    const state = () =>
      Promise.all(people.map((person) => readUserState(ctx, person.result.data!.user.id)));
    const before = await state();
    async function invoke(input: Record<string, unknown>) {
      const response = await ctx
        .actor("list-control")
        .fetch(ctx.baseURL + "/__test/admin/server-api", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ operation: "listUsers", ...input }),
        });
      const text = await response.text();
      return {
        status: response.status,
        body: text ? JSON.parse(text) : null,
        principal: response.headers.get("x-admin-principal"),
        cookies: response.headers.getSetCookie(),
      };
    }
    const rejected = [];
    for (const [input, status] of [
      [{}, 400],
      [{ query: null }, 400],
      [{ query: 7 }, 400],
      [{ query: { limit: true } }, 400],
      [{ query: { offset: null } }, 400],
      [{ query: { searchField: "role" }, headers: admin.headers }, 400],
      [{ query: { sortDirection: "sideways" } }, 400],
      [{ query: { filterValue: ["x", 7] } }, 400],
      [{ query: { filterOperator: "bogus" } }, 400],
      [{ query: {} }, 401],
      [{ query: {}, headers: {} }, 401],
      [
        {
          query: { role: "admin", userId: admin.result.data!.user.id },
          body: { role: "admin" },
          headers: member.headers,
        },
        403,
      ],
      [{ query: {}, profile: "admin-deny-all", headers: admin.headers }, 403],
    ] as const) {
      const result = await invoke(input);
      expect(result.status).toBe(status);
      if (status === 401) {
        expect(result.body).toBeNull();
      }
      rejected.push(result);
    }
    const all = ["Admin", "Alpha", "Beta", "Foreign", "Gamma"];
    const listed = [];
    for (const [query, names, total, pagination] of [
      [{}, all, 5, {}],
      [{ searchField: "name", searchValue: "alpha" }, ["Alpha"], 1, {}],
      [{ filterField: "name", filterOperator: "contains", filterValue: "beta" }, ["Beta"], 1, {}],
      [
        {
          searchField: "name",
          searchValue: "a",
          filterField: "name",
          filterOperator: "in",
          filterValue: ["Alpha", "Beta", "Gamma"],
        },
        ["Alpha", "Beta", "Gamma"],
        3,
        {},
      ],
      [{ limit: 2, offset: 1 }, ["Alpha", "Beta"], 5, { limit: 2, offset: 1 }],
      [{ limit: "2", offset: "1" }, ["Alpha", "Beta"], 5, { limit: 2, offset: 1 }],
      [{ limit: 0, offset: 0 }, all, 5, {}],
      [{ limit: "junk" }, all, 5, {}],
      [{ limit: "0x2" }, ["Admin", "Alpha"], 5, { limit: 2 }],
      [{ limit: -1 }, all, 5, { limit: -1 }],
      [{ offset: -1 }, all, 5, { offset: -1 }],
      [{ limit: 1.5 }, [], 0, {}],
      [{ offset: "1.5" }, [], 0, {}],
      [{ limit: "Infinity" }, [], 0, {}],
      [
        { filterField: "name", filterOperator: "in", filterValue: ["Beta", "Alpha", "Alpha"] },
        ["Alpha", "Beta"],
        2,
        {},
      ],
      [{ filterField: "emailVerified", filterOperator: "in", filterValue: [0] }, all, 5, {}],
      [{ filterField: "banned", filterValue: false }, all, 5, {}],
      [{ sortBy: "unknown" }, [], 0, {}],
      [{ filterField: "unknown", filterValue: "x" }, [], 0, {}],
    ] as const) {
      const result = await invoke({
        query: {
          sortBy: "name",
          sortDirection: "asc",
          ...query,
          userId: member.result.data!.user.id,
        },
        body: 7,
        headers: admin.headers,
      });
      expect(result.status).toBe(200);
      expect(result.body.users.map((user: { name: string }) => user.name)).toEqual([...names]);
      expect(result.body.total).toBe(total);
      expect(result.body.limit).toBe((pagination as Record<string, number>).limit);
      expect(result.body.offset).toBe((pagination as Record<string, number>).offset);
      for (const user of result.body.users) {
        expect(user).not.toHaveProperty("password");
        expect(user).not.toHaveProperty("token");
      }
      expect(result.principal).toBe(admin.result.data!.user.email);
      expect(result.cookies).toEqual([
        "application_a=first; Path=/; HttpOnly",
        "application_b=second; Path=/; HttpOnly",
      ]);
      listed.push(result);
    }
    expect(await state()).toEqual(before);
    return ctx.snapshot({
      people: people.map((person) => person.result),
      before,
      rejected,
      listed,
    });
  },
);
