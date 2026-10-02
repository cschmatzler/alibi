import { expect } from "bun:test";

import { compatScenario } from "../../../support/scenario";

compatScenario(
  "admin official client array filters preserve all operands SQL semantics pagination and authorization without changing owners",
  async (ctx) => {
    const owner = ctx.actor("array-owner");
    const guest = ctx.actor("array-guest");
    const names = [
      "Array Owner",
      "Array Alpha",
      "Array Beta",
      "Array Alpha,Array Beta",
      "Array %_",
    ] as const;
    const actors = names.map((_, index) =>
      index === 0 ? owner : ctx.actor(`array-user-${index}`),
    );
    type SignupUser = NonNullable<
      Awaited<ReturnType<typeof owner.client.signUp.email>>["data"]
    >["user"];
    const users: SignupUser[] = [];

    for (const [index, actor] of actors.entries()) {
      const result = await actor.client.signUp.email({
        email: ctx.uniqueEmail(`array-${index}`),
        name: names[index]!,
        password: "password123",
      });
      expect(result.error).toBeNull();

      if (!result.data) {
        throw Error("actual persisted filter users required");
      }

      users.push(result.data.user);
    }

    await ctx.promoteAdmin({ email: users[0]!.email });
    expect(
      (await owner.client.signIn.email({ email: users[0]!.email, password: "password123" })).error,
    ).toBeNull();

    const before = await Promise.all(users.map((user) => ctx.readUserState({ userId: user.id })));
    const base = { sortBy: "name", sortDirection: "asc" as const, filterField: "name" };
    const membership = [];

    for (const [operator, values, expected] of [
      ["in", [names[1]!, names[2]!], [names[1]!, names[2]!]],
      ["in", [names[2]!, names[1]!], [names[1]!, names[2]!]],
      ["in", [names[1]!, names[1]!], [names[1]!]],
      ["not_in", [names[1]!, names[2]!], [names[4]!, names[3]!, names[0]!]],
    ] as const) {
      const result = await owner.client.admin.listUsers({
        query: { ...base, filterOperator: operator, filterValue: [...values] },
      });
      expect(result.error).toBeNull();
      expect(result.data?.users.map((user) => user.name)).toEqual([...expected]);
      expect(result.data?.total).toBe(expected.length);

      membership.push(result);
    }

    const paged = await owner.client.admin.listUsers({
      query: {
        ...base,
        filterOperator: "in",
        filterValue: [names[1]!, names[2]!],
        limit: 1,
        offset: 1,
      },
    });
    expect(paged.data?.users.map((user) => user.name)).toEqual([names[2]]);
    expect(paged.data).toMatchObject({ total: 2, limit: 1, offset: 1 });

    const byId = await owner.client.admin.listUsers({
      query: {
        ...base,
        filterField: "id",
        filterOperator: "in",
        filterValue: [users[2]!.id, users[1]!.id],
      },
    });
    expect(byId.data?.users.map((user) => user.id)).toEqual([users[1]!.id, users[2]!.id]);

    const byEmail = await owner.client.admin.listUsers({
      query: {
        ...base,
        filterField: "email",
        filterOperator: "in",
        filterValue: [users[1]!.email, users[2]!.email],
      },
    });
    expect(byEmail.data?.users.map((user) => user.id)).toEqual([users[1]!.id, users[2]!.id]);

    const byBoolean = await owner.client.admin.listUsers({
      query: {
        ...base,
        filterField: "emailVerified",
        filterOperator: "in",
        filterValue: ["0", "0"],
      },
    });
    expect(byBoolean.data?.users).toHaveLength(5);
    expect(byBoolean.data?.total).toBe(5);

    const scalarBooleans = [];

    for (const value of ["true", "false", "FALSE", "0"] as const) {
      const result = await owner.client.admin.listUsers({
        query: {
          ...base,
          filterField: "emailVerified",
          filterOperator: "not_in",
          filterValue: value,
        },
      });
      expect(result.error).toBeNull();
      expect(result.data?.users).toHaveLength(value === "true" ? 5 : 0);
      expect(result.data?.total).toBe(value === "true" ? 5 : 0);

      scalarBooleans.push(result);
    }

    const patterns = [];

    for (const operator of ["contains", "starts_with", "ends_with"] as const) {
      const result = await owner.client.admin.listUsers({
        query: { ...base, filterOperator: operator, filterValue: ["array alpha", "array beta"] },
      });
      expect(result.error).toBeNull();
      expect(result.data?.users.map((user) => user.name)).toEqual([names[3]]);

      patterns.push(result);
    }

    const wildcard = await owner.client.admin.listUsers({
      query: { ...base, filterOperator: "contains", filterValue: ["%", "Array Beta"] },
    });
    expect(wildcard.data?.users.map((user) => user.name)).toEqual([names[3]]);

    const failures = [];

    for (const operator of ["eq", "ne", "lt", "lte", "gt", "gte"] as const) {
      const result = await owner.client.admin.listUsers({
        query: {
          ...base,
          filterOperator: operator,
          filterValue: [names[1]!, names[2]!],
          limit: 1,
          offset: 1,
        },
      });
      expect(result.error).toBeNull();
      expect(result.data).toEqual({ users: [], total: 0 });

      failures.push(result);
    }

    const scalarIn = await owner.client.admin.listUsers({
      query: { ...base, filterOperator: "in", filterValue: names[1], limit: 1 },
    });
    expect(scalarIn.data).toEqual({ users: [], total: 0 });

    const scalarNotIn = await owner.client.admin.listUsers({
      query: { ...base, filterOperator: "not_in", filterValue: names[1] },
    });
    expect(scalarNotIn.data?.users).toHaveLength(4);
    expect(scalarNotIn.data?.users.some((user) => user.id === users[1]!.id)).toBe(false);

    const missing = await guest.client.admin.listUsers({
      query: { ...base, filterOperator: "in", filterValue: [names[1]!, names[2]!] },
    });
    const denied = await actors[1]!.client.admin.listUsers({
      query: { ...base, filterOperator: "in", filterValue: [names[1]!, names[2]!] },
    });
    expect(missing.error?.status).toBe(401);
    expect(denied.error?.status).toBe(403);

    const retry = await owner.client.admin.listUsers({
      query: { ...base, filterOperator: "in", filterValue: [names[2]!, names[1]!] },
    });
    expect(retry).toEqual(membership[0]!);

    const after = await Promise.all(users.map((user) => ctx.readUserState({ userId: user.id })));
    expect(after).toEqual(before);

    return {
      users,
      before,
      membership,
      paged,
      byId,
      byEmail,
      byBoolean,
      scalarBooleans,
      patterns,
      wildcard,
      failures,
      scalarIn,
      scalarNotIn,
      missing,
      denied,
      retry,
      after,
    };
  },
  ["GET /admin/list-users"],
);
