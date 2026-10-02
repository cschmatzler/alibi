import { expect } from "bun:test";
import { compatScenario } from "../../support/scenario";

compatScenario(
  "admin repeated query fields retain arrays and reject before authentication without selecting a different owner",
  async (ctx) => {
    const owner = ctx.actor("query-owner"),
      regular = ctx.actor("query-regular"),
      guest = ctx.actor("query-guest");
    const signup = await owner.client.signUp.email({
      email: ctx.uniqueEmail("query-owner"),
      name: "Query Owner",
      password: "password123",
    });
    const other = await regular.client.signUp.email({
      email: ctx.uniqueEmail("query-regular"),
      name: "Query Regular",
      password: "password123",
    });
    expect(signup.error).toBeNull();
    expect(other.error).toBeNull();
    if (!signup.data || !other.data) throw Error("actual query owners required");
    await ctx.promoteAdmin({ email: signup.data.user.email });
    expect(
      (await owner.client.signIn.email({ email: signup.data.user.email, password: "password123" }))
        .error,
    ).toBeNull();
    const before = [
      await ctx.readUserState({ userId: signup.data.user.id }),
      await ctx.readUserState({ userId: other.data.user.id }),
    ];
    const cases = [
      [
        "get-user",
        "id",
        signup.data.user.id,
        other.data.user.id,
        "[query.id] Invalid input: expected string, received array",
      ],
      [
        "get-user",
        "id",
        other.data.user.id,
        other.data.user.id,
        "[query.id] Invalid input: expected string, received array",
      ],
      [
        "list-users",
        "searchValue",
        "Query",
        "Regular",
        "[query.searchValue] Invalid input: expected string, received array",
      ],
      [
        "list-users",
        "searchField",
        "email",
        "name",
        '[query.searchField] Invalid option: expected one of "email"|"name"',
      ],
      [
        "list-users",
        "searchOperator",
        "contains",
        "starts_with",
        '[query.searchOperator] Invalid option: expected one of "contains"|"starts_with"|"ends_with"',
      ],
      ["list-users", "limit", "1", "2", "[query.limit] Invalid input"],
      ["list-users", "offset", "0", "1", "[query.offset] Invalid input"],
      [
        "list-users",
        "sortBy",
        "email",
        "name",
        "[query.sortBy] Invalid input: expected string, received array",
      ],
      [
        "list-users",
        "sortDirection",
        "asc",
        "desc",
        '[query.sortDirection] Invalid option: expected one of "asc"|"desc"',
      ],
      [
        "list-users",
        "filterField",
        "email",
        "name",
        "[query.filterField] Invalid input: expected string, received array",
      ],
      [
        "list-users",
        "filterOperator",
        "eq",
        "ne",
        '[query.filterOperator] Invalid option: expected one of "eq"|"ne"|"lt"|"lte"|"gt"|"gte"|"in"|"not_in"|"contains"|"starts_with"|"ends_with"',
      ],
    ] as const;
    const request = async (actor: typeof owner, path: string) => {
      const response = await actor.fetch(`/api/auth/admin/${path}`);
      const text = await response.text();
      return {
        status: response.status,
        contentType: response.headers.get("content-type"),
        cookies: response.headers.getSetCookie(),
        body: text ? JSON.parse(text) : "",
      };
    };
    const outcomes = [];
    for (const actor of [guest, regular, owner]) {
      for (const [route, key, first, second, message] of cases) {
        const query = new URLSearchParams([
          [key, first],
          [key, second],
        ]);
        const result = await request(actor, `${route}?${query}`);
        expect(result).toEqual({
          status: 400,
          contentType: "application/json",
          cookies: [],
          body: { code: "VALIDATION_ERROR", message },
        });
        outcomes.push(result);
      }
    }
    const combined = await request(
      guest,
      "list-users?sortBy=name&sortBy=email&limit=1&limit=2&searchValue=A&searchValue=B",
    );
    expect(combined).toEqual({
      status: 400,
      contentType: "application/json",
      cookies: [],
      body: {
        code: "VALIDATION_ERROR",
        message:
          "[query.searchValue] Invalid input: expected string, received array; [query.limit] Invalid input; [query.sortBy] Invalid input: expected string, received array",
      },
    });
    const encodedNames = await request(
      owner,
      `get-user?i%64=${encodeURIComponent(signup.data.user.id)}&id=${encodeURIComponent(other.data.user.id)}`,
    );
    expect(encodedNames.body).toEqual({
      code: "VALIDATION_ERROR",
      message: "[query.id] Invalid input: expected string, received array",
    });
    expect(encodedNames.status).toBe(400);
    expect(encodedNames.cookies).toEqual([]);
    const validQuery = `get-user?id=${encodeURIComponent(other.data.user.id)}`;
    const missing = await request(guest, validQuery),
      denied = await request(regular, validQuery);
    expect(missing.status).toBe(401);
    expect(denied.status).toBe(403);
    const allowed = await request(owner, `${validQuery}&ignored=first&ignored=second`);
    expect(allowed.status).toBe(200);
    expect(allowed.body).toHaveProperty("id", other.data.user.id);
    const after = [
      await ctx.readUserState({ userId: signup.data.user.id }),
      await ctx.readUserState({ userId: other.data.user.id }),
    ];
    expect(after).toEqual(before);
    return {
      signup,
      other,
      before,
      outcomes,
      combined,
      encodedNames,
      missing,
      denied,
      allowed,
      after,
    };
  },
  ["GET /admin/get-user", "GET /admin/list-users"],
);
