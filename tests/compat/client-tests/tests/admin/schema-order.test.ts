import { expect } from "bun:test";
import { createAuthClient } from "better-auth/client";
import { adminClient } from "better-auth/client/plugins";
import { compatScenario, type ScenarioContext } from "../../support/scenario";

const schemaPaths = [
  "set-role",
  "create-user",
  "update-user",
  "list-user-sessions",
  "ban-user",
  "unban-user",
  "impersonate-user",
  "revoke-user-session",
  "revoke-user-sessions",
  "remove-user",
  "set-user-password",
  "has-permission",
] as const;
const requiredId = "[body.userId] Invalid input: expected nonoptional, received undefined";
const emptyMessages: Record<(typeof schemaPaths)[number], string> = {
  "set-role": `${requiredId}; [body.role] Invalid input`,
  "create-user":
    "[body.email] Invalid input: expected string, received undefined; [body.name] Invalid input: expected string, received undefined",
  "update-user": `${requiredId}; [body.data] Invalid input: expected record, received undefined`,
  "list-user-sessions": requiredId,
  "ban-user": requiredId,
  "unban-user": requiredId,
  "impersonate-user": requiredId,
  "revoke-user-session": "[body.sessionToken] Invalid input: expected string, received undefined",
  "revoke-user-sessions": requiredId,
  "remove-user": requiredId,
  "set-user-password": `[body.newPassword] Invalid input: expected string, received undefined; ${requiredId}`,
  "has-permission": "[body] Invalid input",
};

async function setup(ctx: ScenarioContext) {
  const wires: {
    path: string;
    status: number;
    body: unknown;
    contentType: string | null;
    cookies: string[];
  }[] = [];
  const client = (name: string) => {
    const result = createAuthClient({
      baseURL: ctx.baseURL,
      plugins: [adminClient()],
      fetchOptions: {
        customFetchImpl: async (input, init) => {
          const response = await ctx.actor(name).fetch(input, init);
          const path = new URL(input instanceof Request ? input.url : input, ctx.baseURL).pathname;
          if (path.includes("/admin/")) {
            const text = await response.clone().text();
            wires.push({
              path,
              status: response.status,
              body: text ? JSON.parse(text) : "",
              contentType: response.headers.get("content-type"),
              cookies: response.headers.getSetCookie(),
            });
          }
          return response;
        },
      },
    });
    return result;
  };
  const owner = client("schema-owner"),
    target = client("schema-target"),
    regular = client("schema-regular"),
    retired = client("schema-retired"),
    guest = client("schema-guest");
  const password = "password123";
  const signup = async (actor: typeof owner, prefix: string) => {
    const result = await actor.signUp.email({
      email: ctx.uniqueEmail(prefix),
      name: prefix,
      password,
    });
    expect(result.error).toBeNull();
    if (!result.data) throw Error("actual registered user required");
    return result;
  };
  const signups = [
    await signup(owner, "schema-owner"),
    await signup(target, "schema-target"),
    await signup(regular, "schema-regular"),
    await signup(retired, "schema-retired"),
  ];
  await ctx.promoteAdmin({ email: signups[0]!.data!.user.email });
  const signin = async (name: string, email: string) => {
    const response = await ctx.actor(name).fetch("/api/auth/sign-in/email", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email, password }),
    });
    expect(response.status).toBe(200);
    return {
      body: await response.json(),
      cookie: response.headers
        .getSetCookie()
        .map((raw) => raw.split(";")[0])
        .join("; "),
    };
  };
  const issuedOwner = await signin("schema-owner", signups[0]!.data!.user.email);
  const issuedRetired = await signin("schema-retired", signups[3]!.data!.user.email);
  expect(issuedOwner.cookie).toContain("session_token=");
  expect(issuedRetired.cookie).toContain("session_token=");
  const signout = await retired.signOut();
  expect(signout.error).toBeNull();
  const ids = signups.map((result) => result.data!.user.id);
  const read = async () => {
    const persisted = [],
      users = [];
    for (const id of ids) {
      persisted.push(await ctx.readUserState({ userId: id }));
      users.push(await owner.admin.getUser({ query: { id } }));
    }
    return { persisted, users };
  };
  return {
    owner,
    target,
    regular,
    retired,
    guest,
    wires,
    ids,
    signups,
    issuedOwner,
    issuedRetired,
    signout,
    read,
  };
}

function validation(message: string) {
  return { message, code: "VALIDATION_ERROR" };
}
function rejected(result: unknown, status: number, body: Record<string, unknown>) {
  expect(result).toEqual({
    data: null,
    error: {
      ...body,
      status,
      statusText: status === 415 ? "Unsupported Media Type" : "Bad Request",
    },
  });
}

for (const mode of ["missing", "tampered", "revoked"] as const) {
  compatScenario(
    `admin ${mode} malformed schemas reject before session cleanup and preserve every owned row`,
    async (ctx) => {
      const fixture = await setup(ctx);
      const { owner, guest, target, ids } = fixture;
      const before = await fixture.read();
      const cookie = mode === "revoked" ? fixture.issuedRetired.cookie : fixture.issuedOwner.cookie;
      const altered = cookie.replace(/(session_token=[^;]+)/, (original) => {
        const [name, value] = original.split("=");
        const decoded = decodeURIComponent(value!);
        const lastDot = decoded.lastIndexOf(".");
        const signature = decoded.slice(lastDot + 1);
        return `${name}=${encodeURIComponent(decoded.slice(0, lastDot + 1) + (signature.startsWith("A") ? "B" : "A") + signature.slice(1))}`;
      });
      const headers =
        mode === "missing" ? undefined : { cookie: mode === "revoked" ? cookie : altered };
      const offset = fixture.wires.length;
      const outcomes = [];
      for (const path of schemaPaths) {
        const result = await guest.$fetch(`/admin/${path}`, { method: "POST", body: {}, headers });
        rejected(result, 400, validation(emptyMessages[path]));
        outcomes.push({ path, result });
        const array = await guest.$fetch(`/admin/${path}`, { method: "POST", body: [], headers });
        rejected(
          array,
          400,
          validation(
            "[body] Invalid input: expected object, received array" +
              (path === "has-permission" ? "; [body] Invalid input" : ""),
          ),
        );
        outcomes.push({ path, result: array });
      }
      const nullBody = await guest.$fetch("/admin/ban-user", {
        method: "POST",
        body: "null",
        headers,
      });
      rejected(nullBody, 400, validation("[body] Invalid input: expected object, received null"));
      const invalidOptional = await guest.admin.banUser(
        { userId: ids[1]!, banReason: null, banExpiresIn: null } as never,
        { headers },
      );
      rejected(
        invalidOptional,
        400,
        validation(
          "[body.banReason] Invalid input: expected string, received null; [body.banExpiresIn] Invalid input: expected number, received null",
        ),
      );
      const role = await guest.admin.setRole({ userId: ids[1]!, role: ["user", 5] } as never, {
        headers,
      });
      rejected(role, 400, validation("[body.role] Invalid input"));
      const create = await guest.admin.createUser(
        { email: 5, password: 5, name: 5, role: 5, data: 5 } as never,
        { headers },
      );
      rejected(
        create,
        400,
        validation(
          "[body.email] Invalid input: expected string, received number; [body.password] Invalid input: expected string, received number; [body.name] Invalid input: expected string, received number; [body.role] Invalid input; [body.data] Invalid input: expected record, received number",
        ),
      );
      const passwords = await guest.admin.setUserPassword(
        { userId: "", newPassword: "" },
        { headers },
      );
      rejected(
        passwords,
        400,
        validation(
          "[body.newPassword] newPassword cannot be empty; [body.userId] userId cannot be empty",
        ),
      );
      const coercionFailures = [];
      for (const userId of [{ toString: null }, { toString: "literal" }, [{ toString: 5 }]]) {
        const result = await guest.admin.listUserSessions({ userId } as never, { headers });
        rejected(
          result,
          400,
          validation(
            `[body.userId] Invalid input: expected string, received ${Array.isArray(userId) ? "array" : "object"}`,
          ),
        );
        coercionFailures.push({ userId, result });
      }
      const schemaWires = fixture.wires.slice(offset);
      for (const wire of schemaWires) {
        expect(wire.status).toBe(400);
        expect(wire.contentType).toBe("application/json");
        expect(wire.cookies).toEqual([]);
      }
      expect(await fixture.read()).toEqual(before);
      // Empty strings and coercible supplied IDs are valid schema inputs, so auth owns these failures.
      const coercions = [];
      for (const userId of [
        "",
        null,
        5,
        true,
        [],
        {},
        [null],
        { "$serde_json::private::RawValue": "literal" },
      ]) {
        const result = await guest.$fetch("/admin/list-user-sessions", {
          method: "POST",
          body: { userId },
          headers,
        });
        expect(result).toEqual({ data: null, error: { status: 401, statusText: "Unauthorized" } });
        coercions.push(result);
      }
      const forbidden = await target.admin.setRole({ userId: ids[0]!, role: "user" });
      expect(forbidden.error).toMatchObject({
        status: 403,
        code: "YOU_ARE_NOT_ALLOWED_TO_CHANGE_USERS_ROLE",
      });
      const coercedOwner = await owner.admin.listUserSessions({ userId: [[ids[1]!]] } as never);
      expect(coercedOwner.error).toBeNull();
      expect(coercedOwner.data?.sessions).toMatchObject([
        { userId: ids[1], token: fixture.signups[1]!.data!.token },
      ]);
      const coercedDenied = await target.admin.banUser({ userId: [ids[0]!] } as never);
      expect(coercedDenied.error).toMatchObject({
        status: 403,
        code: "YOU_ARE_NOT_ALLOWED_TO_BAN_USERS",
      });
      const allowed = await owner.admin.setRole({ userId: ids[1]!, role: "user" });
      expect(allowed.error).toBeNull();
      const current = await owner.getSession();
      expect(current.data?.user.id).toBe(ids[0]);
      expect(await ctx.readUserState({ userId: ids[0]! })).toEqual(before.persisted[0]);
      expect(await ctx.readUserState({ userId: ids[2]! })).toEqual(before.persisted[2]);
      return {
        signups: fixture.signups,
        signins: [fixture.issuedOwner.body, fixture.issuedRetired.body],
        signout: fixture.signout,
        before,
        outcomes,
        nullBody,
        invalidOptional,
        role,
        create,
        passwords,
        coercionFailures,
        schemaWires,
        coercions,
        forbidden,
        coercedOwner,
        coercedDenied,
        allowed,
        current,
        after: await fixture.read(),
      };
    },
    [
      "POST /admin/set-role",
      "POST /admin/create-user",
      "POST /admin/update-user",
      "POST /admin/list-user-sessions",
      "POST /admin/ban-user",
      "POST /admin/unban-user",
      "POST /admin/impersonate-user",
      "POST /admin/revoke-user-session",
      "POST /admin/revoke-user-sessions",
      "POST /admin/remove-user",
      "POST /admin/set-user-password",
      "POST /admin/has-permission",
    ],
  );
}

compatScenario(
  "admin JSON and media rejection precedes authenticated permissions and retains session state",
  async (ctx) => {
    const fixture = await setup(ctx);
    const before = await fixture.read();
    const outcomes = [];
    for (const path of [...schemaPaths, "stop-impersonating"]) {
      for (const input of [
        {
          body: "{",
          headers: { "content-type": "application/json" },
          status: 400,
          expected: { code: "BAD_REQUEST", message: "Invalid JSON in request body" },
        },
        {
          body: "{}",
          headers: { "content-type": "text/plain" },
          status: 415,
          expected: {
            code: "UNSUPPORTED_MEDIA_TYPE",
            message: 'Content-Type "text/plain" is not allowed. Allowed types: application/json',
          },
        },
        {
          body: new TextEncoder().encode("{}"),
          headers: {},
          status: 415,
          expected: {
            code: "UNSUPPORTED_MEDIA_TYPE",
            message: "Content-Type is required. Allowed types: application/json",
          },
        },
      ]) {
        const result = await ctx.rawRequest({
          actor: "schema-regular",
          path: `/api/auth/admin/${path}`,
          method: "POST",
          body: input.body,
          headers: new Headers(input.headers as Record<string, string>),
        });
        expect(result).toEqual({ status: input.status, location: null, body: input.expected });
        outcomes.push({ path, input: { status: input.status, headers: input.headers }, result });
      }
    }
    expect(await fixture.read()).toEqual(before);
    const forbidden = await fixture.regular.admin.banUser({ userId: fixture.ids[1]! });
    expect(forbidden.error).toMatchObject({
      status: 403,
      code: "YOU_ARE_NOT_ALLOWED_TO_BAN_USERS",
    });
    const owner = await fixture.owner.admin.getUser({ query: { id: fixture.ids[1]! } });
    expect(owner.error).toBeNull();
    const current = await fixture.regular.getSession();
    expect(current.data?.user.id).toBe(fixture.ids[2]);
    return {
      signups: fixture.signups,
      before,
      outcomes,
      forbidden,
      owner,
      current,
      after: await fixture.read(),
    };
  },
  [
    "POST /admin/stop-impersonating",
    "POST /admin/set-role",
    "POST /admin/create-user",
    "POST /admin/update-user",
    "POST /admin/list-user-sessions",
    "POST /admin/ban-user",
    "POST /admin/unban-user",
    "POST /admin/impersonate-user",
    "POST /admin/revoke-user-session",
    "POST /admin/revoke-user-sessions",
    "POST /admin/remove-user",
    "POST /admin/set-user-password",
    "POST /admin/has-permission",
  ],
);

compatScenario(
  "admin queries and permission alternatives validate before auth while supplied roles cannot select another owner",
  async (ctx) => {
    const fixture = await setup(ctx);
    const before = await fixture.read();
    const outcomes = [];
    for (const actor of [fixture.guest, fixture.regular]) {
      const missing = await actor.$fetch("/admin/get-user", { method: "GET" });
      rejected(
        missing,
        400,
        validation("[query.id] Invalid input: expected string, received undefined"),
      );
      const query = {
        searchField: "invalid",
        searchOperator: "invalid",
        sortDirection: "invalid",
        filterOperator: "invalid",
      };
      const list = await actor.admin.listUsers({ query } as never);
      rejected(
        list,
        400,
        validation(
          '[query.searchField] Invalid option: expected one of "email"|"name"; [query.searchOperator] Invalid option: expected one of "contains"|"starts_with"|"ends_with"; [query.sortDirection] Invalid option: expected one of "asc"|"desc"; [query.filterOperator] Invalid option: expected one of "eq"|"ne"|"lt"|"lte"|"gt"|"gte"|"in"|"not_in"|"contains"|"starts_with"|"ends_with"',
        ),
      );
      const both = await actor.admin.hasPermission({
        permission: { user: ["get"] },
        permissions: { user: ["get"] },
      } as never);
      rejected(both, 400, validation("[body] Invalid input: more than one option matched"));
      const nested = await actor.admin.hasPermission({
        role: 5,
        permissions: { user: [5] },
      } as never);
      rejected(
        nested,
        400,
        validation(
          "[body.role] Invalid input: expected string, received number; [body] Invalid input",
        ),
      );
      const singular = await actor.admin.hasPermission({
        permission: { user: ["get"] },
        permissions: { user: [5] },
      } as never);
      rejected(singular, 400, {
        message: "invalid permission check. no permission(s) were passed.",
      });
      outcomes.push({ missing, list, both, nested, singular });
    }
    const emptyGuest = await fixture.guest.admin.getUser({ query: { id: "" } });
    expect(emptyGuest.error).toEqual({ status: 401, statusText: "Unauthorized" });
    const emptyDenied = await fixture.regular.admin.getUser({ query: { id: "" } });
    expect(emptyDenied.error).toMatchObject({
      status: 403,
      code: "YOU_ARE_NOT_ALLOWED_TO_GET_USER",
    });
    const emptyOwner = await fixture.owner.admin.getUser({ query: { id: "" } });
    expect(emptyOwner.error).toMatchObject({ status: 404, code: "USER_NOT_FOUND" });
    const ownership = await fixture.regular.admin.hasPermission({
      userId: fixture.ids[0]!,
      role: "admin",
      permissions: { user: ["get"] },
      permission: { user: [5] },
    } as never);
    expect(ownership).toEqual({ data: { error: null, success: false }, error: null });
    expect(await fixture.read()).toEqual(before);
    return {
      signups: fixture.signups,
      before,
      outcomes,
      emptyGuest,
      emptyDenied,
      emptyOwner,
      ownership,
      after: await fixture.read(),
    };
  },
  ["GET /admin/get-user", "GET /admin/list-users", "POST /admin/has-permission"],
);

compatScenario(
  "admin creation validates email only after permission and literal role validation without inserting invalid owners",
  async (ctx) => {
    const actor = ctx.actor("schema-role-owner", "admin-role-manager").client;
    const regular = ctx.actor("schema-email-regular").client;
    const signup = await actor.signUp.email({
      email: ctx.uniqueEmail("schema-role-owner"),
      name: "owner",
      password: "password123",
    });
    expect(signup.error).toBeNull();
    const guest = ctx.actor("schema-role-guest", "admin-role-manager").client;
    const regularSignup = await regular.signUp.email({
      email: ctx.uniqueEmail("schema-email-regular"),
      name: "regular",
      password: "password123",
    });
    expect(regularSignup.error).toBeNull();
    const before = [
      await ctx.readUserState({ userId: signup.data!.user.id }),
      await ctx.readUserState({ userId: regularSignup.data!.user.id }),
    ];
    const absent = async (email: string) => {
      const result = await ctx.rawRequest({
        path: `/__test/admin-role-state?email=${encodeURIComponent(email)}`,
        method: "GET",
      });
      expect(result.status).toBe(200);
      expect(result.body).toEqual({ user: null, accounts: [], sessions: [] });
      return result;
    };
    const bad = { email: "not-an-address", name: "", password: "" };
    const missing = await guest.admin.createUser(bad);
    expect(missing.error).toEqual({ status: 401, statusText: "Unauthorized" });
    const denied = await regular.admin.createUser(bad);
    expect(denied.error).toMatchObject({
      status: 403,
      code: "YOU_ARE_NOT_ALLOWED_TO_CREATE_USERS",
    });
    const invalidRole = await actor.admin.createUser({ ...bad, role: "unknown-role" } as never);
    expect(invalidRole.error).toMatchObject({
      status: 400,
      code: "YOU_ARE_NOT_ALLOWED_TO_SET_NON_EXISTENT_VALUE",
    });
    const deniedState = await absent(bad.email);
    const invalidEmails = [];
    for (const email of [
      bad.email,
      "ending'@example.test",
      "double..dot@example.test",
      "local@-leading.example",
    ]) {
      const result = await actor.admin.createUser({ ...bad, email });
      rejected(result, 400, { message: "Invalid email", code: "INVALID_EMAIL" });
      invalidEmails.push({ email, result, stored: await absent(email) });
    }
    expect([
      await ctx.readUserState({ userId: signup.data!.user.id }),
      await ctx.readUserState({ userId: regularSignup.data!.user.id }),
    ]).toEqual(before);
    const email = ctx.uniqueEmail("SCHEMA-EMPTY-NAME").toUpperCase();
    const created = await actor.admin.createUser({ email, name: "", password: "" });
    expect(created.error).toBeNull();
    expect(created.data?.user).toMatchObject({
      email: email.toLowerCase(),
      name: "",
      role: "manager",
    });
    const createdId = created.data!.user.id;
    if (typeof createdId !== "string") throw Error("actual created owner required");
    const stored = await ctx.readUserState({ userId: createdId });
    expect(stored).toMatchObject({
      user: { id: createdId, email: email.toLowerCase() },
      accounts: [],
      sessions: [],
    });
    const read = await actor.admin.getUser({ query: { id: createdId } });
    expect(read.data).toMatchObject({ id: createdId, name: "", email: email.toLowerCase() });
    const issuedToken = signup.data!.token;
    if (typeof issuedToken !== "string") throw Error("actual issued owner token required");
    const current = await actor.getSession();
    expect(current.data?.session.token).toBe(issuedToken);
    return {
      signup,
      regularSignup,
      before,
      missing,
      denied,
      invalidRole,
      deniedState,
      invalidEmails,
      created,
      stored,
      read,
      current,
      after: [
        await ctx.readUserState({ userId: signup.data!.user.id }),
        await ctx.readUserState({ userId: regularSignup.data!.user.id }),
      ],
    };
  },
  ["POST /admin/create-user", "GET /admin/get-user"],
);
