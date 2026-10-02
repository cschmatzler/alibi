import { expect } from "bun:test";
import { createAuthClient } from "better-auth/client";
import { adminClient } from "better-auth/client/plugins";
import { createAccessControl } from "better-auth/plugins/access";
import { z } from "zod";
import { authProfilePath, type FixtureProfile } from "../../support/profiles";
import { compatScenario, type ScenarioContext } from "../../support/scenario";

const access = createAccessControl({
  user: ["get", "create", "set-role", "update"],
});
const roles: Record<string, ReturnType<typeof access.newRole>> = {
  manager: access.newRole({ user: ["get", "create", "set-role", "update"] }),
  creator: access.newRole({ user: ["create"] }),
  user: access.newRole({ user: ["get"] }),
};
function client(ctx: ScenarioContext, profile: FixtureProfile, name: string) {
  return createAuthClient({
    baseURL: `${ctx.baseURL}${authProfilePath(profile)}`,
    plugins: [adminClient({ ac: access, roles })],
    fetchOptions: { customFetchImpl: ctx.actor(name, profile).fetch },
  });
}
async function signup(ctx: ScenarioContext, profile: FixtureProfile, name: string) {
  const current = client(ctx, profile, name),
    email = ctx.uniqueEmail(`${profile}-${name}`);
  const result = await current.signUp.email({
    email,
    password: "password123",
    name,
  });
  expect(result.error).toBeNull();
  if (!result.data) throw new Error("owner required");
  return { client: current, email, result, userId: result.data.user.id };
}
async function state(ctx: ScenarioContext, email: string) {
  const result = await ctx.rawRequest({
    path: `/__test/admin-role-state?email=${encodeURIComponent(email)}`,
    method: "GET",
  });
  expect(result.status).toBe(200);
  return result.body;
}
const stored = z.object({
  user: z.object({ id: z.string(), role: z.string().nullable() }),
  accounts: z.array(z.object({ userId: z.string() })),
  sessions: z.array(z.object({ userId: z.string(), token: z.string() })),
});
function absent(value: unknown) {
  expect(value).toEqual({ user: null, accounts: [], sessions: [] });
}

compatScenario(
  "admin configured role values retain literal strings and array elements before any target mutation",
  async (ctx) => {
    const owner = await signup(ctx, "admin-role-manager", "owner"),
      target = await signup(ctx, "admin-standard", "target");
    const before = await state(ctx, target.email),
      observations = [];
    for (const role of ["manager,user", ["manager,user"], " manager", [" user"]]) {
      const set = await owner.client.admin.setRole({
        userId: target.userId,
        role,
      });
      expect(set.error?.status).toBe(400);
      expect(set.error?.code).toBe("YOU_ARE_NOT_ALLOWED_TO_SET_NON_EXISTENT_VALUE");
      const update = await owner.client.admin.updateUser({
        userId: target.userId,
        data: { role },
      });
      expect(update.error?.status).toBe(400);
      expect(update.error?.code).toBe("YOU_ARE_NOT_ALLOWED_TO_SET_NON_EXISTENT_VALUE");
      const after = await state(ctx, target.email);
      expect(after).toEqual(before);
      observations.push({ role, set, update, after });
    }
    const array = await owner.client.admin.setRole({
      userId: target.userId,
      role: ["user", "manager"],
    });
    expect(array.error).toBeNull();
    expect(array.data?.user.role).toBe("user,manager");
    const arrayState = await state(ctx, target.email);
    expect(stored.parse(arrayState).user).toMatchObject({
      id: target.userId,
      role: "user,manager",
    });
    const emptyValues = [];
    for (const role of [[], "", [""]]) {
      const accepted = await owner.client.admin.setRole({
        userId: target.userId,
        role,
      });
      expect(accepted.error).toBeNull();
      expect(accepted.data?.user.role).toBe("");
      const persisted = await state(ctx, target.email);
      expect(stored.parse(persisted).user.role).toBe("");
      expect(stored.parse(persisted).sessions[0]?.token).toBe(
        target.result.data?.token ?? undefined,
      );
      emptyValues.push({ role, accepted, persisted });
    }
    const current = await owner.client.getSession();
    expect(current.data?.user.id).toBe(owner.userId);
    expect(current.data?.user.role).toBe("manager");
    return ctx.snapshot({
      signup: owner.result,
      target: target.result,
      before,
      observations,
      array,
      arrayState,
      emptyValues,
      current,
    });
  },
  ["POST /admin/set-role", "POST /admin/update-user"],
);

compatScenario(
  "admin create validates explicit and nested roles before lookup and persists legitimate array ownership",
  async (ctx) => {
    const owner = await signup(ctx, "admin-role-manager", "owner"),
      denied = [];
    for (const [index, input] of [
      { role: "manager,user" },
      { data: { role: "manager,user" } },
      { role: [" user"] },
    ].entries()) {
      const email = ctx.uniqueEmail(`denied-role-${index}`),
        result = await owner.client.admin.createUser({
          email,
          password: "password123",
          name: "Denied",
          ...input,
        });
      expect(result.error?.status).toBe(400);
      expect(result.error?.code).toBe("YOU_ARE_NOT_ALLOWED_TO_SET_NON_EXISTENT_VALUE");
      const persisted = await state(ctx, email);
      absent(persisted);
      denied.push({ input, result, persisted });
    }
    const email = ctx.uniqueEmail("legitimate-role"),
      created = await owner.client.admin.createUser({
        email,
        password: "password123",
        name: "Legitimate",
        role: ["user"],
        data: { role: "manager,user" },
      });
    expect(created.error).toBeNull();
    if (!created.data) throw new Error("created owned account required");
    expect(created.data.user.role).toBe("user");
    const nestedEmail = ctx.uniqueEmail("nested-legitimate-role");
    const nestedCreated = await owner.client.admin.createUser({
      email: nestedEmail,
      password: "password123",
      name: "Nested",
      data: { role: ["user"] },
    });
    expect(nestedCreated.error).toBeNull();
    expect(nestedCreated.data?.user.role).toBe("user");
    const nestedState = await state(ctx, nestedEmail);
    expect(stored.parse(nestedState).user.role).toBe("user");
    expect(stored.parse(nestedState).accounts).toHaveLength(1);
    const emptyEmail = ctx.uniqueEmail("empty-precedence-role");
    const emptyCreated = await owner.client.admin.createUser({
      email: emptyEmail,
      name: "Empty precedence",
      role: "",
      data: { role: ["manager"] },
    });
    expect(emptyCreated.error).toBeNull();
    expect(emptyCreated.data?.user.role).toBe("");
    const emptyState = await state(ctx, emptyEmail);
    expect(stored.parse(emptyState).user.role).toBe("");
    const invalidTypes = [];
    for (const role of [null, { unexpected: "manager" }]) {
      const invalidEmail = ctx.uniqueEmail("invalid-nested-type");
      const invalid = await owner.client.admin.createUser({
        email: invalidEmail,
        name: "Invalid type",
        data: { role },
      });
      expect(invalid.error?.status).toBe(400);
      expect(invalid.error?.code).toBe("INVALID_ROLE_TYPE");
      const persistedInvalid = await state(ctx, invalidEmail);
      absent(persistedInvalid);
      invalidTypes.push({ role, invalid, persisted: persistedInvalid });
    }
    const newClient = client(ctx, "admin-role-manager", "created"),
      signin = await newClient.signIn.email({ email, password: "password123" });
    expect(signin.error).toBeNull();
    expect(signin.data?.user.id).toBe(created.data.user.id);
    const permitted = await newClient.admin.hasPermission({
      permissions: { user: ["get"] },
    });
    expect(permitted.data?.success).toBe(true);
    const forbidden = await newClient.admin.hasPermission({
      permissions: { user: ["create"] },
    });
    expect(forbidden.data?.success).toBe(false);
    const persisted = await state(ctx, email),
      decoded = stored.parse(persisted);
    expect(decoded.user).toMatchObject({
      id: created.data.user.id,
      role: "user",
    });
    expect(decoded.accounts).toHaveLength(1);
    expect(decoded.accounts[0]?.userId).toBe(created.data.user.id);
    expect(decoded.sessions).toHaveLength(1);
    expect(decoded.sessions[0]?.userId).toBe(created.data.user.id);
    const duplicate = await owner.client.admin.createUser({
      email,
      password: "password123",
      name: "Wrong duplicate",
      role: "manager,user",
    });
    expect(duplicate.error?.code).toBe("YOU_ARE_NOT_ALLOWED_TO_SET_NON_EXISTENT_VALUE");
    expect(await state(ctx, email)).toEqual(persisted);
    return ctx.snapshot({
      signup: owner.result,
      denied,
      created,
      nestedCreated,
      nestedState,
      emptyCreated,
      emptyState,
      invalidTypes,
      signin,
      permitted,
      forbidden,
      persisted,
      duplicate,
    });
  },
  ["POST /admin/create-user"],
);

compatScenario(
  "admin create-only grant cannot select explicit or nested roles and retains default creation",
  async (ctx) => {
    const owner = await signup(ctx, "admin-role-creator", "owner"),
      before = await state(ctx, owner.email);
    const defaultEmail = ctx.uniqueEmail("default-created"),
      created = await owner.client.admin.createUser({
        email: defaultEmail,
        password: "password123",
        name: "Default",
      });
    expect(created.error).toBeNull();
    expect(created.data?.user.role).toBe("creator");
    const defaultState = await state(ctx, defaultEmail);
    expect(stored.parse(defaultState).accounts).toHaveLength(1);
    const denied = [];
    for (const [index, input] of [
      { role: "manager" },
      { role: "" },
      { data: { role: "manager" } },
      { data: { role: null } },
      { data: { role: { unexpected: "manager" } } },
      { role: [], data: { role: "user" } },
    ].entries()) {
      const email = ctx.uniqueEmail(`forbidden-role-${index}`),
        result = await owner.client.admin.createUser({
          email,
          password: "password123",
          name: "Forbidden",
          ...input,
        });
      expect(result.error?.status).toBe(403);
      expect(result.error?.code).toBe("YOU_ARE_NOT_ALLOWED_TO_CHANGE_USERS_ROLE");
      const persisted = await state(ctx, email);
      absent(persisted);
      denied.push({ input, result, persisted });
    }
    const duplicate = await owner.client.admin.createUser({
      email: defaultEmail,
      name: "Forbidden duplicate",
      data: { role: "user" },
    });
    expect(duplicate.error?.status).toBe(403);
    expect(duplicate.error?.code).toBe("YOU_ARE_NOT_ALLOWED_TO_CHANGE_USERS_ROLE");
    expect(await state(ctx, defaultEmail)).toEqual(defaultState);
    const after = await state(ctx, owner.email);
    expect(after).toEqual(before);
    const current = await owner.client.getSession();
    expect(current.data?.user.id).toBe(owner.userId);
    expect(current.data?.session.token).toBe(stored.parse(before).sessions[0]?.token);
    return ctx.snapshot({
      signup: owner.result,
      before,
      created,
      defaultState,
      denied,
      duplicate,
      after,
      current,
    });
  },
  ["POST /admin/create-user"],
);

compatScenario(
  "admin unconfigured role table accepts empty role strings and arrays without inventing validation",
  async (ctx) => {
    const owner = await signup(ctx, "admin-standard", "owner"),
      target = await signup(ctx, "admin-standard", "target"),
      observations = [];
    for (const role of ["", [], [""], " user", "user,admin"]) {
      const result = await owner.client.admin.setRole({
        userId: target.userId,
        role,
      });
      expect(result.error).toBeNull();
      expect(result.data?.user.role).toBe(Array.isArray(role) ? role.join(",") : role);
      const persisted = await state(ctx, target.email);
      expect(stored.parse(persisted).user.role).toBe(Array.isArray(role) ? role.join(",") : role);
      expect(stored.parse(persisted).sessions[0]?.token).toBe(
        target.result.data?.token ?? undefined,
      );
      observations.push({ role, result, persisted });
    }
    return ctx.snapshot({
      signup: owner.result,
      target: target.result,
      observations,
    });
  },
  ["POST /admin/set-role"],
);
