import { expect } from "bun:test";

import { compatScenario } from "../../../support/scenario";

compatScenario(
  "server listApiKeys preserves configuration scope and coerced pagination",
  async (ctx) => {
    async function signup(name: string) {
      const actor = ctx.actor(name);
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
      return { actor, result, headers: { cookie } };
    }
    const owner = await signup("key-list-owner");
    const outsider = await signup("key-list-outsider");
    const created = [];
    for (const [name, configId] of [
      ["Alpha", "default"],
      ["Beta", "secondary"],
      ["Gamma", "default"],
    ]) {
      const response = await owner.actor.fetch(ctx.baseURL + "/api/auth/api-key/create", {
        method: "POST",
        headers: { "content-type": "application/json", ...owner.headers },
        body: JSON.stringify({ name, configId, metadata: { purpose: name } }),
      });
      expect(response.status).toBe(200);
      created.push(await response.json());
    }
    async function invoke(query?: Record<string, unknown>, headers?: Record<string, string>) {
      return ctx.rawRequest({
        path: "/__test/server-api/api-key-list",
        method: "POST",
        json: { ...(query ? { query } : {}), ...(headers ? { headers } : {}) },
      });
    }
    const lists = [];
    for (const [query, names, total, limit, offset] of [
      [undefined, ["Alpha", "Beta", "Gamma"], 3, undefined, undefined],
      [{}, ["Alpha", "Beta", "Gamma"], 3, undefined, undefined],
      [{ ignored: { nested: true } }, ["Alpha", "Beta", "Gamma"], 3, undefined, undefined],
      [{ sortBy: "name", sortDirection: "asc", offset: "1", limit: "1" }, ["Beta"], 3, 1, 1],
      [
        { configId: "default", sortBy: "name", sortDirection: "desc" },
        ["Gamma", "Alpha"],
        2,
        undefined,
        undefined,
      ],
      [{ configId: "secondary" }, ["Beta"], 1, undefined, undefined],
      [{ configId: "unknown-config" }, [], 0, undefined, undefined],
      [{ sortBy: "name", offset: true, limit: [1] }, ["Beta"], 3, 1, 1],
      [{ limit: null }, [], 3, 0, undefined],
      [{ limit: "" }, [], 3, 0, undefined],
      [{ sortBy: "name", limit: "0x1" }, ["Alpha"], 3, 1, undefined],
      [{ offset: 99 }, [], 3, undefined, 99],
    ] as const) {
      const result = await invoke(query, owner.headers);
      expect(result.status).toBe(200);
      const body = result.body as {
        apiKeys: Array<{ name: string; metadata: { purpose: string }; key?: string }>;
        total: number;
        limit?: number;
        offset?: number;
      };
      expect(body.apiKeys.map((key) => key.name)).toEqual([...names]);
      expect(body.total).toBe(total);
      expect(body.limit).toBe(limit);
      expect(body.offset).toBe(offset);
      for (const key of body.apiKeys) {
        expect(key.key).toBeUndefined();
        expect(key.metadata.purpose).toBe(key.name);
      }
      lists.push(result);
    }
    const denied = [];
    for (const [query, status, code] of [
      [undefined, 401, "UNAUTHORIZED"],
      [{ limit: -1 }, 400, "VALIDATION_ERROR"],
      [{ limit: 1.5 }, 400, "VALIDATION_ERROR"],
      [{ limit: "bad-number" }, 400, "VALIDATION_ERROR"],
      [{ limit: 1e16 }, 400, "VALIDATION_ERROR"],
      [{ configId: null }, 400, "VALIDATION_ERROR"],
      [{ organizationId: 42 }, 400, "VALIDATION_ERROR"],
      [{ sortBy: null }, 400, "VALIDATION_ERROR"],
      [{ sortDirection: "ASC" }, 400, "VALIDATION_ERROR"],
    ] as const) {
      const result = await invoke(query);
      expect(result.status).toBe(status);
      expect((result.body as { code: string }).code).toBe(code);
      denied.push(result);
    }
    const empty = await invoke(undefined, outsider.headers);
    expect(empty.status).toBe(200);
    expect(empty.body).toEqual({ apiKeys: [], total: 0 });
    const retained = await invoke({ sortBy: "name" }, owner.headers);
    expect(retained.status).toBe(200);
    expect(retained.body).toEqual(lists[0]!.body);
    return ctx.snapshot({
      owner: owner.result,
      outsider: outsider.result,
      created,
      lists,
      denied,
      empty,
      retained,
    });
  },
);
