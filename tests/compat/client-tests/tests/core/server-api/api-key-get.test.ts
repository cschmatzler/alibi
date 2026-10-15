import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";

compatScenario(
  "server API key read/delete lifecycle preserves owner authority and redaction",
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
    const owner = await signup("key-read-owner");
    const outsider = await signup("key-read-outsider");
    const response = await owner.actor.fetch(ctx.baseURL + "/api/auth/api-key/create", {
      method: "POST",
      headers: { "content-type": "application/json", ...owner.headers },
      body: JSON.stringify({
        name: "Read key",
        metadata: { purpose: "read", nested: { value: 3 } },
      }),
    });
    expect(response.status).toBe(200);
    const created = await response.json();
    const { key, ...expected } = created;
    expect(key).toBeTypeOf("string");
    async function invoke(query?: Record<string, unknown>, headers?: Record<string, string>) {
      return ctx.rawRequest({
        path: "/__test/server-api/api-key-get",
        method: "POST",
        json: { ...(query ? { query } : {}), ...(headers ? { headers } : {}) },
      });
    }
    const reads = [];
    for (const configId of [undefined, "default", "unknown-config"]) {
      const result = await invoke(
        { id: created.id, ignored: { nested: true }, ...(configId ? { configId } : {}) },
        owner.headers,
      );
      expect(result.status).toBe(200);
      expect(result.body).toEqual(expected);
      expect(result.body).not.toHaveProperty("key");
      expect(result.body).toMatchObject({
        name: "Read key",
        referenceId: owner.result.data!.user.id,
        metadata: { purpose: "read", nested: { value: 3 } },
      });
      reads.push(result);
    }
    const denied = [];
    for (const [query, headers, status, code] of [
      [undefined, undefined, 400, "VALIDATION_ERROR"],
      [{}, owner.headers, 400, "VALIDATION_ERROR"],
      [{ id: 42 }, owner.headers, 400, "VALIDATION_ERROR"],
      [{ id: created.id, configId: 42 }, owner.headers, 400, "VALIDATION_ERROR"],
      [{ id: created.id }, undefined, 401, "UNAUTHORIZED"],
      [{ id: created.id }, outsider.headers, 404, "KEY_NOT_FOUND"],
      [{ id: "missing-key" }, owner.headers, 404, "KEY_NOT_FOUND"],
      [{ id: created.id, configId: "secondary" }, owner.headers, 404, "KEY_NOT_FOUND"],
    ] as const) {
      const result = await invoke(query, headers);
      expect(result.status).toBe(status);
      expect((result.body as { code: string }).code).toBe(code);
      denied.push(result);
    }
    const after = await invoke({ id: created.id }, owner.headers);
    expect(after.status).toBe(200);
    expect(after.body).toEqual(expected);
    async function deleteKey(body?: Record<string, unknown>, headers?: Record<string, string>) {
      return ctx.rawRequest({
        path: "/__test/server-api/api-key-delete",
        method: "POST",
        json: { ...(body ? { body } : {}), ...(headers ? { headers } : {}) },
      });
    }
    const deleteDenied = [];
    for (const [body, headers, status, code] of [
      [undefined, undefined, 400, "VALIDATION_ERROR"],
      [{}, owner.headers, 400, "VALIDATION_ERROR"],
      [{ keyId: 42 }, owner.headers, 400, "VALIDATION_ERROR"],
      [{ keyId: created.id, configId: 42 }, owner.headers, 400, "VALIDATION_ERROR"],
      [{ keyId: created.id }, undefined, 401, "UNAUTHORIZED"],
      [{ keyId: created.id }, outsider.headers, 404, "KEY_NOT_FOUND"],
      [{ keyId: "missing-key" }, owner.headers, 404, "KEY_NOT_FOUND"],
      [{ keyId: created.id, configId: "secondary" }, owner.headers, 404, "KEY_NOT_FOUND"],
    ] as const) {
      const result = await deleteKey(body, headers);
      expect(result.status).toBe(status);
      expect((result.body as { code: string }).code).toBe(code);
      deleteDenied.push(result);
    }
    const retained = await invoke({ id: created.id }, owner.headers);
    expect(retained.status).toBe(200);
    expect(retained.body).toEqual(expected);
    const removed = await deleteKey(
      { keyId: created.id, ignored: { nested: true } },
      owner.headers,
    );
    expect(removed.status).toBe(200);
    expect(removed.body).toEqual({ success: true });
    const replay = await deleteKey({ keyId: created.id }, owner.headers);
    expect(replay.status).toBe(404);
    expect((replay.body as { code: string }).code).toBe("KEY_NOT_FOUND");
    const missing = await invoke({ id: created.id }, owner.headers);
    expect(missing.status).toBe(404);
    expect((missing.body as { code: string }).code).toBe("KEY_NOT_FOUND");
    return ctx.snapshot({
      owner: owner.result,
      outsider: outsider.result,
      created,
      reads,
      denied,
      after,
      deleteDenied,
      retained,
      removed,
      replay,
      missing,
    });
  },
);
