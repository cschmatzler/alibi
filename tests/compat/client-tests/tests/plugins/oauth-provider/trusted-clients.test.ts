import { Cookie } from "tough-cookie";
import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "Trusted client caches preserve shared authority and reject managed mutations",
  async (ctx) => {
    const actor = ctx.actor();
    const control = (input: object) =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/oauth-provider-clients`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ mode: "trusted", ...input }),
      });
    const signup = async (label: string) => {
      const response = await control({
        action: "signup",
        body: { email: ctx.uniqueEmail(label), name: label, password: "password123" },
      });
      expect(response.status).toBe(200);
      return response.headers
        .getSetCookie()
        .filter((raw) => Boolean(Cookie.parse(raw)?.value))
        .map((raw) => raw.split(";")[0])
        .join("; ");
    };
    const owner = await signup("trusted-owner");
    const other = await signup("trusted-other");
    const created = await control({
      headers: { cookie: owner },
      body: {
        client_name: "Original trusted",
        redirect_uris: ["https://app.fixture.test/callback"],
        token_endpoint_auth_method: "client_secret_post",
      },
    });
    expect(created.status).toBe(201);
    const client = await created.json();
    expect(client.client_id).toBe("trusted-client");
    const resolve = async (input: object = {}) => {
      const response = await control({ action: "trusted-client", ...input });
      expect(response.status).toBe(200);
      return response.json();
    };
    expect(await resolve()).toEqual({ name: "Original trusted" });
    expect((await control({ action: "trusted-external-update" })).status).toBe(200);
    const cache = [];
    for (const [phase, input, name] of [
      ["cached", {}, "Original trusted"],
      ["fresh", { fresh: true }, "External update"],
      ["mutate-copy", { rename: true }, "changed return value"],
      ["copy-survives", {}, "Original trusted"],
    ] as const) {
      const result = await resolve(input);
      expect(result, phase).toEqual({ name });
      cache.push({ phase, result });
    }
    const denied = [];
    for (const [role, cookie] of [
      ["owner", owner],
      ["other", other],
    ]) {
      for (const id of ["trusted-client", "trusted-missing"]) {
        for (const action of ["update", "rotate", "delete"]) {
          const response = await control({
            action,
            headers: { cookie },
            body: {
              client_id: id,
              ...(action === "update" ? { update: { client_name: "Forbidden" } } : {}),
            },
          });
          expect(response.status, `${role}/${id}/${action}`).toBe(400);
          const body = await response.json();
          expect(body).toEqual({
            error: "invalid_client",
            error_description: "trusted clients must be updated manually",
          });
          denied.push({ role, id, action, status: response.status, body });
        }
      }
    }
    const row = await (await control({ action: "row", clientId: "trusted-client" })).json();
    expect(row.clientName).toBe("External update");
    expect((await control({ action: "trusted-external-delete" })).status).toBe(200);
    const deleted = [];
    for (const mode of ["trusted", "trusted-peer"]) {
      const result = await resolve({ mode });
      expect(result).toEqual({ name: "Original trusted" });
      const response = await control({
        mode,
        action: "introspect",
        body: {
          client_id: client.client_id,
          client_secret: client.client_secret,
          token: "not-issued",
        },
      });
      expect(response.status).toBe(200);
      const body = await response.json();
      expect(body).toEqual({ active: false });
      deleted.push({ mode, result, status: response.status, body });
    }
    expect(await resolve({ fresh: true })).toBeNull();
    return ctx.snapshot({ cache, denied, deleted, fresh: null });
  },
);
