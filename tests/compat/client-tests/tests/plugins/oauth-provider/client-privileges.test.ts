import { Cookie } from "tough-cookie";
import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";

compatScenario(
  "Client privilege policy gates real management actions before durable effects",
  async (ctx) => {
    const actor = ctx.actor();
    const control = (input: unknown) =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/oauth-provider-clients`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ mode: "client-policy", ...(input as object) }),
      });
    const signup = async (label: string) => {
      const email = ctx.uniqueEmail(label);
      const r = await control({
        action: "signup",
        body: { email, name: label, password: "password123" },
      });
      expect(r.status).toBe(200);
      const value = (await r.json()) as any;
      const cookie = r.headers
        .getSetCookie()
        .filter((raw) => Boolean(Cookie.parse(raw)?.value))
        .map((raw) => raw.split(";")[0])
        .join("; ");
      return { cookie, user: value.user };
    };
    const owner = await signup("client-policy-owner");
    const other = await signup("client-policy-other");
    const headers = (decision: string, cookie = owner.cookie) => ({
      cookie,
      "x-client-decision": decision,
      "x-policy-caller": "sdk",
    });
    const metadata = { client_name: "Original", grant_types: ["client_credentials"] };
    const created = await control({
      action: "admin-create",
      headers: headers("true"),
      body: metadata,
    });
    expect(created.status).toBe(201);
    const client = (await created.json()) as any;
    const row = () => control({ action: "row", clientId: client.client_id }).then((r) => r.json());
    const before = await row();
    const calls = () =>
      control({ action: "client-policy-calls" }).then((r) => r.json() as Promise<any[]>);
    await calls();
    const results = [];
    for (const [operation, action, body, query] of [
      ["create", "create", metadata, undefined],
      ["admin-create", "create", metadata, undefined],
      ["register", "create", metadata, undefined],
      ["get", "read", undefined, { client_id: client.client_id }],
      ["list", "list", undefined, undefined],
      [
        "update",
        "update",
        { client_id: client.client_id, update: { client_name: "Changed" } },
        undefined,
      ],
      [
        "admin-update",
        "update",
        { client_id: client.client_id, update: { client_name: "Changed" } },
        undefined,
      ],
      ["rotate", "rotate", { client_id: client.client_id }, undefined],
      ["delete", "delete", { client_id: client.client_id }, undefined],
    ] as const) {
      for (const [decision, status] of [
        ["false", 401],
        ["native-error", 403],
        ["api-error", 403],
        ["upstream-error", 503],
        ["ordinary-error", 500],
      ] as const) {
        const r = await control({
          action: operation,
          body,
          query,
          headers: headers(decision),
          captureError: decision === "ordinary-error",
        });
        expect(r.status, `${operation}/${decision}`).toBe(
          decision === "ordinary-error" ? 200 : status,
        );
        const text = await r.text();
        if (decision === "false") expect(text).toBe("");
        if (decision === "ordinary-error") {
          expect(JSON.parse(text)).toEqual({ ordinaryError: "client policy failed" });
        }
        const observed = await calls();
        expect(observed).toHaveLength(1);
        expect(observed[0]).toMatchObject({
          action,
          decision,
          caller: "sdk",
          user: { id: owner.user.id, email: owner.user.email },
          session: { userId: owner.user.id },
        });
        expect(observed[0].session.id).toBeTruthy();
        expect(observed[0].session.token).toBeTruthy();
        expect(await row()).toEqual(before);
        results.push({
          operation,
          decision,
          status,
          body: text ? JSON.parse(text) : null,
          // Actions on an existing client receive its requested client_id.
          clientId: observed[0].clientId ?? null,
        });
      }
    }
    const ordering = [];
    for (const [body, cookie, decision, status, called] of [
      [
        { client_id: client.client_id, update: { client_name: 42 } },
        owner.cookie,
        "false",
        400,
        false,
      ],
      [{ client_id: client.client_id, update: {} }, "", "false", 401, false],
      [{ client_id: "missing", update: {} }, owner.cookie, "false", 401, true],
      [
        { client_id: client.client_id, update: { client_name: "foreign" } },
        other.cookie,
        "true",
        401,
        true,
      ],
      [
        { client_id: client.client_id, update: { client_credentials_scopes: ["email"] } },
        owner.cookie,
        "true",
        400,
        true,
      ],
    ] as const) {
      const r = await control({ action: "admin-update", body, headers: headers(decision, cookie) });
      expect(r.status).toBe(status);
      const observed = await calls();
      expect(observed).toHaveLength(called ? 1 : 0);
      expect(await row()).toEqual(before);
      ordering.push({ status, called });
    }
    const scopeDenials = [];
    for (const [action, body, expected] of [
      [
        "admin-create",
        { grant_types: ["client_credentials"], client_credentials_scopes: ["api:read"] },
        ["create", "configure-client-credentials-scopes"],
      ],
      [
        "admin-update",
        {
          client_id: client.client_id,
          update: { client_name: "Forbidden", client_credentials_scopes: ["api:read"] },
        },
        ["update", "configure-client-credentials-scopes"],
      ],
    ] as const) {
      const r = await control({ action, body, headers: headers("deny-scopes") });
      expect(r.status).toBe(401);
      expect(await r.text()).toBe("");
      const observed = (await calls()).map((v) => v.action);
      expect(observed).toEqual(expected);
      expect(await row()).toEqual(before);
      scopeDenials.push(observed);
    }
    const crossOwner = [];
    for (const [update, decision, status, actions] of [
      [
        { client_name: "foreign", client_credentials_scopes: ["api:read"] },
        "true",
        401,
        ["update"],
      ],
      [
        { client_credentials_scopes: ["email"] },
        "deny-scopes",
        401,
        ["update", "configure-client-credentials-scopes"],
      ],
      [
        { client_credentials_scopes: ["email"] },
        "true",
        400,
        ["update", "configure-client-credentials-scopes"],
      ],
    ] as const) {
      const r = await control({
        action: "admin-update",
        headers: headers(decision, other.cookie),
        body: { client_id: client.client_id, update },
      });
      expect(r.status).toBe(status);
      expect((await calls()).map((v) => v.action)).toEqual(actions);
      expect(await row()).toEqual(before);
      crossOwner.push({ status, actions });
    }
    for (const scopes of [["api:write"], []]) {
      const r = await control({
        action: "admin-update",
        headers: headers("true", other.cookie),
        body: { client_id: client.client_id, update: { client_credentials_scopes: scopes } },
      });
      expect(r.status).toBe(200);
      expect(((await r.json()) as any).client_credentials_scopes).toEqual(scopes);
      expect((await calls()).map((v) => v.action)).toEqual([
        "update",
        "configure-client-credentials-scopes",
      ]);
      const read = await control({
        action: "admin-update",
        headers: headers("true"),
        body: { client_id: client.client_id, update: {} },
      });
      expect(read.status).toBe(200);
      expect(((await read.json()) as any).client_credentials_scopes).toEqual(scopes);
      expect((await calls()).map((v) => v.action)).toEqual(["update"]);
      expect(await row()).toEqual(before);
      crossOwner.push({ scopes });
    }
    const updated = await control({
      action: "admin-update",
      headers: headers("true"),
      body: {
        client_id: client.client_id,
        update: { client_name: "Allowed", client_credentials_scopes: ["api:read"] },
      },
    });
    expect(updated.status).toBe(200);
    const value = (await updated.json()) as any;
    expect(value.client_credentials_scopes).toEqual(["api:read"]);
    expect((await calls()).map((v) => v.action)).toEqual([
      "update",
      "configure-client-credentials-scopes",
    ]);
    expect(await row()).toEqual({ ...(before as object), clientName: "Allowed" });
    // Authenticated DCR participates; anonymous DCR and public reads do not.
    const publicRead = await control({
      action: "public",
      query: { client_id: client.client_id },
      headers: headers("false"),
    });
    expect(publicRead.status).toBe(200);
    const anonymous = await control({
      action: "register",
      headers: headers("false", ""),
      body: { redirect_uris: ["https://app.fixture.test/callback"] },
    });
    expect(anonymous.status).toBe(201);
    expect(await calls()).toEqual([]);
    return {
      results,
      ordering,
      scopeDenials,
      crossOwner,
      updated: ctx.snapshot(value),
      row: ctx.snapshot(await row()),
    };
  },
);
