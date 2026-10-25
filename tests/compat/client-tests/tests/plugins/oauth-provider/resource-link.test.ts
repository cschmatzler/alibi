import { Cookie } from "tough-cookie";
import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "Linking a client durably admits its resource and repeated linkage is idempotent",
  async (ctx) => {
    const actor = ctx.actor();
    const control = (input: unknown) =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/oauth-provider-clients`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(input),
      });
    const signup = await control({
      action: "signup",
      body: {
        email: ctx.uniqueEmail("resource-link-owner"),
        name: "Owner",
        password: "password123",
      },
    });
    expect(signup.status).toBe(200);
    const cookie = signup.headers
      .getSetCookie()
      .filter((raw) => Boolean(Cookie.parse(raw)?.value))
      .map((raw) => raw.split(";")[0])
      .join("; ");
    const other = await control({
      action: "signup",
      body: {
        email: ctx.uniqueEmail("resource-link-other"),
        name: "Other",
        password: "password123",
      },
    });
    expect(other.status).toBe(200);
    const otherCookie = other.headers
      .getSetCookie()
      .filter((raw) => Boolean(Cookie.parse(raw)?.value))
      .map((raw) => raw.split(";")[0])
      .join("; ");
    const identifier = "https://api.fixture.test/link";
    const resource = await control({
      action: "resource-create",
      headers: { cookie },
      body: { identifier, allowedScopes: ["email"] },
    });
    expect(resource.status).toBe(200);
    const created = await control({
      headers: { cookie },
      body: {
        client_name: "Linked client",
        redirect_uris: ["https://app.fixture.test/callback"],
        scope: "email",
        token_endpoint_auth_method: "none",
      },
    });
    expect(created.status).toBe(201);
    const client = (await created.json()) as any;
    const id = client.client_id;
    const query = {
      client_id: id,
      response_type: "code",
      redirect_uri: "https://app.fixture.test/callback",
      scope: "email",
      resource: identifier,
      code_challenge: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
      code_challenge_method: "S256",
    };
    const blocked = await control({
      action: "authorize",
      query,
      headers: { accept: "application/json" },
    });
    expect(blocked.status).toBe(200);
    const denied = (await blocked.json()) as any;
    const deniedURL = new URL(denied.url, ctx.baseURL);
    expect(deniedURL.searchParams.get("error")).toBe("invalid_target");
    expect(deniedURL.searchParams.get("error_description")).toBe(
      `client ${id} is not linked to resource(s) ${identifier}`,
    );
    const failures = [];
    for (const [params, headers, status, error] of [
      [{ identifier: "urn:fixture:missing", client_id: id }, { cookie }, 404, "not_found"],
      [{ identifier, client_id: "unknown-client" }, { cookie }, 404, "not_found"],
      [{ identifier, client_id: id }, {}, 401, null],
    ] as const) {
      const r = await control({ action: "resource-link", params, headers });
      expect(r.status).toBe(status);
      const text = await r.text();
      const value = text ? JSON.parse(text) : null;
      if (error) {
        expect(value.error).toBe(error);
      }
      failures.push({ status: r.status, body: value });
    }
    const empty = await control({ action: "resource-links", clientId: id });
    expect(await empty.json()).toEqual([]);
    const hidden = await control({
      action: "resource-http",
      operation: "link",
      identifier,
      clientId: id,
      headers: { cookie },
    });
    expect(await hidden.json()).toEqual({ status: 404 });
    const start = Date.now();
    const linked = await control({
      action: "resource-link",
      params: { identifier: encodeURIComponent(identifier), client_id: encodeURIComponent(id) },
      headers: { cookie: otherCookie },
    });
    expect(linked.status).toBe(200);
    const result = await linked.json();
    expect(result).toEqual({ linked: true });
    const rowsResponse = await control({ action: "resource-links", clientId: id });
    const rows = (await rowsResponse.json()) as any[];
    expect(rows).toHaveLength(1);
    expect(rows[0].clientId).toBe(id);
    expect(rows[0].resourceId).toBe(identifier);
    expect(rows[0].metadata).toBeNull();
    expect(new Date(rows[0].createdAt).getTime()).toBeGreaterThanOrEqual(start);
    expect(new Date(rows[0].createdAt).getTime()).toBeLessThanOrEqual(Date.now());
    const repeated = await control({
      action: "resource-link",
      params: { identifier, client_id: id },
      headers: { cookie },
    });
    expect(repeated.status).toBe(200);
    const duplicate = await repeated.json();
    expect(duplicate).toEqual({ linked: true, alreadyLinked: true });
    const unchanged = await control({ action: "resource-links", clientId: id });
    expect(await unchanged.json()).toEqual(rows);
    const allowed = await control({
      action: "authorize",
      query,
      headers: { accept: "application/json" },
    });
    expect(allowed.status).toBe(200);
    const redirect = (await allowed.json()) as any;
    expect(new URL(redirect.url, ctx.baseURL).pathname).toBe("/login");
    const removed = await control({
      action: "resource-delete",
      foreignKeys: true,
      params: { identifier },
      headers: { cookie },
    });
    expect(await removed.json()).toEqual({ deleted: true });
    const cascaded = await control({ action: "resource-links", clientId: id });
    expect(await cascaded.json()).toEqual([]);
    const stillExists = await control({
      action: "get",
      query: { client_id: id },
      headers: { cookie },
    });
    expect(stillExists.status).toBe(200);
    const { createdAt, ...link } = rows[0];
    return ctx.snapshot({ failures, result, duplicate, link, redirect });
  },
);

compatScenario(
  "Configured resource privileges gate the catalog and durable client-resource authority",
  async (ctx) => {
    const actor = ctx.actor();
    const control = (input: Record<string, unknown>) =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/oauth-provider-clients`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ mode: "resource-privileges", ...input }),
      });
    const signup = async (name: string) => {
      const response = await control({
        action: "signup",
        body: { email: ctx.uniqueEmail(name), name, password: "password123" },
      });
      expect(response.status).toBe(200);
      const cookie = response.headers
        .getSetCookie()
        .filter((raw) => Boolean(Cookie.parse(raw)?.value))
        .map((raw) => raw.split(";")[0])
        .join("; ");
      return { cookie, user: ((await response.json()) as any).user };
    };
    const owner = await signup("resource-policy-owner");
    const other = await signup("resource-policy-other");
    const headers = (decision: string, cookie = other.cookie) => ({
      cookie,
      "x-resource-decision": decision,
      "x-policy-caller": "paired",
    });
    const identifier = "https://api.fixture.test/privileges";
    const created = await control({
      action: "resource-create",
      headers: headers("true", owner.cookie),
      body: { identifier, allowedScopes: ["email"] },
    });
    expect(created.status).toBe(200);
    const resource = (await created.json()) as any;
    const clientResponse = await control({
      headers: headers("false", owner.cookie),
      body: {
        client_name: "Resource policy client",
        redirect_uris: ["https://app.fixture.test/callback"],
        scope: "email",
        token_endpoint_auth_method: "none",
      },
    });
    expect(clientResponse.status).toBe(201);
    const client = (await clientResponse.json()) as any;
    const params = {
      identifier: encodeURIComponent(identifier),
      client_id: encodeURIComponent(client.client_id),
    };
    const linked = await control({ action: "resource-link", params, headers: headers("true") });
    expect(await linked.json()).toEqual({ linked: true });
    const calls = async () => {
      const response = await control({ action: "resource-privileges-state" });
      return (await response.json()) as any[];
    };
    const initialCalls = await calls();
    expect(initialCalls.map((call) => call.action)).toEqual(["create", "link"]);
    const state = async () => {
      const resourceResponse = await control({ action: "resource-row", identifier });
      const linkResponse = await control({ action: "resource-links", clientId: client.client_id });
      const clientResponse = await control({ action: "row", clientId: client.client_id });
      return {
        resource: await resourceResponse.json(),
        links: await linkResponse.json(),
        client: await clientResponse.json(),
      };
    };
    const before = await state();
    const operations = [
      {
        action: "resource-create",
        privilege: "create",
        body: { identifier: "urn:fixture:new-policy" },
      },
      { action: "resource-list", privilege: "list" },
      { action: "resource-get", privilege: "read", params },
      {
        action: "resource-update",
        privilege: "update",
        params,
        body: { name: "Allowed", identifier: "urn:fixture:ignored", unknown: "filtered" },
      },
      { action: "resource-delete", privilege: "delete", params },
      { action: "resource-link", privilege: "link", params },
      { action: "resource-unlink", privilege: "unlink", params },
    ];
    const trace = [];
    const checkCalls = async (action: string, resourceId: string | null, decision: string) => {
      const observed = await calls();
      expect(observed).toHaveLength(1);
      const call = observed[0];
      expect(call).toMatchObject({
        action,
        resourceId,
        decision,
        caller: "paired",
        user: { id: other.user.id, email: other.user.email },
        session: { userId: other.user.id },
      });
      const session = await control({ action: "session-row", token: call.session.token });
      expect(await session.json()).toEqual({ id: call.session.id });
      return observed;
    };
    for (const operation of operations) {
      for (const [decision, status] of [
        ["false", 401],
        ["native-error", 403],
        ["api-error", 403],
        ["upstream-error", 503],
        ["ordinary-error", 200],
      ] as const) {
        const response = await control({
          ...operation,
          headers: headers(decision),
          captureError: true,
        });
        expect(response.status, `${operation.action}/${decision}`).toBe(status);
        const text = await response.text();
        const value = text ? JSON.parse(text) : null;
        if (decision === "false") expect(value).toBeNull();
        if (decision === "native-error") {
          expect(value).toEqual({ message: "Resource denied" });
        }
        if (decision === "api-error") {
          expect(value).toEqual({ code: "RESOURCE_DENIED", message: "Resource denied" });
        }
        if (decision === "upstream-error") {
          expect(value).toEqual({ code: "RESOURCE_UNAVAILABLE", message: "Resource unavailable" });
        }
        if (decision === "ordinary-error") {
          expect(value).toEqual({ ordinaryError: "resource policy failed" });
        }
        const observed = await checkCalls(
          operation.privilege,
          "params" in operation ? identifier : null,
          decision,
        );
        expect(await state()).toEqual(before);
        const missing = await control({
          action: "resource-row",
          identifier: "urn:fixture:new-policy",
        });
        expect(await missing.json()).toBeNull();
        trace.push({ action: operation.action, decision, status, value, calls: observed });
      }
    }
    for (const [input, decision, status, called] of [
      [{ action: "resource-create", body: { identifier: 42 } }, "false", 400, false],
      [
        { action: "resource-create", body: { identifier: "urn:fixture:new", accessTokenTtl: 0 } },
        "false",
        400,
        false,
      ],
      [{ action: "resource-update", params, body: { name: 42 } }, "false", 400, false],
      [{ action: "resource-get", params, headers: {} }, "false", 401, false],
      [{ action: "resource-list" }, "false", 401, false],
      [{ action: "resource-create", body: { identifier: "/relative" } }, "false", 401, true],
      [{ action: "resource-create", body: { identifier } }, "false", 401, true],
      [
        { action: "resource-get", params: { identifier: "urn:fixture:missing" } },
        "false",
        401,
        true,
      ],
      [
        {
          action: "resource-link",
          params: { identifier: "urn:fixture:missing", client_id: "missing" },
        },
        "false",
        401,
        true,
      ],
      [
        { action: "resource-link", params: { identifier, client_id: "missing" } },
        "false",
        401,
        true,
      ],
      [{ action: "resource-create", body: { identifier: "/relative" } }, "true", 400, true],
      [{ action: "resource-create", body: { identifier } }, "true", 400, true],
      [{ action: "resource-get", params: { identifier: "bad%XX" } }, "true", 404, true],
      [
        {
          action: "resource-link",
          params: { identifier: "urn:fixture:missing", client_id: "missing" },
        },
        "true",
        404,
        true,
      ],
      [
        { action: "resource-link", params: { identifier, client_id: "missing" } },
        "true",
        404,
        true,
      ],
    ] as const) {
      const response = await control({
        headers: headers(decision),
        ...input,
        ...(input.action === "resource-list" ? { headers: undefined } : {}),
      });
      expect(response.status).toBe(status);
      const text = await response.text();
      const value = text ? JSON.parse(text) : null;
      const observed = await calls();
      expect(observed).toHaveLength(called ? 1 : 0);
      expect(await state()).toEqual(before);
      trace.push({ action: input.action, decision, status, value, calls: observed });
    }
    const allowed = [];
    for (const operation of operations.filter((operation) => operation.privilege !== "delete")) {
      const response = await control({ ...operation, headers: headers("true") });
      expect(response.status).toBe(200);
      const value = (await response.json()) as any;
      await checkCalls(operation.privilege, "params" in operation ? identifier : null, "true");
      if (operation.privilege === "create") expect(value.identifier).toBe("urn:fixture:new-policy");
      if (operation.privilege === "list") expect(value).toHaveLength(2);
      if (operation.privilege === "read") expect(value).toEqual(resource);
      if (operation.privilege === "update") {
        expect(value.name).toBe("Allowed");
        expect(value.identifier).toBe(identifier);
        expect(value).not.toHaveProperty("unknown");
        expect(value.allowedScopes).toEqual(["email"]);
        const row = await control({ action: "resource-row", identifier });
        expect(await row.json()).toEqual(value);
      }
      if (operation.privilege === "link") {
        expect(value).toEqual({ linked: true, alreadyLinked: true });
        expect((await state()).links).toEqual(before.links);
      }
      if (operation.privilege === "unlink") {
        expect(value).toEqual({ unlinked: true });
        expect((await state()).links).toEqual([]);
      }
      allowed.push({ action: operation.action, value });
    }
    for (let index = 0; index < 2; index++) {
      const response = await control({
        action: "resource-unlink",
        params: { identifier: "urn:fixture:missing", client_id: "missing" },
        headers: headers("true"),
      });
      expect(await response.json()).toEqual({ unlinked: true });
    }
    const relinked = await control({ action: "resource-link", params, headers: headers("true") });
    expect(await relinked.json()).toEqual({ linked: true });
    const removed = await control({
      action: "resource-delete",
      params,
      foreignKeys: true,
      headers: headers("true"),
    });
    expect(await removed.json()).toEqual({ deleted: true });
    const after = await state();
    expect(after.resource).toBeNull();
    expect(after.links).toEqual([]);
    expect(after.client).toEqual(before.client);
    return ctx.snapshot({ initialCalls, trace, allowed, after });
  },
);
compatScenario(
  "Administrative client creation links requested resources and validates resource identifiers",
  async (ctx) => {
    const actor = ctx.actor();
    const control = (input: unknown) =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/oauth-provider-clients`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(input),
      });
    const signup = await control({
      action: "signup",
      body: {
        email: ctx.uniqueEmail("resource-admin-create"),
        name: "Owner",
        password: "password123",
      },
    });
    expect(signup.status).toBe(200);
    const cookie = signup.headers
      .getSetCookie()
      .filter((raw) => Boolean(Cookie.parse(raw)?.value))
      .map((raw) => raw.split(";")[0])
      .join("; ");
    const identifiers = [];
    for (const identifier of [
      "https://api.fixture.test/admin-linked",
      "https://api.fixture.test/#",
      "javascript:alert(1)",
      "relative",
    ]) {
      const response = await control({
        action: "resource-create",
        headers: { cookie },
        body: { identifier },
      });
      identifiers.push({ identifier, status: response.status, body: await response.json() });
    }
    expect(identifiers.map(({ status }) => status)).toEqual([200, 400, 400, 400]);
    const disabled = await control({
      action: "resource-create",
      headers: { cookie },
      body: { identifier: "https://api.fixture.test/admin-disabled", disabled: true },
    });
    expect(disabled.status).toBe(200);
    const created = [];
    for (const resources of [
      ["https://api.fixture.test/admin-linked", "https://api.fixture.test/admin-linked"],
      ["https://api.fixture.test/admin-missing"],
      ["https://api.fixture.test/admin-disabled"],
      ["https://api.fixture.test/#"],
      [],
    ]) {
      const response = await control({
        action: "admin-create",
        headers: { cookie },
        body: {
          client_name: "Linked at creation",
          redirect_uris: ["https://app.fixture.test/callback"],
          token_endpoint_auth_method: "none",
          resources,
        },
      });
      const value = (await response.json()) as any;
      const links =
        response.status === 201
          ? await (await control({ action: "resource-links", clientId: value.client_id })).json()
          : null;
      created.push({ resources, status: response.status, value, links });
    }
    expect(created.map(({ status }) => status)).toEqual([201, 400, 400, 400, 201]);
    return ctx.snapshot({ identifiers, created });
  },
);
