import { expect } from "bun:test";

import { Cookie } from "tough-cookie";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "OAuth client authentication rejects ambiguous methods and normalizes physical forms",
  async (ctx) => {
    const actor = ctx.actor();
    const control = (input: any) =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/oauth-provider-clients`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(input),
      });
    const signup = await control({
      action: "signup",
      body: {
        email: ctx.uniqueEmail("client-admission-owner"),
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
    const clients = [];
    for (const method of ["client_secret_basic", "client_secret_post"]) {
      const response = await control({
        headers: { cookie },
        body: {
          client_name: method,
          redirect_uris: ["https://app.fixture.test/callback"],
          token_endpoint_auth_method: method,
        },
      });
      expect(response.status).toBe(201);
      clients.push((await response.json()) as any);
    }
    const [basic, post] = clients as any[];
    const authorization = `Basic ${Buffer.from(`${basic.client_id}:${basic.client_secret}`).toString("base64")}`;
    const postBody = {
      token: "not-issued",
      client_id: post.client_id,
      client_secret: post.client_secret,
    };
    const basicBody = {
      token: "not-issued",
      client_id: basic.client_id,
      client_secret: basic.client_secret,
    };
    type Case = {
      name: string;
      body: any;
      formEntries?: [string, string][];
      authorization?: string;
      detail?: string;
    };
    const cases: Case[] = [
      {
        name: "header-and-secret",
        body: basicBody,
        authorization,
        detail: "A request must use only one client authentication method",
      },
      {
        name: "secret-and-assertion",
        body: { ...postBody, client_assertion: "test", client_assertion_type: "urn:test" },
        detail: "A request must use only one client authentication method",
      },
      {
        name: "header-and-assertion",
        body: { token: "not-issued", client_assertion: "test", client_assertion_type: "urn:test" },
        authorization,
        detail: "A request must use only one client authentication method",
      },
    ];
    for (const [field, value] of [
      ["client_id", post.client_id],
      ["client_secret", post.client_secret],
      ["client_assertion", "test"],
      ["client_assertion_type", "urn:test"],
    ]) {
      const formEntries: [string, string][] = [...Object.entries(postBody), [field, value]];
      if (field.startsWith("client_assertion")) {
        formEntries.push([field, value]);
      }
      cases.push({
        name: field,
        body: postBody,
        formEntries,
        detail: `${field} must not be repeated`,
      });
    }
    cases.push({
      name: "empty-duplicates-and-resources",
      body: postBody,
      formEntries: [
        ["token", "not-issued"],
        ["client_id", ""],
        ["client_id", post.client_id],
        ["client_secret", ""],
        ["client_secret", post.client_secret],
        ["resource", "one"],
        ["resource", "two"],
      ],
    });
    cases.push({
      name: "request-auth-authority",
      body: { token: "not-issued", client_id: "wrong", client_secret: "wrong" },
      formEntries: Object.entries(postBody),
    });
    cases.push({
      name: "basic-with-empty-fields",
      body: {
        token: "not-issued",
        client_secret: "",
        client_assertion: "",
        client_assertion_type: "",
      },
      authorization,
    });
    const results = [];
    for (const test of cases) {
      const response = await control({
        action: "introspect",
        body: test.body,
        formEntries: test.formEntries,
        headers: test.authorization ? { authorization: test.authorization } : {},
      });
      expect(response.status, test.name).toBe(test.detail ? 400 : 200);
      const body = await response.json();
      expect(body).toEqual(
        test.detail
          ? { error: "invalid_request", error_description: test.detail }
          : { active: false },
      );
      results.push({ name: test.name, status: response.status, body });
    }
    return ctx.snapshot({ clients, results });
  },
);
