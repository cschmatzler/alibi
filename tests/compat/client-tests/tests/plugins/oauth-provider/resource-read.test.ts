import { Cookie } from "tough-cookie";
import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "Resource lookup decodes identifiers and preserves malformed escapes and disabled policy",
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
        email: ctx.uniqueEmail("resource-read-owner"),
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
        email: ctx.uniqueEmail("resource-read-other"),
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
    const expected = [];
    for (const input of [
      { identifier: "https://api.fixture.test/read+a", name: "Read A", allowedScopes: ["email"] },
      { identifier: "urn:fixture:%61%ZZ", disabled: true },
    ]) {
      const r = await control({ action: "resource-create", headers: { cookie }, body: input });
      expect(r.status).toBe(200);
      expected.push(await r.json());
    }
    const rows = [];
    for (const [identifier, headers, index] of [
      ["https://api.fixture.test/read+a", { cookie }, 0],
      [encodeURIComponent("https://api.fixture.test/read+a"), { cookie: otherCookie }, 0],
      ["urn:fixture:%61%ZZ", { cookie }, 1],
    ] as const) {
      const r = await control({ action: "resource-get", params: { identifier }, headers });
      expect(r.status).toBe(200);
      const row = (await r.json()) as any;
      expect(row).toEqual(expected[index]);
      const { createdAt, updatedAt, ...value } = row;
      rows.push(value);
    }
    const failures = [];
    for (const [identifier, headers, status, description] of [
      [
        "https%3A%2F%2Fapi.fixture.test%2Fmissing",
        { cookie },
        404,
        "resource https://api.fixture.test/missing not found",
      ],
      ["https://api.fixture.test/read+a", {}, 401, null],
      ["%E0%A4", { cookie }, 404, "resource %E0%A4 not found"],
    ] as const) {
      const r = await control({ action: "resource-get", params: { identifier }, headers });
      expect(r.status).toBe(status);
      const text = await r.text();
      const value = text ? JSON.parse(text) : null;
      if (description) {
        expect(value).toEqual({ error: "not_found", error_description: description });
      }
      failures.push({ status: r.status, body: value });
    }
    const hidden = await control({
      action: "resource-http",
      operation: "read",
      identifier: "https://api.fixture.test/read+a",
      headers: { cookie },
    });
    expect(await hidden.json()).toEqual({ status: 404 });
    const unchanged = await control({ action: "resource-list", headers: { cookie } });
    expect(await unchanged.json()).toEqual(expected);
    return ctx.snapshot({ rows, failures });
  },
);
