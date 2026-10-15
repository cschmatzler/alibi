import { expect } from "bun:test";

import { Cookie } from "tough-cookie";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "External client discovery resolves in order and never treats owned rows as managed",
  async (ctx) => {
    const actor = ctx.actor();
    const control = (input: object) =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/oauth-provider-clients`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ mode: "discovered", ...input }),
      });
    const signup = await control({
      action: "signup",
      body: { email: ctx.uniqueEmail("registry-owner"), name: "Owner", password: "password123" },
    });
    expect(signup.status).toBe(200);
    const cookie = signup.headers
      .getSetCookie()
      .filter((raw) => Boolean(Cookie.parse(raw)?.value))
      .map((raw) => raw.split(";")[0])
      .join("; ");
    const results = [];
    const cases: [string, string, boolean, number, string[]][] = [
      [
        "new",
        "live",
        false,
        200,
        ["first:matches", "first:resolve", "live:matches", "live:resolve:new"],
      ],
      ["existing", "live", false, 200, ["live:matches", "live:resolve:existing"]],
      ["reject", "reject", false, 404, ["live:matches", "live:resolve:existing"]],
      ["mismatch", "mismatch", false, 404, ["live:matches"]],
      ["missing-owner", "live", true, 404, []],
      ["restore", "live", false, 200, ["live:matches", "live:resolve:existing"]],
    ];
    cases.push(["refresh", "refresh", false, 200, ["live:matches", "live:resolve:existing"]]);
    for (const [phase, state, missingOwner, status, expected] of cases) {
      const setup = await control({ action: "discovery-state", state });
      expect(setup.status).toBe(200);
      const response = await control({
        mode: missingOwner ? "default" : "discovered",
        action: "public",
        headers: { cookie },
        query: { client_id: "registry-client" },
      });
      expect(response.status, phase).toBe(status);
      const body = await response.json();
      expect(body).toEqual(
        status === 200
          ? {
              client_id: "registry-client",
              client_name: phase === "refresh" ? "Updated registry" : "Registry client",
              redirect_uris: [],
            }
          : { error: "not_found", error_description: "client not found" },
      );
      const events = await (await control({ action: "discovery-events" })).json();
      expect(events, phase).toEqual(expected);
      const rowResponse = await control({ action: "discovery-row", clientId: "registry-client" });
      expect(rowResponse.status).toBe(200);
      const row = await rowResponse.json();
      expect(row).toEqual({
        clientId: "registry-client",
        clientDiscoveryId: "registry-live",
        name: phase === "refresh" ? "Updated registry" : "Registry client",
      });
      results.push({ phase, status: response.status, body, events, row });
    }
    const created = await control({
      headers: { cookie },
      body: {
        client_name: "Managed client",
        redirect_uris: ["https://app.fixture.test/callback"],
        token_endpoint_auth_method: "none",
      },
    });
    expect(created.status).toBe(201);
    const managed = (await created.json()) as any;
    expect(managed.client_id).toBe("registry-managed");
    await control({ action: "discovery-state", state: "live" });
    const response = await control({
      action: "public",
      headers: { cookie },
      query: { client_id: "registry-managed" },
    });
    expect(response.status).toBe(200);
    const body = await response.json();
    expect(body).toEqual({
      client_id: "registry-managed",
      client_name: "Managed client",
      redirect_uris: [],
    });
    const events = await (await control({ action: "discovery-events" })).json();
    expect(events).toEqual([]);
    const validations = [];
    const invalidEmpty = "OAuth Provider extension client discovery id cannot be empty";
    const duplicate =
      'OAuth Provider extensions register client discovery id "same" more than once. Extension contributions must be disjoint.';
    const setups: [string[], string?][] = [
      [[]],
      [["one", "two"]],
      [[""], invalidEmpty],
      [[" \t "], invalidEmpty],
      [["\uFEFF"], invalidEmpty],
      [["\u0085"]],
      [["same", "same"], duplicate],
      [["one", " one "]],
    ];
    for (const [ids, message] of setups) {
      const result = await control({ action: "discovery-validation", ids });
      expect(result.status).toBe(200);
      const body = await result.json();
      expect(body).toEqual(message ? { valid: false, message } : { valid: true });
      validations.push({ ids, body });
    }
    return ctx.snapshot({
      results,
      managed,
      managedPublic: body,
      managedEvents: events,
      validations,
    });
  },
);
