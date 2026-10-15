import { expect } from "bun:test";

import { Cookie } from "tough-cookie";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "Server client resolution returns stored credentials and follows the supplied discovery options",
  async (ctx) => {
    const actor = ctx.actor();
    const control = (input: object) =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/oauth-provider-clients`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(input),
      });
    const resolve = async (clientId: string, discover = true) => {
      const response = await control({ action: "provider-client", clientId, discover });
      expect(response.status).toBe(200);
      return response.json();
    };
    expect(await resolve("unknown-client")).toBeNull();
    expect(await (await control({ action: "discovery-events" })).json()).toEqual([
      "first:matches",
      "live:matches",
    ]);
    const signup = await control({
      action: "signup",
      body: {
        email: ctx.uniqueEmail("server-client-owner"),
        name: "Owner",
        password: "password123",
      },
    });
    expect(signup.status).toBe(200);
    const owner = await signup.json();
    const cookie = signup.headers
      .getSetCookie()
      .filter((raw) => Boolean(Cookie.parse(raw)?.value))
      .map((raw) => raw.split(";")[0])
      .join("; ");
    const created = await control({
      headers: { cookie },
      body: {
        client_name: "Server managed",
        redirect_uris: ["https://app.fixture.test/callback"],
        token_endpoint_auth_method: "client_secret_post",
      },
    });
    expect(created.status).toBe(201);
    const client = await created.json();
    expect((await control({ action: "discovery-state", state: "live" })).status).toBe(200);
    const managed = await resolve(client.client_id);
    const row = await (await control({ action: "row", clientId: client.client_id })).json();
    expect(managed.client_id).toBe(client.client_id);
    expect(managed.client_name).toBe("Server managed");
    expect(managed.user_id).toBe(owner.user.id);
    expect(managed.discovery_id).toBeNull();
    expect(managed.client_secret).toBe(row.client_secret);
    expect(managed.client_secret).not.toBe(client.client_secret);
    expect(await (await control({ action: "discovery-events" })).json()).toEqual([]);
    const results = [];
    for (const [phase, state, discover, found, events] of [
      [
        "new",
        "live",
        true,
        true,
        ["first:matches", "first:resolve", "live:matches", "live:resolve:new"],
      ],
      ["existing", "live", true, true, ["live:matches", "live:resolve:existing"]],
      ["reject", "reject", true, false, ["live:matches", "live:resolve:existing"]],
      ["mismatch", "mismatch", true, false, ["live:matches"]],
      ["missing-owner", "live", false, false, []],
      ["restore", "live", true, true, ["live:matches", "live:resolve:existing"]],
      ["refresh", "refresh", true, true, ["live:matches", "live:resolve:existing"]],
    ] as const) {
      expect((await control({ action: "discovery-state", state })).status).toBe(200);
      const resolved = await resolve("registry-client", discover);
      expect(resolved !== null, phase).toBe(found);
      if (found) {
        expect(resolved).toEqual({
          client_id: "registry-client",
          client_name: phase === "refresh" ? "Updated registry" : "Registry client",
          discovery_id: "registry-live",
          user_id: null,
          client_secret: null,
        });
      }
      const recorded = await (await control({ action: "discovery-events" })).json();
      expect(recorded, phase).toEqual(events);
      results.push({ phase, client: resolved, events: recorded });
    }
    return ctx.snapshot({
      managed: {
        client_id: managed.client_id,
        client_name: managed.client_name,
        user_id: managed.user_id,
        discovery_id: managed.discovery_id,
        protectedSecretMatches: true,
      },
      results,
    });
  },
);
