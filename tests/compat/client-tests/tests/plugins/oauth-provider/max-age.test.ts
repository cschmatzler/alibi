import { Cookie } from "tough-cookie";
import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";

compatScenario(
  "OAuth authorization enforces max_age before issuing code authority from an existing session",
  async (ctx) => {
    const actor = ctx.actor("max-age");
    const control = (input: Record<string, unknown>) =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/oauth-provider-clients`, {
        method: "POST",
        redirect: "manual",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ mode: "interaction", ...input }),
      });
    const signup = await control({
      action: "signup",
      body: {
        email: ctx.uniqueEmail("max-age-owner"),
        name: "Freshness Owner",
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
      action: "admin-create",
      headers: { cookie },
      body: {
        client_name: "Freshness client",
        redirect_uris: ["https://app.fixture.test/callback"],
        scope: "email",
        skip_consent: true,
        require_pkce: false,
      },
    });
    expect(created.status).toBe(201);
    const client = await created.json();
    const authorizationSession = await (
      await control({ action: "session", headers: { cookie } })
    ).json();
    const authorize = (max_age: unknown, transport: "http" | "private", prompt?: string) => {
      const query = {
        client_id: client.client_id,
        response_type: "code",
        redirect_uri: "https://app.fixture.test/callback",
        scope: "email",
        state: "freshness-state",
        ...(max_age === undefined ? {} : { max_age }),
        ...(prompt ? { prompt } : {}),
      };
      return control(
        transport === "http"
          ? {
              action: "protocol-http",
              path: "/oauth2/authorize",
              query,
              headers: { cookie, accept: "application/json" },
            }
          : { action: "authorize", query, headers: { cookie, accept: "application/json" } },
      );
    };
    const outcomes = [];
    for (const [transport, age, prompt] of [
      ["http", "0", undefined],
      ["private", 0, undefined],
      ["private", "0", undefined],
      ["private", 0, "none"],
    ] as const) {
      const response = await authorize(age, transport, prompt);
      expect(response.status).toBe(200);
      const value = await response.json();
      const target = new URL(value.url, ctx.baseURL);
      if (prompt === "none") {
        expect(target.hostname).toBe("app.fixture.test");
        expect(target.searchParams.get("error")).toBe("login_required");
      } else {
        expect(target.pathname, `${ctx.baseURL}:${transport}:max_age=${age}`).toBe("/login");
        expect(target.searchParams.get("max_age")).toBe("0");
      }
      expect(target.searchParams.has("code")).toBe(false);
      expect(response.headers.getSetCookie()).toEqual([]);
      outcomes.push({ transport, age, prompt: prompt ?? null, value });
    }
    for (const [transport, age] of [
      ["http", "86400"],
      ["private", 86400],
      ["private", " 0x15180 "],
    ] as const) {
      const response = await authorize(age, transport);
      expect(response.status).toBe(200);
      const value = await response.json();
      const code = new URL(value.url, ctx.baseURL).searchParams.get("code");
      expect(code).toMatch(/^[a-zA-Z0-9]{32}$/);
      const proof = await (await control({ action: "grant-row", token: code })).json();
      expect(proof.value.userId).toBe(owner.user.id);
      expect(proof.value.sessionId).toBe(authorizationSession.session.id);
      expect(proof.value.query).not.toHaveProperty("max_age");
      outcomes.push({ transport, age, value, proof });
    }
    const invalidValues = [-1, 0.5, "", "  ", "-1", "1.5", "Infinity", false, null, ["0", "1"], {}];
    for (const [transport, age, prompt] of [
      ...invalidValues.map((age) => ["private", age, undefined] as const),
      ["http", "", undefined] as const,
      ["private", -1, "select_account"] as const,
    ]) {
      const response = await authorize(age, transport, prompt);
      expect(response.status).toBe(200);
      const value = await response.json();
      const target = new URL(value.url, ctx.baseURL);
      expect(target.hostname).toBe("app.fixture.test");
      expect(
        target.searchParams.get("error"),
        `${ctx.baseURL}:${transport}:${JSON.stringify(age)}`,
      ).toBe("invalid_request");
      expect(target.searchParams.has("code")).toBe(false);
      expect(response.headers.getSetCookie()).toEqual([]);
      outcomes.push({ transport, age, prompt: prompt ?? null, value });
    }
    return ctx.snapshot({ owner, client, authorizationSession, outcomes });
  },
);
