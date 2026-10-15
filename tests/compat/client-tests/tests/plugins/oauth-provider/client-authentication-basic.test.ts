import { Cookie } from "tough-cookie";
import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "Basic authentication decodes form credentials and preserves reference parsing quirks",
  async (ctx) => {
    const actor = ctx.actor();
    const control = (input: object) =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/oauth-provider-clients`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ mode: "basic-special", ...input }),
      });
    const signup = await control({
      action: "signup",
      body: { email: ctx.uniqueEmail("basic-form-owner"), name: "Owner", password: "password123" },
    });
    expect(signup.status).toBe(200);
    const cookie = signup.headers
      .getSetCookie()
      .filter((raw) => Boolean(Cookie.parse(raw)?.value))
      .map((raw) => raw.split(";")[0])
      .join("; ");
    const created = await control({
      headers: { cookie },
      body: {
        client_name: "Basic grammar",
        redirect_uris: ["https://app.fixture.test/callback"],
        token_endpoint_auth_method: "client_secret_basic",
      },
    });
    expect(created.status).toBe(201);
    const client = (await created.json()) as any;
    expect(client.client_id).toBe("client +/é:fixed");
    expect(client.client_secret).toBe("secret +/é:tail");
    const encode = (value: string) => new URLSearchParams({ v: value }).toString().slice(2);
    const payload = `${encode(client.client_id)}:${encode(client.client_secret)}`;
    const b64 = (value: string) => Buffer.from(value).toString("base64");
    const encoded = b64(payload);
    const invalid = "invalid authorization header format";
    const unsupported = "unsupported authorization scheme";
    const cases: [string, string, number, string?, string?][] = [
      ["canonical", `Basic ${encoded}`, 200],
      ["lowercase", `basic ${encoded}`, 200],
      ["spaces", `bAsIc   ${encoded}`, 200],
      ["percent-space", `Basic ${b64(payload.replaceAll("+", "%20"))}`, 200],
      ["unpadded", `Basic ${encoded.replace(/=+$/, "")}`, 200],
      ["ignored-after-padding", `Basic ${encoded}=garbage`, 200],
      ["unescaped-secret-separator", `Basic ${b64(`${payload}&ignored=1`)}`, 200],
      ["missing-colon", `Basic ${b64("no-colon")}`, 401, invalid, "Basic"],
      ["empty-id", `Basic ${b64(":secret")}`, 401, invalid, "Basic"],
      ["empty-secret", `Basic ${b64("client:")}`, 401, invalid, "Basic"],
      ["malformed-base64", "Basic %%%", 401, invalid, "Basic"],
      ["bare-basic", "Basic", 401, unsupported, "Basic"],
      ["tab-basic", `Basic\t${encoded}`, 401, unsupported, "Basic"],
      ["bearer", "Bearer example", 401, unsupported, "Bearer"],
      ["invalid-scheme", "@bad example", 400, "Invalid authorization header format"],
    ];
    const results = [];
    for (const [name, authorization, status, detail, challenge] of cases) {
      const response = await control({
        action: "introspect",
        body: { token: "not-issued" },
        headers: { authorization },
      });
      expect(response.status, name).toBe(status);
      expect(response.headers.get("www-authenticate"), name).toBe(challenge ?? null);
      const body = await response.json();
      expect(body).toEqual(
        detail
          ? {
              error: status === 400 ? "invalid_request" : "invalid_client",
              error_description: detail,
            }
          : { active: false },
      );
      results.push({
        name,
        status: response.status,
        challenge: response.headers.get("www-authenticate"),
        body,
      });
    }
    return ctx.snapshot({ client, results });
  },
);
