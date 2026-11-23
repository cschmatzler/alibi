import { expect } from "vitest";

import { oauthProtocolQuotaSeconds } from "../../../support/oauth-protocol-quota";
import { compatScenario } from "../../../support/scenario";

compatScenario(
  "OAuth protocol quotas inherit global policy and exempt private server dispatch",
  async (ctx) => {
    const actor = ctx.actor("oauth-limiter");
    const control = (input: object) =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/oauth-provider-clients`, {
        method: "POST",
        redirect: "manual",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(input),
      });
    const credentials = {
      client_id: "quota-missing",
      client_secret: "not-secret",
      token: "missing",
    };
    const token = {
      grant_type: "client_credentials",
      client_id: "quota-missing",
      client_secret: "not-secret",
      scope: "email",
    };
    const request = async (mode: string, path: string, ip: string, post = false) => {
      const response = await control({
        mode,
        action: "protocol-http",
        path: `/oauth2/${path}`,
        method: !post && ["authorize", "userinfo"].includes(path) ? "GET" : "POST",
        headers: {
          "x-forwarded-for": ip,
          ...(path === "userinfo" && !post ? { authorization: "Bearer missing" } : {}),
        },
        ...(path === "authorize"
          ? {
              query: {
                client_id: "quota-missing",
                response_type: "code",
                redirect_uri: "https://app.fixture.test/callback",
              },
            }
          : {}),
        ...(path === "register" ? { contentType: "application/json" } : {}),
        body:
          path === "token"
            ? token
            : path === "userinfo"
              ? { access_token: "missing" }
              : path === "register"
                ? { redirect_uris: ["https://app.fixture.test/callback"] }
                : credentials,
      });
      const raw = await response.text();
      return {
        status: response.status,
        body:
          raw !== "" && response.headers.get("content-type")?.startsWith("application/json")
            ? JSON.parse(raw)
            : raw,
        headers: Object.fromEntries(
          [
            "content-type",
            "x-retry-after",
            "set-cookie",
            "cache-control",
            "pragma",
            "www-authenticate",
          ].map((name) => [name, response.headers.get(name)]),
        ),
      };
    };
    const receipts = [];
    const retryHeader = expect.stringMatching(/^[1-9]\d*$/);
    for (const [modeIndex, mode] of [
      "rate-default",
      "rate-override",
      "rate-false",
      "rate-global-disabled",
      "rate-application",
    ].entries()) {
      const ip = `198.51.100.${modeIndex + 1}`;
      for (const [path, defaultMax, status] of [
        ["token", 20, 400],
        ["authorize", 30, 302],
        ["introspect", 100, 400],
        ["revoke", 30, 400],
        ["register", 5, 403],
        ["userinfo", 60, 401],
      ] as const) {
        if (mode === "rate-override" && !["token", "authorize", "introspect"].includes(path)) {
          continue;
        }
        const retry = oauthProtocolQuotaSeconds(mode, `/oauth2/${path}`);
        const max =
          mode === "rate-default"
            ? defaultMax
            : retry === undefined
              ? 3
              : mode === "rate-false" || path === "token"
                ? 2
                : 1;
        const admitted = await request(mode, path, ip);
        expect(admitted.status).toBe(status);
        expect(admitted.headers["x-retry-after"]).toBeNull();
        for (let index = 1; index < max; index++) {
          expect(await request(mode, path, ip, index % 2 === 1)).toEqual(admitted);
        }
        if (retry !== undefined) {
          const denied = await request(mode, path, ip);
          expect(denied).toEqual({
            status: 429,
            body: { message: "Too many requests. Please try again later." },
            headers: {
              "content-type": "application/json",
              "x-retry-after": retryHeader,
              "set-cookie": null,
              "cache-control": null,
              pragma: null,
              "www-authenticate": null,
            },
          });
          expect(await request(mode, path, `198.51.101.${modeIndex + 1}`)).toEqual(admitted);
          // The transport comparison checks the wire countdown against its request windows.
          receipts.push({
            mode,
            path,
            max,
            admitted,
            denied: { ...denied, headers: { ...denied.headers, "x-retry-after": String(retry) } },
          });
        } else receipts.push({ mode, path, max, admitted });
      }
      if (mode === "rate-default") {
        for (const attachRequest of [false, true]) {
          const response = await control({
            mode,
            action: "token",
            attachRequest,
            headers: { "x-forwarded-for": ip },
            body: token,
          });
          expect(response.status).toBe(400);
          expect(response.headers.get("x-retry-after")).toBeNull();
          receipts.push({
            phase: "private-bypass",
            attachRequest,
            status: response.status,
            body: await response.json(),
          });
        }
        const stillDenied = await request(mode, "token", ip);
        expect(stillDenied.status).toBe(429);
        expect(stillDenied.headers["x-retry-after"]).toEqual(retryHeader);
        for (let index = 0; index < 2; index++) {
          expect((await request(mode, "token-extra", ip)).status).toBe(404);
        }
        const exactMatch = await request(mode, "token-extra", ip);
        expect(exactMatch.status).toBe(429);
        expect(exactMatch.headers["x-retry-after"]).toEqual(retryHeader);
        receipts.push({
          phase: "exact-matcher",
          exactMatch: {
            ...exactMatch,
            headers: {
              ...exactMatch.headers,
              "x-retry-after": String(oauthProtocolQuotaSeconds(mode, "/oauth2/token-extra")),
            },
          },
        });
      }
    }
    return ctx.snapshot({ receipts });
  },
  [
    "POST /oauth2/token",
    "GET /oauth2/authorize",
    "POST /oauth2/introspect",
    "POST /oauth2/revoke",
    "POST /oauth2/register",
    "GET /oauth2/userinfo",
  ],
);
