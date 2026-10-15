import { expect } from "bun:test";
import { createHash } from "node:crypto";

import { compatScenario } from "../../../support/scenario";
const control = "/__test/oauth-popup";
compatScenario(
  "SDK OAuth popup callback delivers success and provider failure then retires its marker",
  async (ctx) => {
    const results = [];
    const actor = ctx.actor("popup-sdk");
    for (const denied of [false, true]) {
      const started = await actor.fetch(`${ctx.baseURL}${control}/server-start`, {
        method: "POST",
        redirect: "manual",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          query: {
            provider: "gitlab",
            popupOrigin: "http://app.fixture.test",
            popupNonce: "sdk-popup-nonce",
            callbackURL: "/sdk-popup-done",
          },
        }),
      });
      expect(started.status).toBe(302);
      const cookie = started.headers
        .getSetCookie()
        .map((value) => value.split(";")[0])
        .join("; ");
      const authorization = new URL(started.headers.get("location")!);
      let query: Record<string, string>;
      if (denied) {
        query = {
          state: authorization.searchParams.get("state")!,
          error: "access_denied",
          error_description: "User cancelled",
        };
      } else {
        const authorized = await actor.fetch(authorization, { redirect: "manual" });
        expect(authorized.status).toBe(302);
        query = Object.fromEntries(new URL(authorized.headers.get("location")!).searchParams);
      }
      const response = await actor.fetch(`${ctx.baseURL}${control}/server-callback`, {
        method: "POST",
        redirect: "manual",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ query, headers: { cookie } }),
      });
      expect(response.status).toBe(200);
      expect(response.headers.get("content-type")).toContain("text/html");
      expect(response.headers.get("content-security-policy")).toContain("script-src");
      expect(
        response.headers
          .getSetCookie()
          .some((value) => value.includes("oauth_popup=") && value.includes("Max-Age=0")),
      ).toBe(true);
      const html = await response.text();
      const match = html.match(
        /<script type="application\/json" id="better-auth-oauth-popup">([^]*?)<\/script>/,
      );
      expect(match).not.toBeNull();
      const delivered = JSON.parse(match![1]!);
      expect(delivered).toMatchObject({
        type: "better-auth:oauth-popup",
        targetOrigin: "http://app.fixture.test",
        nonce: "sdk-popup-nonce",
      });
      if (denied) {
        expect(delivered.error).toEqual({ code: "access_denied", description: "User cancelled" });
        expect(delivered.token).toBeUndefined();
      } else {
        expect(delivered.redirectTo).toBe("/sdk-popup-done");
        expect(
          response.headers
            .getSetCookie()
            .some(
              (value) =>
                value.startsWith("better-auth.session_token=") &&
                decodeURIComponent(
                  value.split(";")[0]!.slice("better-auth.session_token=".length),
                ) === delivered.token,
            ),
        ).toBe(true);
        const session = await actor.fetch(
          `${ctx.baseURL}/__test/profiles/oauth-popup/api/auth/get-session`,
          {
            headers: {
              origin: "http://app.fixture.test",
              cookie: response.headers
                .getSetCookie()
                .map((value) => value.split(";")[0])
                .join("; "),
            },
          },
        );
        expect(session.status).toBe(200);
        expect(((await session.json()) as any).user.email).toBe("popup-owner@fixture.test");
      }
      results.push({ denied, delivered });
    }
    const state = await ctx.rawRequest({ path: `${control}/state` });
    expect((state.body as any).user).toHaveLength(1);
    expect((state.body as any).session).toHaveLength(1);
    expect((state.body as any).verification).toHaveLength(0);
    const stored = state.body as any;
    const authorize = stored.receipts.find((receipt: any) => receipt.stage === "authorize");
    const token = stored.receipts.find((receipt: any) => receipt.stage === "token");
    expect(createHash("sha256").update(token.body.code_verifier).digest("base64url")).toBe(
      authorize.query.code_challenge,
    );
    const { receipts, ...rows } = stored;
    return ctx.snapshot({ results, rows, stages: receipts.map((receipt: any) => receipt.stage) });
  },
  ["GET /oauth-popup/start", "GET /callback/{}"],
);
