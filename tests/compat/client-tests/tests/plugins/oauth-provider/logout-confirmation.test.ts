import { createHmac, timingSafeEqual } from "node:crypto";

import { Cookie } from "tough-cookie";
import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "Browser logout requires authentic session-bound confirmation and rejects forgery",
  async (ctx) => {
    const actor = ctx.actor();
    const control = (input: unknown) =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/oauth-provider-clients`, {
        method: "POST",
        redirect: "manual",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(input),
      });
    const signup = async (label: string) => {
      const r = await control({
        action: "signup",
        body: { email: ctx.uniqueEmail(label), name: "Native owner", password: "password123" },
      });
      expect(r.status).toBe(200);
      const cookie = r.headers
        .getSetCookie()
        .filter((raw) => Boolean(Cookie.parse(raw)?.value))
        .map((raw) => raw.split(";")[0])
        .join("; ");
      const sessionResponse = await control({ action: "session", headers: { cookie } });
      expect(sessionResponse.status).toBe(200);
      return { cookie, session: (await sessionResponse.json()) as any };
    };
    const owner = await signup("logout-confirm-owner");
    const other = await signup("logout-confirm-other");
    const started = Date.now();
    const r = await control({
      action: "logout-http",
      path: "/oauth2/end-session",
      method: "GET",
      headers: { cookie: owner.cookie, accept: "text/html" },
    });
    const finished = Date.now();
    expect(r.status).toBe(200);
    expect(r.headers.get("content-type")).toBe("text/html; charset=utf-8");
    expect(r.headers.get("cache-control")).toBe("no-store");
    expect(r.headers.get("pragma")).toBe("no-cache");
    const html = await r.text();
    expect(html).toContain("data-oidc-logout-confirmation");
    expect(html).toContain('name="action" value="confirm"');
    expect(html).toContain(`action="${ctx.baseURL}/api/auth/oauth2/end-session/confirm"`);
    const raw = r.headers
      .getSetCookie()
      .find((raw) => raw.includes(".oauth_logout_confirmation="))!;
    const proof = Cookie.parse(raw)!;
    expect(proof.path).toBe("/api/auth/oauth2/end-session/confirm");
    expect(proof.maxAge).toBe(300);
    expect(proof.httpOnly).toBe(true);
    expect(proof.sameSite).toBe("lax");
    const decoded = decodeURIComponent(proof.value);
    const index = decoded.lastIndexOf(".");
    const payload = decoded.slice(0, index);
    const signature = Buffer.from(decoded.slice(index + 1), "base64");
    expect(
      timingSafeEqual(
        signature,
        createHmac("sha256", "compat-test-only-key-not-real-minimum-32chars")
          .update(payload)
          .digest(),
      ),
    ).toBe(true);
    const state = JSON.parse(payload);
    expect(Object.keys(state).sort()).toEqual(["expiresAt", "sessionId"]);
    expect(state.sessionId).toBe(owner.session.session.id);
    expect(state.expiresAt).toBeGreaterThanOrEqual(started + 300_000);
    expect(state.expiresAt).toBeLessThanOrEqual(finished + 300_000);
    const proofCookie = `${proof.key}=${proof.value}`;
    const failures = [];
    for (const cookie of [
      `${owner.cookie}; ${proof.key}=forged`,
      `${other.cookie}; ${proofCookie}`,
    ]) {
      const denied = await control({
        action: "logout-http",
        path: "/oauth2/end-session/confirm",
        method: "POST",
        headers: { cookie, accept: "application/json" },
        body: { action: "confirm" },
      });
      expect(denied.status).toBe(400);
      const body = await denied.json();
      expect(body).toEqual({
        error: "invalid_request",
        error_description: "The logout confirmation is invalid or expired",
      });
      failures.push(body);
    }
    const retained = await control({ action: "session-row", token: owner.session.session.token });
    expect(retained.status).toBe(200);
    expect(((await retained.json()) as any).id).toBe(owner.session.session.id);
    const ended = await control({
      action: "logout-http",
      path: "/oauth2/end-session/confirm",
      method: "POST",
      headers: { cookie: `${owner.cookie}; ${proofCookie}`, accept: "text/html" },
      body: { action: "confirm" },
    });
    expect(ended.status).toBe(200);
    expect(await ended.text()).toContain('data-oidc-logout-state="logged-out"');
    const retired = await control({ action: "session-row", token: owner.session.session.token });
    expect(retired.status).toBe(200);
    expect(await retired.json()).toBeNull();
    const untouched = await control({ action: "session-row", token: other.session.session.token });
    expect(untouched.status).toBe(200);
    expect(((await untouched.json()) as any).id).toBe(other.session.session.id);
    const missing = await control({ action: "confirm-logical" });
    expect(missing.status).toBe(400);
    expect(await missing.json()).toEqual({
      error: "invalid_request",
      error_description: "The logout confirmation is invalid or expired",
    });
    const again = await control({
      action: "logout-http",
      path: "/oauth2/end-session",
      method: "GET",
      headers: { cookie: other.cookie, accept: "text/html" },
    });
    expect(again.status).toBe(200);
    const otherProof = again.headers
      .getSetCookie()
      .find((raw) => raw.includes(".oauth_logout_confirmation="))!
      .split(";")[0];
    const logical = await control({
      action: "confirm-logical",
      headers: { cookie: `${other.cookie}; ${otherProof}` },
    });
    expect(logical.status).toBe(200);
    expect(await logical.json()).toBeNull();
    const removed = await control({ action: "session-row", token: other.session.session.token });
    expect(removed.status).toBe(200);
    expect(await removed.json()).toBeNull();
    return ctx.snapshot({
      authorizationSession: owner.session,
      otherAuthorizationSession: other.session,
      failures,
      ended: ended.status,
      logical: logical.status,
    });
  },
);
