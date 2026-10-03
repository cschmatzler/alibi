import { expect } from "bun:test";
import { createHash, createHmac } from "node:crypto";
import { mkdir } from "node:fs/promises";

import { chromium } from "playwright";

import { compatScenario } from "../../../support/scenario";

const PATH = "/__test/profiles/oauth-popup/api/auth";
const CONTROL = "/__test/oauth-popup";
const APP = "http://app.fixture.test";
const secret = "compat-test-only-key-not-real-minimum-32chars";
const bundle = await Bun.build({
  entrypoints: [new URL("./browser-client.ts", import.meta.url).pathname],
  target: "browser",
  minify: false,
});
if (!bundle.success) throw new Error(`Popup client bundling failed: ${bundle.logs}`);
const clientJS = await bundle.outputs[0]!.text();
function payload(html: string) {
  const raw = html.match(
    /<script type="application\/json" id="better-auth-oauth-popup">([^]*?)<\/script>/,
  )?.[1];
  if (!raw) throw new Error(`Completion HTML missing: ${html}`);
  return JSON.parse(raw);
}
function verify(signed: string) {
  const decoded = decodeURIComponent(signed);
  const dot = decoded.lastIndexOf(".");
  expect(decoded.slice(dot + 1)).toBe(
    createHmac("sha256", secret).update(decoded.slice(0, dot)).digest("base64"),
  );
  return decoded.slice(0, dot);
}

// Primary owner: real HTTP issuance/consumption and official-client Chromium
// delivery. A missing route, wrong marker/signature/CSP/recipient, token from a
// different session, or replay that mints a session fails at this boundary.
// Existing OAuth tests do not execute popup start or the official popup client.
compatScenario(
  "OAuth popup trusted start, stored lifecycle and official Chromium completion",
  async (ctx) => {
    const browser = await chromium.launch({
      executablePath: process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH,
    });
    const raw: unknown[] = [];
    const observations: unknown[] = [];
    const base = ctx.baseURL;
    const readState = async (request: any) => (await request.get(`${base}${CONTROL}/state`)).json();
    try {
      const context = await browser.newContext();
      const request = context.request;
      const reset = async () => {
        await request.post(`${base}${CONTROL}/reset`);
        await context.clearCookies();
      };
      async function responseRecord(response: any) {
        const record = {
          url: typeof response.url === "function" ? response.url() : response.url,
          status: typeof response.status === "function" ? response.status() : response.status,
          headers:
            typeof response.headers === "function"
              ? response.headers()
              : Object.fromEntries(response.headers),
          body: await response.text(),
        };
        raw.push(record);
        return record;
      }
      async function start(extra: Record<string, string> = {}) {
        const query = new URLSearchParams({
          provider: "gitlab",
          popupOrigin: APP,
          popupNonce: "nonce-132",
          callbackURL: "/finished",
          ...extra,
        });
        return responseRecord(
          await request.get(`${base}${PATH}/oauth-popup/start?${query}`, { maxRedirects: 0 }),
        );
      }
      const dangerous = "</script><script>window.pwned=true</script>\u2028\u2029";
      await reset();
      const foreign = await start({ popupOrigin: "https://foreign.invalid" });
      expect(foreign.status).toBe(403);
      expect(JSON.parse(foreign.body).code).toBe("INVALID_ORIGIN");
      expect((await readState(request)).verification).toHaveLength(0);
      observations.push({ foreign: { status: foreign.status, body: JSON.parse(foreign.body) } });
      for (const [key, code] of [
        ["callbackURL", "invalid_callback_url"],
        ["errorCallbackURL", "invalid_error_callback_url"],
        ["newUserCallbackURL", "invalid_new_user_callback_url"],
      ] as const) {
        const record = await start({
          [key]: `https://foreign.invalid/${dangerous}`,
          popupNonce: dangerous,
        });
        expect(record.status).toBe(200);
        const data = payload(record.body);
        expect(data).toEqual({
          type: "better-auth:oauth-popup",
          targetOrigin: APP,
          nonce: dangerous,
          error: { code, description: `Untrusted URL: https://foreign.invalid/${dangerous}` },
        });
        expect(record.body).not.toContain(dangerous);
        expect(record.body.match(/<script/g)).toHaveLength(2);
        const script = record.body.match(/<script>([^]*?)<\/script>/)![1]!;
        expect(record.headers["content-security-policy"]).toBe(
          `default-src 'none'; script-src 'sha256-${createHash("sha256").update(script).digest("base64")}'; base-uri 'none'`,
        );
        expect(record.headers["content-security-policy"]).toContain(
          "sha256-tIo2K8VBC9SnhvdZ+9GsGkQoZm+jm/JcxL+d+i8b8KQ=",
        );
        const expectedData = {
          type: "better-auth:oauth-popup",
          targetOrigin: APP,
          nonce: dangerous,
          error: { code, description: `Untrusted URL: https://foreign.invalid/${dangerous}` },
        };
        const escaped = JSON.stringify(expectedData)
          .replace(/</g, "\\u003c")
          .replace(/\u2028/g, "\\u2028")
          .replace(/\u2029/g, "\\u2029");
        expect(record.body).toBe(`<!doctype html>
<html>
<head><meta charset="utf-8"><title>Completing sign-in</title></head>
<body>
<script type="application/json" id="better-auth-oauth-popup">${escaped}</script>
<script>${script}</script>
</body>
</html>`);
        expect(record.headers["cache-control"]).toBe("no-store");
        expect(record.headers.pragma).toBe("no-cache");
        observations.push({
          key,
          status: record.status,
          payload: data,
          html: record.body,
          csp: record.headers["content-security-policy"],
        });
      }
      expect((await readState(request)).verification).toHaveLength(0);
      const unknown = await responseRecord(
        await ctx
          .actor()
          .fetch(
            `${base}${PATH}/oauth-popup/start?${new URLSearchParams({ provider: "missing", popupOrigin: APP, popupNonce: dangerous })}`,
            { redirect: "manual", headers: { origin: APP } },
          ),
      );
      expect(payload(unknown.body).error.code).toBe("provider_not_found");
      observations.push({ unknown: payload(unknown.body) });
      await reset();
      const issued = await start({
        scopes: "read_user,custom",
        requestSignUp: "true",
        additionalData: JSON.stringify({
          callbackURL: "https://foreign.invalid",
          expiresAt: 0,
          idTokenNonce: "attacker-nonce",
          serverContext: { anonymousUserId: "foreign-user" },
          custom: "kept",
        }),
      });
      expect(issued.status).toBe(302);
      const issuedState = await readState(request);
      raw.push({ issuedState });
      expect(issuedState.verification).toHaveLength(1);
      const row = issuedState.verification[0];
      const stored = JSON.parse(row.value);
      const providerURL = new URL(issued.headers.location!);
      expect(row.identifier).toBe(providerURL.searchParams.get("state"));
      expect(stored.callbackURL).toBe("/finished");
      expect(stored.custom).toBe("kept");
      expect(stored.idTokenNonce).toBeUndefined();
      expect(stored.serverContext).toBeUndefined();
      expect(stored.requestSignUp).toBe(true);
      expect(stored.expiresAt - Date.now()).toBeGreaterThan(590_000);
      expect(stored.expiresAt - Date.now()).toBeLessThanOrEqual(600_000);
      const cookies = await context.cookies();
      const marker = cookies.find((c) => c.name === "better-auth.oauth_popup")!;
      expect(JSON.parse(verify(marker.value))).toEqual({
        popupOrigin: APP,
        popupNonce: "nonce-132",
      });
      expect(marker.httpOnly).toBe(true);
      expect(marker.expires - Date.now() / 1000).toBeGreaterThan(590);
      const providerResponse = await responseRecord(
        await request.get(providerURL.href, { maxRedirects: 0 }),
      );
      const callback = providerResponse.headers.location!;
      const done = await responseRecord(await request.get(callback, { maxRedirects: 0 }));
      expect(done.status).toBe(200);
      const data = payload(done.body);
      expect(data.nonce).toBe("nonce-132");
      expect(data.redirectTo).toBe("/finished");
      expect(done.headers.location).toBe(data.redirectTo);
      expect(done.headers["set-auth-token"]).toBe(data.token);
      const token = verify(data.token);
      const after = await readState(request);
      raw.push({ after });
      expect(after.verification).toHaveLength(0);
      expect(after.session).toHaveLength(1);
      expect(after.user).toHaveLength(1);
      expect(after.session[0].token).toBe(token);
      expect(after.session[0].userId).toBe(after.user[0].id);
      expect(after.account[0].userId).toBe(after.user[0].id);
      expect(after.account[0].accountId).toBe("132");
      expect(after.account[0].providerId).toBe("gitlab");
      expect((await context.cookies()).some((c) => c.name === "better-auth.oauth_popup")).toBe(
        false,
      );
      const bearer = await request.get(`${base}${PATH}/get-session`, {
        headers: { authorization: `Bearer ${data.token}`, cookie: "" },
      });
      expect((await bearer.json()).user.id).toBe(after.user[0].id);
      const foreignContext = await browser.newContext();
      expect(
        await (await foreignContext.request.get(`${base}${PATH}/get-session`)).json(),
      ).toBeNull();
      await foreignContext.close();
      const replay = await responseRecord(await request.get(callback, { maxRedirects: 0 }));
      expect(replay.status).toBe(302);
      expect((await readState(request)).session).toEqual(after.session);
      await context.addCookies([marker]);
      const popupReplay = await responseRecord(await request.get(callback, { maxRedirects: 0 }));
      expect(popupReplay.status).toBe(200);
      expect(payload(popupReplay.body).error.code).toBe("state_mismatch");
      expect(payload(popupReplay.body).nonce).toBe("nonce-132");
      expect((await readState(request)).session).toEqual(after.session);
      observations.push({
        popupReplay: { status: popupReplay.status, error: payload(popupReplay.body).error },
      });
      observations.push({
        success: {
          nonce: data.nonce,
          redirectTo: data.redirectTo,
          tokenOwned: true,
          bearerOwned: true,
          authHeaderMatchesToken: true,
          foreignSession: null,
          replayStatus: replay.status,
        },
      });
      for (const mode of [
        "expired",
        "state-tampered",
        "marker-tampered",
        "provider-error",
      ] as const) {
        await reset();
        await request
          .get(
            `${base}${PATH}/oauth-popup/start?${new URLSearchParams({ provider: "gitlab", popupOrigin: APP, popupNonce: "nonce-132", callbackURL: "/finished", errorCallbackURL: "/error-page" })}`,
            { maxRedirects: 0 },
          )
          .then(async (r) => {
            const provider = await request.get(r.headers().location!, { maxRedirects: 0 });
            let callback = new URL(provider.headers().location!);
            if (mode === "expired") await request.post(`${base}${CONTROL}/expire`);
            if (mode === "state-tampered") callback.searchParams.set("state", "tampered-state");
            if (mode === "provider-error") {
              callback.searchParams.set("error", "access_denied");
              callback.searchParams.set("error_description", dangerous);
            }
            if (mode === "marker-tampered") {
              const marker = (await context.cookies()).find(
                (c) => c.name === "better-auth.oauth_popup",
              )!;
              await context.addCookies([{ ...marker, value: `${marker.value}tampered` }]);
            }
            const before = await readState(request);
            const result = await responseRecord(
              await request.get(callback.href, { maxRedirects: 0 }),
            );
            const after = await readState(request);
            raw.push({ mode, before, after });
            expect(after.session).toHaveLength(mode === "marker-tampered" ? 1 : 0);
            expect(after.user).toHaveLength(mode === "marker-tampered" ? 1 : 0);
            expect(after.account).toHaveLength(mode === "marker-tampered" ? 1 : 0);
            if (mode === "marker-tampered") {
              expect(result.status).toBe(302);
              expect(result.body).not.toContain("better-auth:oauth-popup");
            } else {
              expect(result.status).toBe(200);
              expect(payload(result.body).nonce).toBe("nonce-132");
              expect(payload(result.body).token).toBeUndefined();
              if (mode === "provider-error") {
                expect(payload(result.body).error).toEqual({
                  code: "access_denied",
                  description: dangerous,
                });
              }
            }
            observations.push({
              mode,
              status: result.status,
              error: mode === "marker-tampered" ? null : payload(result.body).error,
              stateCount: after.verification.length,
            });
          });
      }
      await reset();
      const page = await context.newPage();
      await page.goto(`${base}/__health`);
      await page.addScriptTag({ content: clientJS });
      const result = await page.evaluate(async () =>
        (window as any).popupClient.signIn.popup({ provider: "gitlab", callbackURL: "/finished" }),
      );
      expect(result).toEqual({ data: { success: true }, error: null });
      const browserState = await readState(request);
      raw.push({ browserState });
      expect(browserState.session).toHaveLength(1);
      expect(
        await page.evaluate(
          async () => (await (window as any).popupClient.getSession()).data.user.email,
        ),
      ).toBe("popup-owner@fixture.test");
      expect(await page.evaluate(() => localStorage.getItem("better-auth.popup_token"))).toBeNull();
      observations.push({ officialSuccess: result });
      await reset();
      // Chromium's sandbox genuinely denies window.open (no allow-popups).
      await page.evaluate(() => {
        const iframe = document.createElement("iframe");
        iframe.sandbox.add("allow-scripts", "allow-same-origin");
        iframe.src = "/__health";
        document.body.append(iframe);
      });
      const frame = await page.waitForSelector("iframe").then((el) => el.contentFrame());
      await frame!.waitForLoadState();
      await frame!.addScriptTag({ content: clientJS });
      const blocked = await frame!.evaluate(async () =>
        (window as any).popupClient.signIn.popup({ provider: "gitlab" }),
      );
      expect(blocked.error.code).toBe("POPUP_BLOCKED");
      const blockedState = await readState(request);
      expect(blockedState.session).toHaveLength(0);
      expect(blockedState.verification).toHaveLength(0);
      observations.push({ blocked });
      await request.post(`${base}${CONTROL}/hold`);
      const popupEvent = context.waitForEvent("page");
      const closing = page.evaluate(async () =>
        (window as any).popupClient.signIn.popup({ provider: "gitlab" }),
      );
      const popup = await popupEvent;
      await popup.waitForURL(`**${CONTROL}/provider/oauth/authorize**`);
      await popup.close();
      const closed = await closing;
      expect(closed.error.code).toBe("POPUP_CLOSED");
      const closedState = await readState(request);
      expect(closedState.session).toHaveLength(0);
      expect(closedState.verification).toHaveLength(1);
      observations.push({ closed });
      await reset();
      await request.post(`${base}${CONTROL}/hold`);
      const heldEvent = context.waitForEvent("page");
      const held = page.evaluate(async () =>
        (window as any).popupClient.signIn.popup({ provider: "gitlab", timeoutMs: 5000 }),
      );
      void held.catch(() => {});
      const heldPopup = await heldEvent;
      await heldPopup.waitForURL(`**${CONTROL}/provider/oauth/authorize**`);
      const mark = (await context.cookies()).find((c) => c.name === "better-auth.oauth_popup")!;
      const nonce = JSON.parse(verify(mark.value)).popupNonce;
      await page.evaluate(
        (url) => {
          const frame = document.createElement("iframe");
          frame.id = "foreign-sender";
          frame.src = url;
          document.body.append(frame);
        },
        `${base.replace("localhost", "127.0.0.1")}/__health`,
      );
      const foreignFrame = await page
        .waitForSelector("#foreign-sender")
        .then((el) => el.contentFrame());
      await foreignFrame!.waitForLoadState();
      await foreignFrame!.evaluate(
        ({ nonce, base }) =>
          window.parent.postMessage(
            { type: "better-auth:oauth-popup", nonce, token: "foreign-token" },
            base,
          ),
        { nonce, base },
      );
      await page.evaluate(() =>
        window.postMessage(
          { type: "better-auth:oauth-popup", nonce: "wrong-nonce", token: "wrong-token" },
          location.origin,
        ),
      );
      const rejected = await held;
      expect(rejected.error.code).toBe("POPUP_TIMEOUT");
      expect((await readState(request)).session).toHaveLength(0);
      observations.push({ foreignAndWrongNonce: rejected });
      await reset();
      await page.evaluate(
        (url) => {
          const iframe = document.createElement("iframe");
          iframe.id = "embedded-app";
          iframe.src = url;
          document.body.append(iframe);
        },
        `${base.replace("localhost", "127.0.0.1")}/__health?authOrigin=${encodeURIComponent(base)}`,
      );
      const embedded = await page.waitForSelector("#embedded-app").then((el) => el.contentFrame());
      await embedded!.waitForLoadState();
      await embedded!.addScriptTag({ content: clientJS });
      const bearerHeaders: string[] = [];
      context.on("request", (request) => {
        if (request.url().endsWith(`${PATH}/get-session`) && request.headers().authorization) {
          bearerHeaders.push(request.headers().authorization!);
        }
      });
      const embeddedResult = await embedded!.evaluate(async () =>
        (window as any).popupClient.signIn.popup({ providerId: "local" }),
      );
      expect(embeddedResult).toEqual({ data: { success: true }, error: null });
      const embeddedState = await readState(request);
      raw.push({ embeddedState });
      expect(embeddedState.session).toHaveLength(1);
      expect(embeddedState.account[0].providerId).toBe("local");
      const embeddedToken = await embedded!.evaluate(() =>
        localStorage.getItem("better-auth.popup_token"),
      );
      expect(embeddedToken).not.toBeNull();
      expect(verify(embeddedToken!)).toBe(embeddedState.session[0].token);
      expect(bearerHeaders).toContain(`Bearer ${embeddedToken}`);
      const embeddedSession = await embedded!.evaluate(
        async () => (await (window as any).popupClient.getSession()).data,
      );
      expect(embeddedSession.user.id).toBe(embeddedState.user[0].id);
      await embedded!.evaluate(async () => (window as any).popupClient.signOut());
      expect(
        await embedded!.evaluate(() => localStorage.getItem("better-auth.popup_token")),
      ).toBeNull();
      expect((await readState(request)).session).toHaveLength(0);
      observations.push({
        embeddedSuccess: embeddedResult,
        bearerOwned: true,
        signoutClearsToken: true,
      });
      await context.close();
      return observations;
    } catch (error) {
      console.error("popup owner underlying failure", error);
      throw error;
    } finally {
      const directory = process.env.POPUP_EVIDENCE_DIR || "/tmp/popup132-evidence";
      await mkdir(directory, { recursive: true });
      await Bun.write(
        `${directory}/${base.includes(":3100") ? "source" : base.replace(/\W/g, "_")}-raw.json`,
        JSON.stringify(raw, null, 2),
      );
      await browser.close();
    }
  },
  [],
  60_000,
);
