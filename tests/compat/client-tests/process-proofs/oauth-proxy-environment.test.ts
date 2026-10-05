import { expect } from "bun:test";

import { symmetricDecrypt } from "better-auth/crypto";

import { oauthPurposeSecret } from "../support/oauth-encryption";
import { compatScenario } from "../support/scenario";
const secret = "local-fixture-dedicated-oauth-proxy-secret-32";
const path = "/__test/profiles/oauth-proxy/api/auth";
async function response(r: Response) {
  const text = await r.text();
  return {
    status: r.status,
    location: r.headers.get("location"),
    body: text ? JSON.parse(text) : text,
  };
}
const observations = (s: any) => ({
  ...s,
  receipts: s.receipts.map((r: any) => ({
    ...r,
    ...(r.body?.code_verifier
      ? {
          body: {
            ...r.body,
            code_verifier: { token: r.body.code_verifier, length: r.body.code_verifier.length },
          },
        }
      : {}),
  })),
});
const state = async (ctx: any) =>
  (await ctx.rawRequest({ path: "/__test/oauth-proxy/state" })).body;
compatScenario(
  "OAuth proxy remaining actual process vendor and production URL environment selection",
  async (ctx) => {
    const owner = ctx.actor("remaining-environment", "oauth-proxy");
    const environment = await ctx.rawRequest({
      path: "/__test/oauth-proxy/options",
      method: "POST",
      json: { mode: "environment" },
    });
    expect(environment.status).toBe(200);
    // An untrusted transport Host must fall back to the configured vendor URL,
    // never receive the authenticated provider profile.
    const vendorStart = await owner.fetch(`${ctx.baseURL}${path}/sign-in/social`, {
      method: "POST",
      redirect: "manual",
      headers: { host: "untrusted.fixture.test", "content-type": "application/json" },
      body: JSON.stringify({
        provider: "gitlab",
        callbackURL: `${ctx.baseURL}/vendor-done`,
        disableRedirect: true,
      }),
    });
    expect(vendorStart.status).toBe(200);
    const vendorBody = await vendorStart.json();
    const vendorURL = new URL(vendorBody.url);
    const vendorPack = JSON.parse(
      await symmetricDecrypt({
        key: oauthPurposeSecret(secret, "oauth-proxy-package"),
        data: vendorURL.searchParams.get("state")!,
      }),
    );
    const vendorState = JSON.parse(
      await symmetricDecrypt({
        key: oauthPurposeSecret(secret, "oauth-proxy-state"),
        data: vendorPack.stateCookie,
      }),
    );
    if (process.env.COMPAT_OBSERVATIONS_DIR) {
      await Bun.write(
        `${process.env.COMPAT_OBSERVATIONS_DIR}/vendor-${new URL(ctx.baseURL).port}.json`,
        JSON.stringify(
          {
            vendorBody,
            vendorPack,
            vendorState,
            cookies: vendorStart.headers.getSetCookie(),
            physical: await state(ctx),
          },
          null,
          2,
        ),
      );
    }
    expect(new URL(vendorState.callbackURL).origin).toBe(ctx.baseURL);
    const vendorApproved = await response(await owner.fetch(vendorURL, { redirect: "manual" }));
    const vendorTransfer = await response(
      await owner.fetch(vendorApproved.location!, { redirect: "manual", credentials: "omit" }),
    );
    const vendorBridge = new URL(vendorTransfer.location!);
    const vendorToken = vendorBridge.searchParams.get("profile")!;
    const vendorPayload = JSON.parse(
      await symmetricDecrypt({
        key: oauthPurposeSecret(secret, "oauth-proxy-profile"),
        data: vendorToken,
      }),
    );
    const vendorCompleted = await response(await owner.fetch(vendorBridge, { redirect: "manual" }));
    expect(vendorCompleted.location).toBe(`${ctx.baseURL}/vendor-done`);
    const skipEnvironment = await ctx.rawRequest({
      path: "/__test/oauth-proxy/options",
      method: "POST",
      json: { mode: "environment-skip" },
    });
    expect(skipEnvironment.status).toBe(200);
    // BETTER_AUTH_URL selects whether to skip; it does not replace the auth
    // base for exchange when productionURL is absent in the plugin options.
    const start = await owner.fetch(`${ctx.baseURL}${path}/sign-in/social`, {
      method: "POST",
      redirect: "manual",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        provider: "gitlab",
        callbackURL: `${ctx.baseURL}/environment-done`,
        disableRedirect: true,
      }),
    });
    expect(start.status).toBe(200);
    const started = await start.json();
    const authURL = new URL(started.url);
    const packed = JSON.parse(
      await symmetricDecrypt({
        key: oauthPurposeSecret(secret, "oauth-proxy-package"),
        data: authURL.searchParams.get("state")!,
      }),
    );
    expect(packed.isOAuthProxy).toBe(true);
    expect(authURL.searchParams.get("redirect_uri")).toBe(`${ctx.baseURL}${path}/callback/gitlab`);
    const stateBytes = await symmetricDecrypt({
      key: oauthPurposeSecret(secret, "oauth-proxy-state"),
      data: packed.stateCookie,
    });
    const saved = JSON.parse(stateBytes);
    expect(saved.oauthState).toBe(packed.state);
    const retained = {
      ...saved,
      oauthState: { state: saved.oauthState },
      codeVerifier: { token: saved.codeVerifier },
      expiresAt: new Date(saved.expiresAt).toISOString(),
    };
    const approved = await response(await owner.fetch(authURL, { redirect: "manual" }));
    const transfer = await response(
      await owner.fetch(approved.location!, { redirect: "manual", credentials: "omit" }),
    );
    const bridge = new URL(transfer.location!);
    const token = bridge.searchParams.get("profile")!;
    const payload = JSON.parse(
      await symmetricDecrypt({
        key: oauthPurposeSecret(secret, "oauth-proxy-profile"),
        data: token,
      }),
    );
    const completed = await response(await owner.fetch(bridge, { redirect: "manual" }));
    expect(completed.location).toBe(`${ctx.baseURL}/environment-done`);
    // The actual production transport matches BETTER_AUTH_URL and skips the
    // wrapper. This separate request only issues ordinary production state.
    const production = ctx.baseURL.replace("localhost", "127.0.0.1");
    const skipped = await owner.fetch(`${production}${path}/sign-in/social`, {
      method: "POST",
      redirect: "manual",
      credentials: "omit",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        provider: "gitlab",
        callbackURL: `${ctx.baseURL}/environment-done`,
        disableRedirect: true,
      }),
    });
    expect(skipped.status).toBe(200);
    const skippedBody = await skipped.json();
    const ordinaryState = new URL(skippedBody.url).searchParams.get("state")!;
    expect(ordinaryState).toHaveLength(32);
    return {
      vendorBody,
      vendorState: {
        ...vendorPack,
        stateCookie: {
          token: vendorPack.stateCookie,
          payload: {
            ...vendorState,
            oauthState: { state: vendorState.oauthState },
            codeVerifier: { token: vendorState.codeVerifier },
            expiresAt: new Date(vendorState.expiresAt).toISOString(),
          },
        },
      },
      vendorApproved,
      vendorTransfer,
      vendorProfile: { oauthProxyProfile: { token: vendorToken, payload: vendorPayload } },
      vendorCompleted,
      environment,
      skipEnvironment,
      started,
      environmentState: {
        ...packed,
        stateCookie: { token: packed.stateCookie, payload: retained },
      },
      approved,
      transfer,
      environmentProfile: { oauthProxyProfile: { token, payload } },
      completed,
      skipped: { status: skipped.status, body: skippedBody },
      final: observations(await state(ctx)),
    };
  },
  ["POST /sign-in/social", "GET /callback/{id}/oauth-proxy"],
  undefined,
  { oauthProxyProfileSecret: oauthPurposeSecret(secret, "oauth-proxy-profile") },
);
