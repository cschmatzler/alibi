import { expect } from "bun:test";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

import { importPKCS8, SignJWT } from "jose";

import { authProfilePath } from "../../../support/profiles";
import { compatScenario, type ScenarioContext } from "../../../support/scenario";

type State = {
  users: Record<string, any>[];
  accounts: Record<string, any>[];
  sessions: Record<string, any>[];
};
type Receipt = {
  path: string;
  authorization?: string | null;
  body?: [string, string][];
  raw?: string;
};
async function state(ctx: ScenarioContext): Promise<State> {
  return (await ctx.rawRequest({ path: "/__test/social-provider/state" })).body as State;
}
async function control(ctx: ScenarioContext, value: unknown) {
  expect(
    (
      await ctx.rawRequest({
        path: "/__test/generic-discovery/control",
        method: "POST",
        json: value,
      })
    ).status,
  ).toBe(200);
}
async function receipts(ctx: ScenarioContext): Promise<Receipt[]> {
  return (await ctx.rawRequest({ path: "/__test/generic-discovery/receipts" })).body as Receipt[];
}
async function evidence(
  ctx: ScenarioContext,
  name: string,
  result: unknown,
  rawStateRows?: unknown,
) {
  const rows = await receipts(ctx);
  if (process.env.DISCOVERY_EVIDENCE_DIR) {
    await Bun.write(
      `${process.env.DISCOVERY_EVIDENCE_DIR}/${Bun.hash(ctx.baseURL + name)}.json`,
      JSON.stringify({ name, baseURL: ctx.baseURL, result, receipts: rows, rawStateRows }, null, 2),
    );
  }
  return result;
}
function observed(rows: Receipt[]) {
  return rows
    .filter((r) => r.path !== "/metadata")
    .map(({ raw: _, body, ...row }) => ({
      ...row,
      ...(body
        ? {
            body: Object.fromEntries(
              body.map(([k, v]) => [k, k === "code_verifier" ? { token: v, length: v.length } : v]),
            ),
          }
        : {}),
    }));
}
for (const mode of ["success", "override", "fallback", "invalid-issuer", "mapped"] as const) {
  const name = `generic discovery ${mode} resolves real grants and retains account ownership`;
  compatScenario(
    name,
    async (ctx) => {
      const fixture = `generic-discovery-${mode}` as const;
      const actor = ctx.actor("owner", fixture);
      const foreign = ctx.actor("foreign", fixture);
      expect(
        (
          await foreign.client.signUp.email({
            email: ctx.uniqueEmail("foreign"),
            password: "Password123!",
            name: "Foreign",
          })
        ).error,
      ).toBeNull();
      const before = await state(ctx);
      const profile = {
        id: ctx.uniqueToken("subject"),
        email: ctx.uniqueEmail("discovery"),
        email_verified: true,
        name: "Discovery Name",
        picture: "https://image.example.invalid/profile",
        image: "https://ignored.example.invalid/profile",
      };
      await control(ctx, { profile });
      const start = await actor.client.signIn.social({
        provider: "discovery",
        callbackURL: "/dashboard",
        scopes: ["requested"],
      });
      await evidence(ctx, name + " start", { before, start: ctx.snapshot(start) });
      expect(start.error).toBeNull();
      const url = new URL(start.data!.url!);
      const kind = ["override", "fallback", "invalid-issuer"].includes(mode)
        ? "configured"
        : "discovered";
      expect(url.origin).toBe(`https://${kind}.example.invalid`);
      expect(url.pathname).toBe("/authorize");
      expect(url.searchParams.get("scope")).toBe("requested profile");
      expect(url.searchParams.has("nonce")).toBe(false);
      const callbackURL =
        ctx.baseURL +
        authProfilePath(fixture) +
        `/callback/discovery?code=discovery-code&state=${encodeURIComponent(url.searchParams.get("state")!)}`;
      const callback = await actor.fetch(callbackURL, { redirect: "manual" });
      expect(callback.headers.get("location")).toBe("/dashboard");
      const after = await state(ctx);
      for (const table of ["users", "accounts", "sessions"] as const) {
        expect(after[table]).toHaveLength(before[table].length + 1);
      }
      const account = after.accounts.find((a) => a.providerId === "discovery")!;
      expect(account.accountId).toBe(profile.id);
      expect(after.users.find((u) => u.id === account.userId)).toMatchObject({
        email: profile.email,
        name: mode === "mapped" ? "Mapped Name" : "Discovery Name",
        emailVerified: true,
        image: "https://image.example.invalid/profile",
      });
      expect(account).toMatchObject({
        accessToken: "discovery-access",
        refreshToken: "discovery-refresh",
        scope: "profile",
      });
      const metadata = (await receipts(ctx)).filter(
        (r) => r.path === "/metadata" && (r as any).mode === mode,
      );
      expect(metadata).toHaveLength(1);
      expect(metadata[0]).toMatchObject({ header: "configured-header" });
      const grant = (await receipts(ctx)).find((r) => r.path.startsWith("/token"))!;
      const form = Object.fromEntries(grant.body!);
      expect(grant.path).toBe(`/token/${kind}`);
      expect(grant).toMatchObject({ grantHeader: "configured-grant" });
      expect(form.resource).toBe("discovery-resource");
      expect(form.code).toBe("discovery-code");
      expect(form.client_secret).toBe("discovery-secret");
      expect(createHash("sha256").update(form.code_verifier!).digest("base64url")).toBe(
        url.searchParams.get("code_challenge")!,
      );
      expect((await receipts(ctx)).find((r) => r.path.startsWith("/user"))).toMatchObject({
        path: `/user/${kind}`,
        authorization: "Bearer discovery-access",
      });
      const replay = await actor.fetch(callbackURL, { redirect: "manual" });
      expect(new URL(replay.headers.get("location")!, ctx.baseURL).searchParams.get("error")).toBe(
        "state_mismatch",
      );
      expect(await state(ctx)).toEqual(after);
      const denied = await foreign.client.refreshToken({ accountId: String(account.id) });
      expect(denied.error).not.toBeNull();
      expect(await state(ctx)).toEqual(after);
      await control(ctx, {
        profile,
        tokenResponse: {
          access_token: "rotated-access",
          refresh_token: "rotated-refresh",
          token_type: "Bearer",
          expires_in: 1800,
          scope: "profile",
        },
      });
      const refresh = await actor.client.refreshToken({ accountId: String(account.id) });
      expect(refresh.error).toBeNull();
      const rotated = await state(ctx);
      expect(rotated.users).toEqual(after.users);
      expect(rotated.sessions).toEqual(after.sessions);
      expect(rotated.accounts.find((a) => a.id === account.id)).toMatchObject({
        accessToken: "rotated-access",
        refreshToken: "rotated-refresh",
      });
      const refreshGrant = (await receipts(ctx)).filter((r) => r.path.startsWith("/token"))[1]!;
      expect(Object.fromEntries(refreshGrant.body!)).toMatchObject({
        grant_type: "refresh_token",
        refresh_token: "discovery-refresh",
        resource: "refresh-resource",
      });
      expect((await actor.client.signOut()).error).toBeNull();
      const logout = await state(ctx);
      expect(logout.users).toEqual(rotated.users);
      expect(logout.accounts).toEqual(rotated.accounts);
      expect(logout.sessions).toEqual(before.sessions);
      return evidence(ctx, name, {
        start: ctx.snapshot(start),
        before,
        after,
        rotated,
        logout,
        denied: ctx.snapshot(denied),
        refresh: ctx.snapshot(refresh),
        receipts: observed(await receipts(ctx)),
      });
    },
    ["POST /sign-in/social", "GET /callback/{}", "POST /refresh-token", "POST /sign-out"],
  );
}
for (const mode of ["failed", "invalid-jwks", "required"] as const) {
  const name = `generic discovery ${mode} skips unusable provider without writes`;
  compatScenario(
    name,
    async (ctx) => {
      const before = await state(ctx);
      const actor = ctx.actor("owner", `generic-discovery-${mode}`);
      const start = await actor.client.signIn.social({
        provider: "discovery",
        callbackURL: "/dashboard",
      });
      expect(start.error?.code).toBe("PROVIDER_NOT_FOUND");
      expect(await state(ctx)).toEqual(before);
      expect((await receipts(ctx)).filter((r) => r.path !== "/metadata")).toHaveLength(0);
      return evidence(ctx, name, { before, after: await state(ctx), start: ctx.snapshot(start) });
    },
    ["POST /sign-in/social"],
  );
}
for (const failure of ["token", "userinfo"] as const) {
  const name = `generic discovery ${failure} failure cannot persist account or session`;
  compatScenario(
    name,
    async (ctx) => {
      const before = await state(ctx);
      const actor = ctx.actor("owner", "generic-discovery-success");
      await control(ctx, failure === "token" ? { tokenStatus: 503 } : { userStatus: 503 });
      const start = await actor.client.signIn.social({
        provider: "discovery",
        callbackURL: "/dashboard",
      });
      expect(start.error).toBeNull();
      const url = new URL(start.data!.url!);
      const response = await actor.fetch(
        ctx.baseURL +
          authProfilePath("generic-discovery-success") +
          `/callback/discovery?code=discovery-code&state=${encodeURIComponent(url.searchParams.get("state")!)}`,
        { redirect: "manual" },
      );
      expect(
        new URL(response.headers.get("location")!, ctx.baseURL).searchParams.get("error"),
      ).toBe(failure === "token" ? "invalid_code" : "unable_to_get_user_info");
      expect(await state(ctx)).toEqual(before);
      return evidence(ctx, name, {
        before,
        after: await state(ctx),
        status: response.status,
        location: response.headers.get("location"),
        receipts: observed(await receipts(ctx)),
      });
    },
    ["POST /sign-in/social", "GET /callback/{}"],
  );
}
for (const variant of [
  "valid",
  "issuer",
  "audience",
  "nonce",
  "signature",
  "algorithm",
  "expired",
] as const) {
  const name = `generic discovery oidc ${variant} uses discovered verification before profile admission`;
  compatScenario(
    name,
    async (ctx) => {
      const actor = ctx.actor("owner", "generic-discovery-oidc");
      const before = await state(ctx);
      const start = await actor.client.signIn.social({
        provider: "discovery",
        callbackURL: "/dashboard",
        additionalData: { idTokenNonce: "attacker-nonce" },
      });
      expect(start.error).toBeNull();
      const url = new URL(start.data!.url!);
      expect(url.searchParams.get("scope")).toBe("openid profile");
      const nonce = url.searchParams.get("nonce")!;
      expect(nonce).toBeTruthy();
      expect(nonce).not.toBe("attacker-nonce");
      const stateRows = (await ctx.readVerificationState({
        identifier: `auth-state:${url.searchParams.get("state")!}`,
      })) as { value: string }[];
      expect(stateRows).toHaveLength(1);
      const payload = JSON.parse(stateRows[0]!.value);
      expect(payload.idTokenNonce).toBe(nonce);

      const key = await importPKCS8(
        readFileSync(
          `../../../tests/fixtures/one-tap/${variant === "signature" ? "wrong-private-key.pem" : "private-key.pem"}`,
          "utf8",
        ),
        variant === "algorithm" ? "RS384" : "RS256",
      );
      const subject = ctx.uniqueToken("oidc-subject");
      const email = ctx.uniqueEmail("oidc");
      const token = await new SignJWT({
        sub: subject,
        email,
        name: "OIDC Name",
        email_verified: true,
        nonce: variant === "nonce" ? "wrong" : nonce,
      })
        .setProtectedHeader({
          alg: variant === "algorithm" ? "RS384" : "RS256",
          kid: "one-tap-local-rs256",
        })
        .setIssuer(
          variant === "issuer" ? "https://wrong.example.invalid" : "https://issuer.example.invalid",
        )
        .setAudience(variant === "audience" ? "wrong-client" : "discovery-client")
        .setExpirationTime(variant === "expired" ? 1 : 4102444800)
        .sign(key);
      await control(ctx, {
        profile: { id: "custom-id", sub: subject, email, name: "OIDC Name", emailVerified: true },
        tokenResponse: {
          access_token: "oidc-access",
          refresh_token: "oidc-refresh",
          token_type: "Bearer",
          expires_in: 3600,
          id_token: token,
          scope: "openid profile",
        },
      });
      const response = await actor.fetch(
        ctx.baseURL +
          authProfilePath("generic-discovery-oidc") +
          `/callback/discovery?code=discovery-code&state=${encodeURIComponent(url.searchParams.get("state")!)}`,
        { redirect: "manual" },
      );
      const after = await state(ctx);
      if (variant === "valid") {
        expect(response.headers.get("location")).toBe("/dashboard");
        expect(after.accounts).toHaveLength(before.accounts.length + 1);
        expect(after.accounts.find((a) => a.providerId === "discovery")).toMatchObject({
          accountId: subject,
        });
        expect(after.users[0]).toMatchObject({ email, name: "OIDC Name" });
      } else {
        expect(
          new URL(response.headers.get("location")!, ctx.baseURL).searchParams.get("error"),
        ).toBe("unable_to_get_user_info");
        expect(after).toEqual(before);
      }
      expect((await receipts(ctx)).some((r) => r.path.startsWith("/user"))).toBe(false);
      expect((await receipts(ctx)).filter((r) => r.path === "/custom")).toHaveLength(
        variant === "valid" ? 1 : 0,
      );
      return evidence(
        ctx,
        name,
        {
          start: ctx.snapshot(start),
          stateBinding: { idTokenNonce: payload.idTokenNonce },
          before,
          after,
          status: response.status,
          location: response.headers.get("location"),
          receipts: observed(await receipts(ctx)),
        },
        stateRows,
      );
    },
    ["POST /sign-in/social", "GET /callback/{}"],
  );
}
