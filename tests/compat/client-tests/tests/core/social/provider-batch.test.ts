import { expect } from "bun:test";
import { createHash } from "node:crypto";
import { mkdir } from "node:fs/promises";

import inputs from "../../../../fixtures/provider-batch-profiles.json";
import { authProfilePath, type FixtureProfile } from "../../../support/profiles";
import { compatScenario, type ScenarioContext } from "../../../support/scenario";

// Independent published contracts, exercised through the official social SDK.
// Existing dedicated owners retain lifecycle/proof/ownership/rotation controls.
const contracts = {
  roblox: ["https://apis.roblox.com/oauth/v1/authorize", ["openid", "profile"], false],
  salesforce: [
    "https://login.salesforce.com/services/oauth2/authorize",
    ["openid", "email", "profile"],
    true,
  ],
  slack: ["https://slack.com/openid/connect/authorize", ["openid", "profile", "email"], false],
  spotify: ["https://accounts.spotify.com/authorize", ["user-read-email"], true],
  tiktok: ["https://www.tiktok.com/v2/auth/authorize", ["user.info.profile"], false],
  twitch: ["https://id.twitch.tv/oauth2/authorize", ["user:read:email", "openid"], false],
  twitter: [
    "https://x.com/i/oauth2/authorize",
    ["users.read", "tweet.read", "offline.access", "users.email"],
    true,
  ],
  vercel: ["https://vercel.com/oauth/authorize", [], true],
  vk: ["https://id.vk.com/authorize", ["email", "phone"], true],
  wechat: ["https://open.weixin.qq.com/connect/qrconnect", ["snsapi_login"], false],
  zoom: ["https://zoom.us/oauth/authorize", [], true],
} as const;
type Provider = keyof typeof inputs;
const providers = Object.keys(inputs) as Provider[];
function selected(provider: Provider, mode: string): FixtureProfile {
  return `provider-batch-${provider}-${mode}` as FixtureProfile;
}
async function control(
  ctx: ScenarioContext,
  provider: Provider,
  value: Record<string, unknown> = {},
) {
  expect(
    (
      await ctx.rawRequest({
        path: "/__test/provider-batch/control",
        method: "POST",
        json: { provider, ...value },
      })
    ).status,
  ).toBe(200);
}
async function read(ctx: ScenarioContext, path: string) {
  // Physical SQL schemas and runtime-added wire headers are separate observers,
  // not authentication responses. Preserve their complete bytes in the archive;
  // assert contracts independently on each store and compare the SDK response.
  const response = await fetch(`${ctx.baseURL}/__test/provider-batch/${path}`);
  expect(response.status).toBe(200);
  return response.json();
}
async function archive(ctx: ScenarioContext, name: string, extra: unknown) {
  if (!process.env.PROVIDER_BATCH_EVIDENCE_DIR) return;
  await mkdir(process.env.PROVIDER_BATCH_EVIDENCE_DIR, { recursive: true });
  await Bun.write(
    `${process.env.PROVIDER_BATCH_EVIDENCE_DIR}/${Bun.hash(ctx.baseURL + name)}.json`,
    JSON.stringify(
      {
        name,
        baseURL: ctx.baseURL,
        extra,
        receipts: await read(ctx, "receipts"),
        callbacks: await read(ctx, "callbacks"),
        sql: await read(ctx, "sql-state"),
      },
      null,
      2,
    ),
  );
}
function grantBody(row: Record<string, any>) {
  if (!row.body?.code_verifier) return row.body;
  return {
    ...row.body,
    code_verifier: {
      token: row.body.code_verifier,
      length: row.body.code_verifier.length,
    },
  };
}
async function flow(
  ctx: ScenarioContext,
  provider: Provider,
  mode: string,
  scopes?: string[],
  requestSignUp?: boolean,
) {
  const profile = selected(provider, mode);
  const actor = ctx.actor("batch", profile);
  const start = await actor.client.signIn.social({
    provider,
    callbackURL: "/dashboard",
    scopes,
    requestSignUp,
    additionalParams: {
      owner: "batch",
      client_key: "must-not-replace-key",
      appid: "must-not-replace-appid",
    },
  });
  expect(start.error).toBeNull();
  const url = new URL(start.data!.url!);
  const response = await actor.fetch(
    ctx.baseURL +
      authProfilePath(profile) +
      `/callback/${provider}?code=batch-code&state=${encodeURIComponent(url.searchParams.get("state")!)}`,
    { redirect: "manual" },
  );
  return { actor, start, url, response };
}
function status(response: Response, baseURL: string) {
  return {
    status: response.status,
    location: response.headers.get("location"),
    error: response.headers.get("location")
      ? new URL(response.headers.get("location")!, baseURL).searchParams.get("error")
      : null,
    clearsState: response.headers
      .getSetCookie()
      .some(
        (value) => /better-auth\.(?:oauth_)?state=;/.test(value) && value.includes("Max-Age=0"),
      ),
  };
}

for (const provider of Object.keys(contracts) as Array<keyof typeof contracts>) {
  for (const mode of ["default", "configured", "disabled-configured"]) {
    compatScenario(
      `provider batch ${provider} ${mode} factory and real callback`,
      async (ctx) => {
        await control(ctx, provider);
        const requested = mode === "default" ? undefined : ["requested", "shared", "requested"];
        const completed = await flow(ctx, provider, mode, requested);
        const [endpoint, defaults, pkce] = contracts[provider];
        expect(completed.url.origin + completed.url.pathname).toBe(endpoint);
        const configured = mode === "default" ? [] : ["configured", "shared", "configured"];
        const base = mode === "disabled-configured" ? [] : [...defaults];
        const scopes =
          provider === "slack"
            ? [...base, ...(requested ?? []), ...configured]
            : [...base, ...configured, ...(requested ?? [])];
        expect(completed.url.searchParams.get("scope")).toBe(
          provider === "zoom"
            ? null
            : scopes.length
              ? scopes.join(["tiktok", "wechat"].includes(provider) ? "," : " ")
              : ["tiktok", "wechat"].includes(provider)
                ? ""
                : null,
        );
        expect(completed.url.searchParams.get("code_challenge_method")).toBe(pkce ? "S256" : null);
        expect(completed.url.searchParams.get("owner")).toBe("batch");
        expect(completed.url.searchParams.get("state")).not.toBe("must-not-replace-state");
        expect(
          completed.url.searchParams.get(
            provider === "tiktok" ? "client_key" : provider === "wechat" ? "appid" : "client_id",
          ),
        ).toBe("batch-client");
        if (provider === "twitch") {
          expect(completed.url.searchParams.get("claims")).toBe(
            '{"id_token":{"email":null,"email_verified":null,"preferred_username":null,"picture":null}}',
          );
        }
        expect(completed.response.status).toBe(302);
        expect(completed.response.headers.get("location")).toBe("/dashboard");
        const session = await completed.actor.client.getSession();
        expect(session.error).toBeNull();
        expect(session.data?.user.name).toBe("Batch Name");
        const wire = (await read(ctx, "receipts")) as Array<Record<string, any>>;
        expect(wire[0]!.stage).toBe("token");
        expect(wire[0]!.method).toBe(provider === "wechat" ? "GET" : "POST");
        const grant = provider === "wechat" ? wire[0]!.query : wire[0]!.body;
        expect(grant.code).toBe("batch-code");
        expect(grant.grant_type).toBe("authorization_code");
        expect(Boolean(grant.code_verifier)).toBe(pkce || provider === "tiktok");
        if (pkce) {
          expect(grant.code_verifier).toMatch(/^[A-Za-z0-9_-]+$/);
          expect(
            createHash("sha256")
              .update(grant.code_verifier as string)
              .digest("base64url"),
          ).toBe(completed.url.searchParams.get("code_challenge")!);
        }
        if (provider === "twitter") {
          expect((wire[0]!.declaredHeaders ?? wire[0]!.headers).authorization).toBe(
            "Basic " + Buffer.from("batch-client:batch-secret").toString("base64"),
          );
        }
        if (provider === "vk") {
          expect(wire[1]!.method).toBe("POST");
          expect(wire[1]!.body).toEqual({
            access_token: "batch-access",
            client_id: "batch-client",
          });
        }
        if (provider === "twitter") {
          expect(wire.map((row) => row.stage)).toEqual(["token", "user", "email"]);
        }
        if (provider === "twitch") expect(wire).toHaveLength(1);
        const sql = (await read(ctx, "sql-state")) as Record<
          string,
          Array<Record<string, unknown>>
        >;
        const source = "user" in sql;
        const users = sql[source ? "user" : "users"]!;
        const accounts = sql[source ? "account" : "accounts"]!;
        const sessions = sql[source ? "session" : "sessions"]!;
        expect(users).toHaveLength(1);
        expect(accounts).toHaveLength(1);
        expect(sessions).toHaveLength(1);
        expect(accounts[0]![source ? "accountId" : "account_id"]).toBe("batch-subject");
        expect(accounts[0]![source ? "accessToken" : "access_token"]).toBe("batch-access");
        await archive(ctx, `${provider}-${mode}`, {
          start: completed.start,
          session,
          status: status(completed.response, ctx.baseURL),
        });
        return {
          start: ctx.snapshot(completed.start),
          session: ctx.snapshot(session),
          callback: status(completed.response, ctx.baseURL),
          stages: wire.map((row) => ({
            stage: row.stage,
            method: row.method,
            query: row.query,
            body: grantBody(row),
          })),
          rowCounts: {
            users: users.length,
            accounts: accounts.length,
            sessions: sessions.length,
          },
        };
      },
      ["POST /sign-in/social", "GET /callback/{}"],
    );
  }
}

for (const provider of providers) {
  for (const mode of ["mapped-async", "custom-async", "mapper-error", "custom-error"]) {
    compatScenario(
      `provider batch ${provider} ${mode} application callback contract`,
      async (ctx) => {
        const responseProfile: any = structuredClone(inputs[provider]);
        const witness = `application-profile-${provider}-${mode}`;
        if (provider === "notion") responseProfile.bot.owner.user.applicationWitness = witness;
        else responseProfile.applicationWitness = witness;
        const providedProfile =
          provider === "notion" && mode.startsWith("custom")
            ? responseProfile.bot.owner.user
            : responseProfile;
        const grant = {
          access_token: `application-${provider}-access`,
          refresh_token: `application-${provider}-refresh`,
          token_type: "Bearer",
          expires_in: 3600,
          refresh_token_expires_in: 7200,
          scope: "identity email",
          openid: "batch-subject",
          ...(["paybin", "twitch"].includes(provider)
            ? {
                id_token: `e30.${Buffer.from(JSON.stringify(responseProfile)).toString("base64url")}.fixture`,
              }
            : {}),
        };
        await control(ctx, provider, { profile: providedProfile, tokenResponse: grant });
        const completed = await flow(ctx, provider, mode);
        const ignored = provider === "tiktok" && ["mapped-async", "mapper-error"].includes(mode);
        const caught = ["paypal", "salesforce"].includes(provider) && mode === "mapper-error";
        const failure = mode.endsWith("error") && !ignored;
        const outcome = status(completed.response, ctx.baseURL);
        expect(outcome.status).toBe(failure ? (caught ? 302 : 500) : 302);
        expect(outcome.clearsState).toBe(!failure || caught);
        if (failure) {
          expect((await completed.actor.client.getSession()).data).toBeNull();
          expect(outcome.error).toBe(caught ? "unable_to_get_user_info" : null);
        } else {
          expect(outcome.location).toBe("/dashboard");
          const session = await completed.actor.client.getSession();
          expect(session.data?.user.name).toBe(
            mode === "custom-async" ? "Callback Name" : ignored ? "Batch Name" : "Async Name",
          );
        }
        const callbacks = (await read(ctx, "callbacks")) as Array<Record<string, unknown>>;
        expect(callbacks).toHaveLength(ignored ? 0 : 1);
        if (!ignored) {
          expect(callbacks[0]!.provider).toBe(provider);
          if (mode.startsWith("mapper") || mode.startsWith("mapped")) {
            const expected =
              provider === "notion"
                ? responseProfile.bot.owner.user
                : provider === "twitter"
                  ? {
                      ...responseProfile,
                      data: { ...responseProfile.data, email: "batch@example.invalid" },
                    }
                  : responseProfile;
            expect(callbacks[0]!.profile).toEqual(expected);
          } else {
            const token = callbacks[0]!.token as any;
            expect(token.accessToken).toBe(`application-${provider}-access`);
            expect(token.refreshToken).toBe(`application-${provider}-refresh`);
            expect(token.tokenType).toBe("Bearer");
            expect(token.scopes).toEqual(
              provider === "wechat" ? ["identity email"] : ["identity", "email"],
            );
            expect(Date.parse(token.accessTokenExpiresAt) - Date.now()).toBeGreaterThan(3590000);
            expect(Date.parse(token.accessTokenExpiresAt) - Date.now()).toBeLessThanOrEqual(
              3600000,
            );
            if (provider === "wechat")
              expect(token.openid ?? token.raw?.openid).toBe("batch-subject");
            else {
              expect(token.raw).toEqual(grant);
              expect(Date.parse(token.refreshTokenExpiresAt) - Date.now()).toBeGreaterThan(7190000);
              expect(Date.parse(token.refreshTokenExpiresAt) - Date.now()).toBeLessThanOrEqual(
                7200000,
              );
              if (provider === "paybin" || provider === "twitch")
                expect(token.idToken).toBe(grant.id_token);
            }
          }
        }
        const sql = (await read(ctx, "sql-state")) as Record<
          string,
          Array<Record<string, unknown>>
        >;
        const source = "user" in sql;
        expect(sql[source ? "user" : "users"]).toHaveLength(failure ? 0 : 1);
        expect(sql[source ? "verification" : "verifications"]).toHaveLength(0);
        if (!failure) {
          expect(
            sql[source ? "account" : "accounts"]![0]![source ? "accountId" : "account_id"],
          ).toBe("batch-subject");
        }
        await archive(ctx, `${provider}-${mode}`, { outcome });
        return {
          outcome,
          // Rust Option::None and JS undefined both represent an absent optional token.
          // WeChat's JS provider exposes semantic extras at the top level; the Rust
          // callback carries them in raw. The assertions above bind those actual
          // fields before this platform representation projection.
          callbacks: ctx.snapshot(
            callbacks.map((receipt) => {
              if (!receipt.token) return receipt;
              const token = { ...(receipt.token as Record<string, unknown>) };
              if (token.idToken == null) delete token.idToken;
              if (provider === "wechat") {
                const raw = token.raw as Record<string, unknown> | undefined;
                const openid = token.openid ?? raw?.openid;
                const unionid = token.unionid ?? raw?.unionid;
                delete token.raw;
                delete token.refreshTokenExpiresAt;
                delete token.openid;
                delete token.unionid;
                if (openid != null) token.openid = openid;
                if (unionid != null) token.unionid = unionid;
              }
              return { ...receipt, token };
            }),
          ),
          accountSubject: failure ? null : "batch-subject",
        };
      },
      ["POST /sign-in/social", "GET /callback/{}"],
    );
  }
}

for (const [label, provider, profile, expectedName, expectedVerified, physicalVerified] of [
  ["empty verification", "paypal", { ...inputs.paypal, email_verified: "" }, "Batch Name", "", ""],
  ["numeric verification", "slack", { ...inputs.slack, email_verified: 2 }, "Batch Name", false, 2],
  [
    "numeric name and image",
    "notion",
    {
      bot: {
        owner: {
          user: { ...inputs.notion.bot.owner.user, name: 2, avatar_url: 2 },
        },
      },
    },
    "2",
    false,
    0,
  ],
] as const) {
  compatScenario(
    `provider batch raw SQL scalar regression ${label}`,
    async (ctx) => {
      await control(ctx, provider, { profile });
      const completed = await flow(ctx, provider, "default");
      expect(completed.response.headers.get("location")).toBe("/dashboard");
      const session = await completed.actor.client.getSession();
      expect(session.error).toBeNull();
      expect(session.data?.user.name).toBe(expectedName);
      expect((session.data?.user as unknown as Record<string, unknown>)?.emailVerified).toEqual(
        expectedVerified,
      );
      if (provider === "notion") expect(session.data?.user.image).toBe("2");
      const sql = (await read(ctx, "sql-state")) as Record<string, Array<Record<string, unknown>>>;
      const source = "user" in sql;
      const row = sql[source ? "user" : "users"]![0]!;
      expect(row[source ? "emailVerified" : "email_verified"]).toBe(physicalVerified);
      expect(sql[source ? "account" : "accounts"]).toHaveLength(1);
      expect(sql[source ? "session" : "sessions"]).toHaveLength(1);
      await archive(ctx, label, {
        session,
        status: status(completed.response, ctx.baseURL),
      });
      return {
        session: ctx.snapshot(session),
        verification: row[source ? "emailVerified" : "email_verified"],
      };
    },
    ["GET /callback/{}", "GET /get-session"],
  );
}

for (const provider of ["vk", "wechat"] as const) {
  compatScenario(
    `provider batch ${provider} original client array reaches custom transport`,
    async (ctx) => {
      await control(ctx, provider);
      const completed = await flow(ctx, provider, "client-array");
      expect(completed.response.headers.get("location")).toBe("/dashboard");
      expect(completed.url.searchParams.get(provider === "wechat" ? "appid" : "client_id")).toBe(
        provider === "wechat" ? "batch-client,secondary-client" : "batch-client",
      );
      const receipts = (await read(ctx, "receipts")) as Array<Record<string, any>>;
      expect(provider === "wechat" ? receipts[0]!.query.appid : receipts[1]!.body.client_id).toBe(
        "batch-client,secondary-client",
      );
      await archive(ctx, `${provider}-client-array`, {
        start: completed.start,
      });
      return {
        start: ctx.snapshot(completed.start),
        wire: receipts.map((row) => ({
          stage: row.stage,
          method: row.method,
          query: row.query,
          body: grantBody(row),
        })),
      };
    },
    ["GET /callback/{}"],
  );
}

for (const provider of ["spotify", "wechat", "vercel"] as const) {
  compatScenario(
    `provider batch ${provider} encrypted tokens persist and decrypt through official account API`,
    async (ctx) => {
      await control(ctx, provider);
      const completed = await flow(ctx, provider, "encrypted");
      expect(completed.response.headers.get("location")).toBe("/dashboard");
      const sql = (await read(ctx, "sql-state")) as Record<string, Array<Record<string, unknown>>>;
      const source = "user" in sql;
      const account = sql[source ? "account" : "accounts"]![0]!;
      const token = await completed.actor.client.getAccessToken({
        accountId: String(account.id),
      });
      expect(token.error).toBeNull();
      expect(token.data?.accessToken).toBe("batch-access");
      const stored = account[source ? "accessToken" : "access_token"];
      expect(stored).toBeString();
      expect(stored).not.toBe("batch-access");
      expect(String(stored)).toMatch(/^(?:\$ba\$\d+\$)?[0-9a-f]+$/);
      if (provider === "wechat") {
        expect(account[source ? "idToken" : "id_token"]).toBeNull();
      }
      await archive(ctx, `${provider}-encrypted`, { token });
      return {
        token: ctx.snapshot(token),
        encrypted: true,
        idToken:
          provider === "wechat" ? account[source ? "idToken" : "id_token"] : "not-applicable",
      };
    },
    ["GET /callback/{}", "POST /get-access-token"],
  );
}

// Exercise the changed persistence branch, including Zoom's absent options.
for (const provider of providers) {
  compatScenario(
    `provider batch ${provider} override updates only original owned profile`,
    async (ctx) => {
      await control(ctx, provider);
      const first = await flow(ctx, provider, "override");
      expect(first.response.headers.get("location")).toBe("/dashboard");
      const before = await first.actor.client.getSession();
      const updated: any = structuredClone(inputs[provider]);
      const data =
        provider === "notion"
          ? updated.bot.owner.user
          : provider === "tiktok"
            ? updated.data.user
            : provider === "twitter"
              ? updated.data
              : provider === "vk"
                ? updated.user
                : updated;
      const nameKey =
        provider === "polar"
          ? "public_name"
          : ["roblox", "wechat"].includes(provider)
            ? "nickname"
            : provider === "twitch"
              ? "preferred_username"
              : ["spotify", "tiktok"].includes(provider)
                ? "display_name"
                : "name";
      if (provider === "vk") {
        data.first_name = "Updated";
        data.last_name = "Name";
      } else if (provider === "zoom") data.display_name = "Updated Name";
      else data[nameKey] = "Updated Name";
      await control(ctx, provider, { profile: updated });
      const second = await flow(ctx, provider, "override");
      expect(second.response.headers.get("location")).toBe("/dashboard");
      const after = await second.actor.client.getSession();
      expect(after.data?.user.id).toBe(before.data?.user.id);
      expect(after.data?.user.name).toBe(provider === "zoom" ? "Batch Name" : "Updated Name");
      const sql: any = await read(ctx, "sql-state");
      const source = "user" in sql;
      expect(sql[source ? "user" : "users"]).toHaveLength(1);
      expect(sql[source ? "account" : "accounts"]).toHaveLength(1);
      expect(sql[source ? "session" : "sessions"]).toHaveLength(2);
      expect(sql[source ? "account" : "accounts"][0][source ? "accountId" : "account_id"]).toBe(
        "batch-subject",
      );
      await archive(ctx, `${provider}-override`, { before, after });
      return { before: ctx.snapshot(before), after: ctx.snapshot(after) };
    },
    ["GET /callback/{}", "GET /get-session"],
  );
}

for (const provider of ["spotify", "wechat", "vercel"] as const) {
  compatScenario(
    `provider batch ${provider} refresh callback follows factory support`,
    async (ctx) => {
      await control(ctx, provider);
      const completed = await flow(ctx, provider, "refresh-callback");
      expect(completed.response.headers.get("location")).toBe("/dashboard");
      const sql: any = await read(ctx, "sql-state");
      const source = "user" in sql;
      const account = sql[source ? "account" : "accounts"][0];
      const token = await completed.actor.client.refreshToken({
        accountId: String(account.id),
      });
      const callbacks: any[] = await read(ctx, "callbacks");
      if (provider === "vercel") {
        expect(token.error?.code).toBe("TOKEN_REFRESH_NOT_SUPPORTED");
        expect(callbacks).toEqual([]);
        expect(await read(ctx, "sql-state")).toEqual(sql);
      } else {
        expect(token.error).toBeNull();
        expect(token.data?.accessToken).toBe("callback-access");
        expect(token.data?.refreshToken).toBe("callback-refresh");
        expect(callbacks).toEqual([{ kind: "refresh", provider, refreshToken: "batch-refresh" }]);
        const after: any = await read(ctx, "sql-state");
        expect(
          after[source ? "account" : "accounts"][0][source ? "accessToken" : "access_token"],
        ).toBe("callback-access");
        expect(
          after[source ? "account" : "accounts"][0][source ? "refreshToken" : "refresh_token"],
        ).toBe("callback-refresh");
        expect(after[source ? "user" : "users"]).toEqual(sql[source ? "user" : "users"]);
        expect(after[source ? "session" : "sessions"]).toEqual(
          sql[source ? "session" : "sessions"],
        );
      }
      await archive(ctx, `${provider}-refresh-callback`, { token });
      return { token: ctx.snapshot(token), callbacks };
    },
    ["POST /refresh-token"],
  );
}

compatScenario(
  "provider batch stored scopes use comma boundaries and JavaScript trim",
  async (ctx) => {
    await control(ctx, "wechat", {
      tokenResponse: {
        access_token: "batch-access",
        openid: "batch-subject",
        refresh_token: "batch-refresh",
        expires_in: 3600,
        scope: "\u0085alpha\u0085,\ufeffbeta\ufeff",
      },
    });
    const completed = await flow(ctx, "wechat", "default");
    expect(completed.response.headers.get("location")).toBe("/dashboard");
    const sql: any = await read(ctx, "sql-state");
    const source = "user" in sql;
    const account = sql[source ? "account" : "accounts"][0];
    expect(account.scope).toBe("\u0085alpha\u0085,\ufeffbeta\ufeff");
    const token = await completed.actor.client.getAccessToken({
      accountId: String(account.id),
    });
    expect(token.error).toBeNull();
    expect(token.data?.scopes).toEqual(["\u0085alpha\u0085", "beta"]);
    await archive(ctx, "stored-scopes", { token });
    return { token: ctx.snapshot(token), storedScope: account.scope };
  },
  ["POST /get-access-token"],
);

for (const variant of ["missing", "malformed", "valid"] as const) {
  compatScenario(
    `Twitch ID token ${variant} callback and replay`,
    async (ctx) => {
      const foreign = ctx.actor("foreign");
      expect(
        (
          await foreign.client.signUp.email({
            email: ctx.uniqueEmail("twitch-foreign"),
            password: "password123",
            name: "Foreign owner",
          })
        ).error,
      ).toBeNull();
      const foreignSession = await foreign.client.getSession();
      const grant: Record<string, unknown> = {
        access_token: "twitch-real-grant",
        refresh_token: "twitch-real-refresh",
        token_type: "Bearer",
        expires_in: 3600,
        scope: "openid user:read:email",
      };
      if (variant === "malformed") grant.id_token = "not-a-jwt";
      if (variant === "valid")
        grant.id_token = `e30.${Buffer.from(JSON.stringify(inputs.twitch)).toString("base64url")}.fixture`;
      await control(ctx, "twitch", { tokenResponse: grant });
      const completed = await flow(ctx, "twitch", "default");
      const publicResult = status(completed.response, ctx.baseURL);
      const body = await completed.response.text();
      if (variant === "valid") {
        expect(publicResult.status).toBe(302);
        expect(publicResult.location).toBe("/dashboard");
      } else if (variant === "missing") {
        expect(publicResult.status).toBe(302);
        expect(publicResult.error).toBe("unable_to_get_user_info");
      } else expect(publicResult.status).toBe(500);
      const session = await completed.actor.client.getSession();
      if (variant === "valid") expect(session.data?.user.name).toBe("Batch Name");
      else {
        expect(session.data).toBeNull();
        expect(
          completed.response.headers
            .getSetCookie()
            .some(
              (cookie) => /session_token=([^;]+)/.test(cookie) && !cookie.includes("Max-Age=0"),
            ),
        ).toBe(false);
      }
      const sql = (await read(ctx, "sql-state")) as Record<string, any[]>;
      const source = "user" in sql;
      expect(sql[source ? "user" : "users"]).toHaveLength(variant === "valid" ? 2 : 1);
      expect(sql[source ? "account" : "accounts"]).toHaveLength(variant === "valid" ? 2 : 1);
      expect(sql[source ? "verification" : "verifications"]).toHaveLength(0);
      expect(await foreign.client.getSession()).toEqual(foreignSession);
      const replay = await completed.actor.fetch(
        ctx.baseURL +
          authProfilePath(selected("twitch", "default")) +
          `/callback/twitch?code=batch-code&state=${encodeURIComponent(completed.url.searchParams.get("state")!)}`,
        { redirect: "manual" },
      );
      expect(status(replay, ctx.baseURL).error).toBe("state_mismatch");
      const receipts: any[] = await read(ctx, "receipts");
      expect(receipts.map((row) => row.stage)).toEqual(["token"]);
      return {
        result: publicResult,
        body,
        session: ctx.snapshot(session),
        replay: status(replay, ctx.baseURL),
        wire: receipts.map((row) => ({
          stage: row.stage,
          method: row.method,
          body: grantBody(row),
        })),
        foreign: ctx.snapshot(foreignSession),
      };
    },
    ["POST /sign-in/social", "GET /callback/{}", "GET /get-session"],
  );
}

// Missing/empty optional fields must reach the provider's actual fallback branch.
for (const variant of ["missing", "empty"] as const) {
  for (const provider of ["roblox", "slack", "salesforce", "spotify"] as const) {
    compatScenario(
      `provider profile fallback ${provider} ${variant}`,
      async (ctx) => {
        const foreign = ctx.actor("foreign");
        const foreignEmail = ctx.uniqueEmail("fallback-foreign");
        const foreignSignup = await foreign.client.signUp.email({
          email: foreignEmail,
          password: "password123",
          name: "Unrelated owner",
        });
        expect(foreignSignup.error).toBeNull();
        const before = await foreign.client.getSession();
        const profile: any = structuredClone(inputs[provider]);
        const fallback = "https://images.example.invalid/fallback.png";
        let expectedName = "Batch Name";
        let expectedImage: string | null = fallback;
        if (provider === "roblox") {
          if (variant === "empty") profile.nickname = "";
          else delete profile.nickname;
          profile.preferred_username = "Fallback username";
          expectedName = "Fallback username";
          expectedImage = "https://images.example.invalid/batch.png";
        } else if (provider === "slack") {
          if (variant === "empty") profile.picture = "";
          else delete profile.picture;
          profile["https://slack.com/user_image_512"] = fallback;
        } else if (provider === "salesforce") {
          if (variant === "empty") profile.photos.picture = "";
          else delete profile.photos.picture;
          profile.photos.thumbnail = fallback;
        } else {
          profile.images =
            variant === "empty"
              ? []
              : [{ url: fallback }, { url: "https://images.example.invalid/second.png" }];
          expectedImage = variant === "empty" ? null : fallback;
        }
        await control(ctx, provider, { profile });
        const completed = await flow(ctx, provider, "default");
        expect(completed.response.status).toBe(302);
        expect(completed.response.headers.get("location")).toBe("/dashboard");
        const session = await completed.actor.client.getSession();
        expect(session.error).toBeNull();
        expect(session.data?.user.name).toBe(expectedName);
        expect(session.data?.user.image ?? null).toBe(expectedImage);
        expect(session.data?.user.emailVerified).toBe(["salesforce", "slack"].includes(provider));
        const sql = (await read(ctx, "sql-state")) as Record<string, any[]>;
        const source = "user" in sql;
        const users = sql[source ? "user" : "users"]!;
        const accounts = sql[source ? "account" : "accounts"]!;
        const owner = users.find((row) => row.id === session.data!.user.id);
        expect(owner).toMatchObject({ name: expectedName, image: expectedImage });
        expect(
          accounts.find((row) => row[source ? "providerId" : "provider_id"] === provider),
        ).toMatchObject({
          [source ? "accountId" : "account_id"]: "batch-subject",
          [source ? "userId" : "user_id"]: owner.id,
        });
        expect(users).toHaveLength(2);
        expect(accounts).toHaveLength(2);
        expect(await foreign.client.getSession()).toEqual(before);
        return {
          session: ctx.snapshot(session),
          callback: status(completed.response, ctx.baseURL),
          foreign: ctx.snapshot(before),
        };
      },
      ["POST /sign-in/social", "GET /callback/{}", "GET /get-session"],
    );
  }
}

for (const hasUnion of [true, false]) {
  compatScenario(
    `WeChat union identity ${hasUnion ? "stable across applications" : "empty falls back"}`,
    async (ctx) => {
      const foreign = ctx.actor("foreign");
      expect(
        (
          await foreign.client.signUp.email({
            email: ctx.uniqueEmail("wechat-foreign"),
            password: "password123",
            name: "Unrelated owner",
          })
        ).error,
      ).toBeNull();
      const foreignSession = await foreign.client.getSession();
      const subject = hasUnion ? "stable-union" : "application-one";
      const observations = [];
      let originalOwner: string | undefined;
      let originalAccount: string | undefined;
      for (const app of hasUnion ? ["one", "two"] : ["one"]) {
        await control(ctx, "wechat", {
          profile: {
            ...inputs.wechat,
            unionid: hasUnion ? "stable-union" : "",
            openid: `application-${app}`,
          },
          tokenResponse: {
            access_token: `wechat-${app}-access`,
            refresh_token: `wechat-${app}-refresh`,
            expires_in: 3600,
            scope: "snsapi_login",
            openid: `transport-${app}`,
          },
        });
        const completed = await flow(ctx, "wechat", "default");
        expect(completed.response.headers.get("location")).toBe("/dashboard");
        const session = await completed.actor.client.getSession();
        expect(session.data?.user.email).toBe(`${subject}@wechat.placeholder.invalid`);
        expect(session.data?.user.emailVerified).toBe(false);
        const sql = (await read(ctx, "sql-state")) as Record<string, any[]>;
        const source = "user" in sql;
        const accounts = sql[source ? "account" : "accounts"]!;
        const account = accounts.find(
          (row) => row[source ? "providerId" : "provider_id"] === "wechat",
        );
        expect(account[source ? "accountId" : "account_id"]).toBe(subject);
        expect(account[source ? "userId" : "user_id"]).toBe(session.data!.user.id);
        if (app === "one") {
          originalOwner = session.data!.user.id;
          originalAccount = account.id;
        } else {
          expect(session.data!.user.id).toBe(originalOwner!);
          expect(account.id).toBe(originalAccount!);
        }
        expect(sql[source ? "user" : "users"]).toHaveLength(2);
        expect(accounts).toHaveLength(2);
        expect(sql[source ? "session" : "sessions"]).toHaveLength(app === "one" ? 2 : 3);
        const receipts: any[] = await read(ctx, "receipts");
        expect(receipts.map((row) => row.stage)).toEqual(
          app === "one" ? ["token", "user"] : ["token", "user", "token", "user"],
        );
        expect(receipts.at(-1)!.query).toMatchObject({
          openid: `transport-${app}`,
          access_token: `wechat-${app}-access`,
          lang: "zh_CN",
        });
        observations.push({
          session: ctx.snapshot(session),
          callback: status(completed.response, ctx.baseURL),
          subject,
          query: receipts.at(-1)!.query,
        });
      }
      expect(await foreign.client.getSession()).toEqual(foreignSession);
      return { observations, foreign: ctx.snapshot(foreignSession) };
    },
    ["POST /sign-in/social", "GET /callback/{}", "GET /get-session"],
  );
}

for (const emailMode of ["http-error", "missing", "empty", "confirmed", "primary-error"] as const) {
  for (const inline of [true, false]) {
    if (emailMode === "primary-error" && inline) continue;
    compatScenario(
      `Twitter optional email ${emailMode} inline=${inline}`,
      async (ctx) => {
        const foreign = ctx.actor("foreign");
        expect(
          (
            await foreign.client.signUp.email({
              email: ctx.uniqueEmail("twitter-foreign"),
              password: "password123",
              name: "Unrelated owner",
            })
          ).error,
        ).toBeNull();
        const foreignSession = await foreign.client.getSession();
        const profile = {
          data: { ...inputs.twitter.data, ...(inline ? { email: "inline@example.invalid" } : {}) },
        };
        await control(ctx, "twitter", {
          profile,
          profileStatus: emailMode === "primary-error" ? 503 : 200,
          emailStatus: emailMode === "http-error" ? 503 : 200,
          emailProfile: {
            data:
              emailMode === "missing"
                ? {}
                : { confirmed_email: emailMode === "confirmed" ? "confirmed@example.invalid" : "" },
          },
        });
        const completed = await flow(ctx, "twitter", "default");
        const session = await completed.actor.client.getSession();
        const denied = emailMode === "primary-error";
        const expectedEmail =
          emailMode === "confirmed"
            ? "confirmed@example.invalid"
            : inline
              ? "inline@example.invalid"
              : "batch-subject@twitter.placeholder.invalid";
        expect(completed.response.status).toBe(302);
        if (denied) {
          expect(status(completed.response, ctx.baseURL).error).toBe("unable_to_get_user_info");
          expect(session.data).toBeNull();
        } else {
          expect(completed.response.headers.get("location")).toBe("/dashboard");
          expect(session.data?.user).toMatchObject({
            email: expectedEmail,
            emailVerified: emailMode === "confirmed",
            name: "Batch Name",
          });
        }
        const receipts: any[] = await read(ctx, "receipts");
        expect(receipts.map((row) => row.stage)).toEqual(
          denied ? ["token", "user"] : ["token", "user", "email"],
        );
        expect(receipts[1].query).toEqual({ "user.fields": "profile_image_url" });
        if (!denied) expect(receipts[2].query).toEqual({ "user.fields": "confirmed_email" });
        const sql = (await read(ctx, "sql-state")) as Record<string, any[]>;
        const source = "user" in sql;
        expect(sql[source ? "user" : "users"]).toHaveLength(denied ? 1 : 2);
        expect(sql[source ? "account" : "accounts"]).toHaveLength(denied ? 1 : 2);
        if (!denied) {
          const owner = sql[source ? "user" : "users"]!.find(
            (row) => row.id === session.data!.user.id,
          );
          expect(owner.email).toBe(expectedEmail);
          expect(Boolean(owner[source ? "emailVerified" : "email_verified"])).toBe(
            emailMode === "confirmed",
          );
          const account = sql[source ? "account" : "accounts"]!.find(
            (row) => row[source ? "providerId" : "provider_id"] === "twitter",
          );
          expect(account[source ? "accountId" : "account_id"]).toBe("batch-subject");
          expect(account[source ? "userId" : "user_id"]).toBe(owner.id);
        }
        expect(sql[source ? "verification" : "verifications"]).toHaveLength(0);
        expect(await foreign.client.getSession()).toEqual(foreignSession);
        return {
          session: ctx.snapshot(session),
          callback: status(completed.response, ctx.baseURL),
          wire: receipts.map((row) => ({
            stage: row.stage,
            method: row.method,
            query: row.query,
            body: grantBody(row),
            authorization: (row.declaredHeaders ?? row.headers).authorization,
          })),
          foreign: ctx.snapshot(foreignSession),
        };
      },
      ["POST /sign-in/social", "GET /callback/{}", "GET /get-session"],
    );
  }
}

for (const provider of ["zoom", "roblox"] as const) {
  for (const mode of ["signup-disabled", "implicit-disabled"] as const) {
    for (const requestSignUp of [false, true]) {
      compatScenario(
        `factory signup flags ${provider} ${mode} request=${requestSignUp}`,
        async (ctx) => {
          await control(ctx, provider);
          const completed = await flow(ctx, provider, mode, undefined, requestSignUp);
          const denied =
            (provider === "roblox" && mode === "signup-disabled") ||
            (mode === "implicit-disabled" && !requestSignUp);
          expect(completed.response.status).toBe(302);
          if (denied) expect(status(completed.response, ctx.baseURL).error).toBe("signup_disabled");
          else expect(completed.response.headers.get("location")).toBe("/dashboard");
          const session = await completed.actor.client.getSession();
          if (denied) expect(session.data).toBeNull();
          else expect(session.data?.user.name).toBe("Batch Name");
          const sql = (await read(ctx, "sql-state")) as Record<string, any[]>;
          const source = "user" in sql;
          for (const table of source
            ? ["user", "account", "session"]
            : ["users", "accounts", "sessions"])
            expect(sql[table]).toHaveLength(denied ? 0 : 1);
          expect(sql[source ? "verification" : "verifications"]).toHaveLength(0);
          const receipts: any[] = await read(ctx, "receipts");
          expect(receipts.map((row) => row.stage)).toEqual(["token", "user"]);
          return {
            session: ctx.snapshot(session),
            callback: status(completed.response, ctx.baseURL),
            wire: receipts.map((row) => ({
              stage: row.stage,
              method: row.method,
              query: row.query,
              body: grantBody(row),
            })),
          };
        },
        ["POST /sign-in/social", "GET /callback/{}", "GET /get-session"],
      );
    }
  }
}

for (const stage of ["token", "user", "refresh"] as const) {
  for (const errcode of [40029, 0]) {
    compatScenario(
      `WeChat HTTP-200 errcode ${stage} ${errcode}`,
      async (ctx) => {
        const foreign = ctx.actor("foreign");
        const foreignSignup = await foreign.client.signUp.email({
          email: ctx.uniqueEmail("wechat-error-foreign"),
          password: "password123",
          name: "Unrelated owner",
        });
        expect(foreignSignup.error).toBeNull();
        const foreignState = await ctx.readUserState({ userId: foreignSignup.data!.user.id });
        const grant = {
          access_token: "error-stage-access",
          refresh_token: "error-stage-refresh",
          expires_in: 3600,
          scope: "snsapi_login",
          openid: "transport-owner",
        };
        const failed = errcode !== 0;
        const configure = (code: number) =>
          control(
            ctx,
            "wechat",
            stage === "user"
              ? {
                  profile: {
                    ...inputs.wechat,
                    errcode: code,
                    errmsg: "Application provider error",
                  },
                }
              : {
                  tokenResponse: { ...grant, errcode: code, errmsg: "Application provider error" },
                },
          );
        let callback;
        let token;
        let recovered;
        let session;
        if (stage === "refresh") {
          await control(ctx, "wechat");
          const completed = await flow(ctx, "wechat", "default");
          expect(completed.response.headers.get("location")).toBe("/dashboard");
          const before = (await read(ctx, "sql-state")) as Record<string, any[]>;
          const source = "user" in before;
          const account = before[source ? "account" : "accounts"]!.find(
            (row) => row[source ? "providerId" : "provider_id"] === "wechat",
          );
          await configure(errcode);
          token = await completed.actor.client.refreshToken({ accountId: account.id });
          if (failed) {
            expect(token.error).toMatchObject({
              status: 400,
              code: "FAILED_TO_REFRESH_ACCESS_TOKEN",
            });
            expect(await read(ctx, "sql-state")).toEqual(before);
          } else {
            expect(token.error).toBeNull();
            expect(token.data?.accessToken).toBe(grant.access_token);
          }
          await configure(0);
          recovered = await completed.actor.client.refreshToken({ accountId: account.id });
          expect(recovered.error).toBeNull();
          expect(recovered.data?.accessToken).toBe(grant.access_token);
          expect(recovered.data?.refreshToken).toBe(grant.refresh_token);
          const after = (await read(ctx, "sql-state")) as Record<string, any[]>;
          expect(after[source ? "user" : "users"]).toEqual(before[source ? "user" : "users"]);
          expect(after[source ? "session" : "sessions"]).toEqual(
            before[source ? "session" : "sessions"],
          );
          expect(
            after[source ? "account" : "accounts"]!.find((row) => row.id === account.id),
          ).toMatchObject({
            [source ? "accessToken" : "access_token"]: grant.access_token,
            [source ? "refreshToken" : "refresh_token"]: grant.refresh_token,
          });
          session = await completed.actor.client.getSession();
          expect(session.data?.user.id).toBe(account[source ? "userId" : "user_id"]);
        } else {
          await configure(errcode);
          const completed = await flow(ctx, "wechat", "default");
          callback = status(completed.response, ctx.baseURL);
          expect(callback.status).toBe(302);
          const current = await completed.actor.client.getSession();
          if (failed) {
            expect(callback.error).toBe(
              stage === "token" ? "invalid_code" : "unable_to_get_user_info",
            );
            expect(current.data).toBeNull();
          } else {
            expect(callback.location).toBe("/dashboard");
            expect(current.data).not.toBeNull();
          }
          const sql = (await read(ctx, "sql-state")) as Record<string, any[]>;
          const source = "user" in sql;
          for (const table of source
            ? ["user", "account", "session"]
            : ["users", "accounts", "sessions"])
            expect(sql[table]).toHaveLength(failed ? 1 : 2);
          expect(sql[source ? "verification" : "verifications"]).toHaveLength(0);
          const firstReceipts: any[] = await read(ctx, "receipts");
          expect(firstReceipts.map((row) => row.stage)).toEqual(
            failed && stage === "token" ? ["token"] : ["token", "user"],
          );
          await configure(0);
          const valid = await flow(ctx, "wechat", "default");
          expect(valid.response.headers.get("location")).toBe("/dashboard");
          session = await valid.actor.client.getSession();
          expect(session.data?.user.email).toBe("batch-subject@wechat.placeholder.invalid");
        }
        expect(await ctx.readUserState({ userId: foreignSignup.data!.user.id })).toEqual(
          foreignState,
        );
        const receipts: any[] = await read(ctx, "receipts");
        if (stage === "refresh") {
          expect(receipts.map((row) => row.stage)).toEqual(["token", "user", "refresh", "refresh"]);
          expect(receipts[2].query.refresh_token).toBe("batch-refresh");
          expect(receipts[3].query.refresh_token).toBe(
            failed ? "batch-refresh" : grant.refresh_token,
          );
        }
        return {
          callback,
          token: ctx.snapshot(token),
          recovered: ctx.snapshot(recovered),
          session: ctx.snapshot(session),
          wire: receipts.map((row) => ({
            stage: row.stage,
            method: row.method,
            query: row.query,
            body: row.body,
          })),
        };
      },
      ["GET /callback/{}", "POST /refresh-token", "GET /get-session"],
    );
  }
}

for (const mode of ["default", "pkce-disabled"] as const) {
  compatScenario(
    `Zoom configured PKCE ${mode} retains actual code grant verifier`,
    async (ctx) => {
      await control(ctx, "zoom");
      const completed = await flow(ctx, "zoom", mode);
      expect(completed.url.searchParams.get("code_challenge_method")).toBe(
        mode === "default" ? "S256" : null,
      );
      expect(completed.url.searchParams.has("code_challenge")).toBe(mode === "default");
      expect(completed.response.headers.get("location")).toBe("/dashboard");
      const receipts: any[] = await read(ctx, "receipts");
      expect(receipts.map((row) => row.stage)).toEqual(["token", "user"]);
      const grant = receipts[0].body;
      expect(grant).toMatchObject({
        grant_type: "authorization_code",
        code: "batch-code",
        client_id: "batch-client",
        client_secret: "batch-secret",
      });
      expect(grant.code_verifier).toMatch(/^[A-Za-z0-9_-]{43,128}$/);
      expect(grant.redirect_uri).toBe(
        ctx.baseURL + authProfilePath(selected("zoom", mode)) + "/callback/zoom",
      );
      if (mode === "default")
        expect(createHash("sha256").update(grant.code_verifier!).digest("base64url")).toBe(
          completed.url.searchParams.get("code_challenge")!,
        );
      const session = await completed.actor.client.getSession();
      expect(session.data?.user.email).toBe("batch@example.invalid");
      return {
        start: ctx.snapshot(completed.start),
        callback: status(completed.response, ctx.baseURL),
        session: ctx.snapshot(session),
        grant: grantBody(receipts[0]),
      };
    },
    ["POST /sign-in/social", "GET /callback/{}", "GET /get-session"],
  );
}

for (const mode of ["default", "prompt-none", "prompt-consent", "prompt-empty"] as const) {
  compatScenario(
    `Roblox configured prompt ${mode} preserves actual callback owner`,
    async (ctx) => {
      await control(ctx, "roblox");
      const completed = await flow(ctx, "roblox", mode);
      expect(completed.url.searchParams.get("prompt")).toBe(
        mode === "prompt-none"
          ? "none"
          : mode === "prompt-consent"
            ? "consent"
            : "select_account consent",
      );
      expect(completed.url.searchParams.get("state")).toBeString();
      expect(completed.response.status).toBe(302);
      expect(completed.response.headers.get("location")).toBe("/dashboard");
      const session = await completed.actor.client.getSession();
      expect(session.data?.user.name).toBe("Batch Name");
      const sql = (await read(ctx, "sql-state")) as Record<string, any[]>;
      const source = "user" in sql;
      const account = sql[source ? "account" : "accounts"]![0];
      expect(account[source ? "accountId" : "account_id"]).toBe("batch-subject");
      expect(account[source ? "userId" : "user_id"]).toBe(session.data!.user.id);
      expect(sql[source ? "user" : "users"]).toHaveLength(1);
      expect(sql[source ? "session" : "sessions"]).toHaveLength(1);
      expect(sql[source ? "verification" : "verifications"]).toHaveLength(0);
      const receipts: any[] = await read(ctx, "receipts");
      expect(receipts.map((row) => row.stage)).toEqual(["token", "user"]);
      return {
        start: ctx.snapshot(completed.start),
        callback: status(completed.response, ctx.baseURL),
        session: ctx.snapshot(session),
        wire: receipts.map((row) => ({
          stage: row.stage,
          method: row.method,
          query: row.query,
          body: row.body,
        })),
      };
    },
    ["POST /sign-in/social", "GET /callback/{}", "GET /get-session"],
  );
}

for (const mode of ["default", "language-en"] as const) {
  compatScenario(
    `WeChat authorization language ${mode} keeps separate user-info language`,
    async (ctx) => {
      const foreign = ctx.actor("foreign");
      expect(
        (
          await foreign.client.signUp.email({
            email: ctx.uniqueEmail("wechat-language-foreign"),
            password: "password123",
            name: "Foreign owner",
          })
        ).error,
      ).toBeNull();
      const foreignBefore = await foreign.client.getSession();
      await control(ctx, "wechat");
      const completed = await flow(ctx, "wechat", mode);
      expect(completed.url.searchParams.get("lang")).toBe(mode === "default" ? "cn" : "en");
      expect(completed.url.searchParams.get("scope")).toBe("snsapi_login");
      expect(completed.url.searchParams.get("appid")).toBe("batch-client");
      expect(completed.url.searchParams.get("state")).toBeString();
      expect(completed.url.hash).toBe("#wechat_redirect");
      expect(completed.response.headers.get("location")).toBe("/dashboard");
      const receipts: any[] = await read(ctx, "receipts");
      expect(receipts.map((row) => row.stage)).toEqual(["token", "user"]);
      expect(receipts[1].query).toEqual({
        access_token: "batch-access",
        openid: "batch-subject",
        lang: "zh_CN",
      });
      const session = await completed.actor.client.getSession();
      expect(session.data?.user.email).toBe("batch-subject@wechat.placeholder.invalid");
      const sql = (await read(ctx, "sql-state")) as Record<string, any[]>;
      const source = "user" in sql;
      const account = sql[source ? "account" : "accounts"]!.find(
        (row) => row[source ? "providerId" : "provider_id"] === "wechat",
      );
      expect(account[source ? "accountId" : "account_id"]).toBe("batch-subject");
      expect(account[source ? "userId" : "user_id"]).toBe(session.data!.user.id);
      expect(sql[source ? "session" : "sessions"]).toHaveLength(2);
      expect(await foreign.client.getSession()).toEqual(foreignBefore);
      return {
        start: ctx.snapshot(completed.start),
        session: ctx.snapshot(session),
        callback: status(completed.response, ctx.baseURL),
        wire: receipts.map((row) => ({
          stage: row.stage,
          method: row.method,
          query: row.query,
          body: row.body,
        })),
      };
    },
    ["POST /sign-in/social", "GET /callback/{}", "GET /get-session"],
  );
}
