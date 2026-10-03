import { expect } from "bun:test";

import { SignJWT, jwtVerify } from "jose";

import { authProfilePath, type FixtureProfile } from "../../../support/profiles";
import { compatScenario, type ScenarioContext } from "../../../support/scenario";

compatScenario(
  "paybin mapped invalid subjects reach application mapper before denial",
  async (ctx) => {
    const foreign = ctx.actor("foreign");
    expect(
      (
        await foreign.client.signUp.email({
          email: ctx.uniqueEmail("foreign"),
          password: "Password123!",
          name: "Foreign Owner",
        })
      ).error,
    ).toBeNull();

    const before = await state(ctx);
    const originals: Record<string, unknown>[] = [];
    const callbacks: unknown[] = [];

    for (const variant of ["missing", "null", "empty"] as const) {
      const original: Record<string, unknown> = {
        ...profile(ctx),
        applicationField: "Original profile receipt",
      };

      if (variant === "missing") {
        delete original.sub;
      } else {
        original.sub = variant === "null" ? null : "";
      }

      originals.push(original);
      await control(ctx, { profile: original });
      const flow = await callback(ctx, "social-paybin-mapped");
      const observed = await ctx.rawRequest({ path: "/__test/paybin/mapper-receipts" });
      expect(observed.status).toBe(200);
      expect(observed.body).toEqual(originals);
      expect(flow.response.status).toBe(302);

      const error = new URL(flow.response.headers.get("location")!, ctx.baseURL).searchParams.get(
        "error",
      );
      expect(error).toBe("unable_to_get_user_info");
      expect(await state(ctx)).toEqual(before);
      expect((await flow.actor.client.getSession()).data).toBeNull();
      expect(await receipts(ctx)).toHaveLength(originals.length);

      callbacks.push({ status: flow.response.status, error });
    }

    const mapperReceipts = (await ctx.rawRequest({ path: "/__test/paybin/mapper-receipts" }))
      .body as Record<string, unknown>[];
    return {
      before,
      after: await state(ctx),
      callbacks,
      mapperReceipts: mapperReceipts.map(({ sub: rawSubject, ...fields }) => ({
        ...fields,
        rawSubject,
      })),
    };
  },
  ["GET /callback/{}"],
);

async function state(ctx: ScenarioContext) {
  const r = await ctx.rawRequest({ path: "/__test/social-provider/duplicate-state" });
  expect(r.status).toBe(200);
  const rows = r.body as {
    users: Array<Record<string, unknown>>;
    accounts: Array<Record<string, unknown>>;
    sessions: Array<Record<string, unknown>>;
  };
  return {
    ...rows,
    accounts: rows.accounts.map((row) => {
      if (typeof row.password !== "string") return row;
      // Existing physical-account owner representation: retain the full bytes
      // and the salt/key relation without requiring independent random salts to match.
      expect(row.password).toMatch(/^[a-f0-9]{32}:[a-f0-9]{128}$/);
      const [salt, derivedKey] = row.password.split(":");
      return {
        ...row,
        password: {
          token: row.password,
          salt: { token: salt, length: 32 },
          derivedKey: { token: derivedKey, length: 128 },
          encoding: "hex-lower",
        },
      };
    }),
  };
}

const key = new TextEncoder().encode("fixture-paybin-independent-hmac-key-32");
async function control(ctx: ScenarioContext, value: Record<string, unknown>) {
  const idToken = value.profile
    ? await new SignJWT(value.profile as Record<string, unknown>)
        .setProtectedHeader({ alg: "HS256" })
        .sign(key)
    : undefined;
  if (idToken) {
    expect((await jwtVerify(idToken, key, { algorithms: ["HS256"] })).payload).toEqual(
      value.profile as Record<string, unknown>,
    );
  }
  const json = {
    ...value,
    ...(idToken ? { idToken } : {}),
    ...(value.tokenResponse && idToken
      ? { tokenResponse: { ...(value.tokenResponse as object), id_token: idToken } }
      : {}),
  };
  expect(
    (await ctx.rawRequest({ path: "/__test/paybin/control", method: "POST", json })).status,
  ).toBe(200);
  return idToken;
}

async function receipts(ctx: ScenarioContext) {
  const r = await ctx.rawRequest({ path: "/__test/paybin/receipts" });
  expect(r.status).toBe(200);
  return (
    r.body as Array<{
      path: string;
      authorization: string | null;
      body: Record<string, string> | null;
    }>
  ).map((row) => ({
    ...row,
    body: (row.body?.code_verifier
      ? {
          ...row.body,
          code_verifier: { token: row.body.code_verifier, length: row.body.code_verifier.length },
        }
      : row.body) as Record<string, unknown> | null,
  }));
}

function profile(ctx: ScenarioContext) {
  return {
    sub: ctx.uniqueToken("paybin-subject"),
    name: "Paybin Name",
    email: ctx.uniqueEmail("paybin"),
    email_verified: false,
    country: "Synthetic Country",
    two_factor_authentication_enabled: true,
  };
}

async function callback(
  ctx: ScenarioContext,
  mode: FixtureProfile = "social-paybin-default",
  requestSignUp = false,
) {
  const actor = ctx.actor("paybin", mode);
  const start = await actor.client.signIn.social({
    provider: "paybin",
    callbackURL: "/dashboard",
    requestSignUp,
  });
  expect(start.error).toBeNull();

  const url = new URL(start.data!.url!);
  const path =
    authProfilePath(mode) +
    `/callback/paybin?code=fixture-code&state=${encodeURIComponent(url.searchParams.get("state")!)}`;
  const response = await actor.fetch(ctx.baseURL + path, { redirect: "manual" });
  return { actor, start, url, path, response };
}

for (const mode of [
  "default",
  "configured",
  "disabled-scope",
  "disabled-configured",
  "configured-endpoint",
  "issuer",
  "empty-issuer",
  "prompt",
] as const) {
  compatScenario(
    `paybin published ${mode} authorization preserves scope order and uses issuer and required PKCE`,
    async (ctx) => {
      const result = await ctx.actor("paybin", `social-paybin-${mode}`).client.signIn.social({
        provider: "paybin",
        callbackURL: "/dashboard",
        scopes: ["requested-scope", "shared-scope", "requested-scope"],
        loginHint: "login@example.invalid",
        additionalParams: {
          owner: "workspace",
          prompt: "caller-prompt",
          custom: "caller-value",
        },
      });
      expect(result.error).toBeNull();

      const url = new URL(result.data!.url!);
      expect(url.origin).toBe(
        mode === "configured-endpoint"
          ? "https://configured.example.invalid"
          : mode === "issuer"
            ? "https://issuer.example.invalid"
            : "https://idp.paybin.io",
      );
      expect(url.pathname).toBe(
        mode === "configured-endpoint"
          ? "/authorize"
          : mode === "issuer"
            ? "/root//oauth2/authorize"
            : "/oauth2/authorize",
      );
      expect(url.searchParams.get("response_type")).toBe("code");
      expect(url.searchParams.get("state")).not.toBe("forged");
      expect(url.searchParams.get("client_id")).toBe("fixture-social-client");
      expect(url.searchParams.get("nonce")).toBeNull();
      expect(url.searchParams.get("response_mode")).toBeNull();
      expect(url.searchParams.get("login_hint")).toBe("login@example.invalid");
      expect(url.searchParams.get("owner")).toBe("workspace");
      expect(url.searchParams.get("custom")).toBe("caller-value");
      expect(url.searchParams.get("prompt")).toBe("caller-prompt");
      expect(url.searchParams.get("code_challenge_method")).toBe("S256");
      expect(url.searchParams.get("code_challenge")).toHaveLength(43);
      expect(url.searchParams.get("scope")).toBe(
        mode === "configured" || mode === "disabled-configured"
          ? (mode === "configured" ? "openid email profile " : "") +
              "configured-scope shared-scope configured-scope requested-scope shared-scope requested-scope"
          : (mode === "disabled-scope" ? "" : "openid email profile ") +
              "requested-scope shared-scope requested-scope",
      );
      expect(url.searchParams.get("redirect_uri")).toBe(
        mode === "configured-endpoint"
          ? "https://configured.example.invalid/callback"
          : ctx.baseURL + authProfilePath(`social-paybin-${mode}`) + "/callback/paybin",
      );

      return {
        result: ctx.snapshot(result),
        persisted: await state(ctx),
        receipts: await receipts(ctx),
      };
    },
  );
}

compatScenario("paybin disabled defaults with no requested scopes omits scope", async (ctx) => {
  const result = await ctx
    .actor("paybin", "social-paybin-disabled-scope")
    .client.signIn.social({ provider: "paybin", loginHint: "" });
  expect(result.error).toBeNull();
  expect(new URL(result.data!.url!).searchParams.get("scope")).toBeNull();
  expect(new URL(result.data!.url!).searchParams.get("login_hint")).toBeNull();

  return { result: ctx.snapshot(result) };
});

for (const mode of ["default", "encoded", "configured-endpoint", "client-key", "issuer"] as const) {
  compatScenario(
    `paybin ${mode} credentials reach real token exchange refresh and owned persistence`,
    async (ctx) => {
      const foreign = ctx.actor("foreign");
      expect(
        (
          await foreign.client.signUp.email({
            email: ctx.uniqueEmail("foreign"),
            password: "Password123!",
            name: "Foreign Owner",
          })
        ).error,
      ).toBeNull();

      const before = await state(ctx);
      const data = profile(ctx);
      const idToken = await control(ctx, { profile: data });
      const fixtureMode = `social-paybin-${mode}` as const;
      const flow = await callback(ctx, fixtureMode);
      expect(flow.response.status).toBe(302);
      expect(flow.response.headers.get("location")).toBe("/dashboard");

      const session = await flow.actor.client.getSession();
      expect(session.data?.user).toBeTruthy();

      const after = await state(ctx);

      for (const table of ["users", "accounts", "sessions"] as const) {
        expect(after[table]).toHaveLength(before[table].length + 1);
        expect(after[table].find((row) => row.id === before[table][0]!.id)).toEqual(
          before[table][0],
        );
      }

      const owner = after.users.find((row) => row.id !== before.users[0]!.id)!;
      expect(owner).toMatchObject({
        name: "Paybin Name",
        email: data.email,
        emailVerified: false,
        image: null,
      });

      const account = after.accounts.find((row) => row.userId === owner.id)!;
      expect(account).toMatchObject({
        providerId: "paybin",
        accountId: data.sub,
        accessToken: "fixture-paybin-access",
        refreshToken: "fixture-paybin-refresh",
        idToken,
        scope: "user-details.read",
      });

      const raw = await ctx.rawRequest({ path: "/__test/paybin/receipts" });
      const rows = raw.body as Array<{
        path: string;
        authorization: string | null;
        body: Record<string, string>;
      }>;
      const exchange = rows[0]!.body;
      expect(exchange).toEqual({
        grant_type: "authorization_code",
        code: "fixture-code",
        code_verifier: expect.any(String),
        client_id: mode === "encoded" ? "client :+!*'()" : "fixture-social-client",
        client_secret: mode === "encoded" ? "secret :+!*'()" : "fixture-social-secret",
        ...(mode === "client-key" ? { client_key: "fixture-client-key" } : {}),
        redirect_uri:
          mode === "configured-endpoint"
            ? "https://configured.example.invalid/callback"
            : ctx.baseURL + authProfilePath(fixtureMode) + "/callback/paybin",
      });

      expect(rows).toHaveLength(1);
      expect(rows[0]!.path).toBe(mode === "issuer" ? "/root//oauth2/token" : "/oauth2/token");
      expect(rows[0]!.authorization).toBeNull();
      const verifier = exchange.code_verifier!;
      const challenge = Buffer.from(
        await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier)),
      ).toString("base64url");
      expect(challenge).toBe(flow.url.searchParams.get("code_challenge")!);
      expect(
        (await jwtVerify(String(account.idToken), key, { algorithms: ["HS256"] })).payload,
      ).toEqual(data);
      const replay = await flow.actor.fetch(ctx.baseURL + flow.path, { redirect: "manual" });
      expect(replay.status).toBe(302);
      expect(await state(ctx)).toEqual(after);
      expect(await receipts(ctx)).toHaveLength(1);

      const denied = await foreign.client.refreshToken({ accountId: String(account.id) });
      expect(denied.error).toBeTruthy();
      expect(await state(ctx)).toEqual(after);
      expect(await receipts(ctx)).toHaveLength(1);

      await control(ctx, {
        tokenResponse: {
          access_token: "rotated-paybin-access",
          refresh_token: "rotated-paybin-refresh",
          token_type: "Bearer",
          expires_in: 1800,
          scope: "user-details.read updated",
        },
      });
      const refreshed = await flow.actor.client.refreshToken({ accountId: String(account.id) });
      expect(refreshed.error).toBeNull();

      const rotated = await state(ctx);
      expect(rotated.accounts.find((row) => row.id === account.id)).toMatchObject({
        accessToken: "rotated-paybin-access",
        refreshToken: "rotated-paybin-refresh",
        scope: "user-details.read",
      });
      expect(rotated.users).toEqual(after.users);
      expect(rotated.sessions).toEqual(after.sessions);
      expect(rotated.accounts.find((row) => row.id === before.accounts[0]!.id)).toEqual(
        before.accounts[0],
      );

      const refreshRequests = await receipts(ctx);
      expect(refreshRequests[1]).toMatchObject({
        path: mode === "issuer" ? "/root//oauth2/token" : "/oauth2/token",
        authorization: null,
        body: {
          grant_type: "refresh_token",
          refresh_token: "fixture-paybin-refresh",
          client_id: mode === "encoded" ? "client :+!*'()" : "fixture-social-client",
          client_secret: mode === "encoded" ? "secret :+!*'()" : "fixture-social-secret",
        },
      });
      expect((await flow.actor.client.signOut()).error).toBeNull();

      const logout = await state(ctx);
      expect(logout.users).toEqual(rotated.users);
      expect(logout.accounts).toEqual(rotated.accounts);
      expect(logout.sessions).toEqual(before.sessions);
      expect(await receipts(ctx)).toEqual(refreshRequests);

      return {
        start: ctx.snapshot(flow.start),
        callback: { status: flow.response.status, location: flow.response.headers.get("location") },
        session: ctx.snapshot(session),
        before,
        after,
        replay: { status: replay.status, location: replay.headers.get("location") },
        denied: ctx.snapshot(denied),
        refreshed: ctx.snapshot(refreshed),
        rotated,
        logout,
        receipts: refreshRequests,
      };
    },
    ["POST /sign-in/social", "GET /callback/{}", "POST /refresh-token", "POST /sign-out"],
  );
}

for (const variant of [
  "missing-name",
  "null-name",
  "empty-name",
  "zero-name",
  "numeric-name",
  "numeric-subject",
  "username-fallback",
  "numeric-username",
  "verified",
  "missing-verified",
  "null-verified",
  "zero-verified",
  "numeric-verified",
  "missing-image",
  "null-image",
  "empty-image",
  "numeric-image",
  "mapped",
] as const) {
  compatScenario(
    `paybin ${variant} profile preserves raw owner and account info`,
    async (ctx) => {
      const data: Record<string, unknown> = {
        ...profile(ctx),
        picture: "https://images.example.invalid/paybin.png",
      };
      if (variant === "missing-name") delete data.name;
      if (variant === "null-name") data.name = null;
      if (variant === "empty-name") data.name = "";
      if (variant === "zero-name") data.name = 0;
      if (variant === "numeric-name") data.name = 42;
      if (variant === "numeric-subject") data.sub = 42;
      if (variant === "username-fallback") {
        data.name = "";
        data.preferred_username = "Username";
      }
      if (variant === "numeric-username") {
        data.name = null;
        data.preferred_username = 42;
      }
      if (variant === "verified") data.email_verified = true;
      if (variant === "missing-verified") delete data.email_verified;
      if (variant === "null-verified") data.email_verified = null;
      if (variant === "zero-verified") data.email_verified = 0;
      if (variant === "numeric-verified") data.email_verified = 42;
      if (variant === "missing-image") delete data.picture;
      if (variant === "null-image") data.picture = null;
      if (variant === "empty-image") data.picture = "";
      if (variant === "numeric-image") data.picture = 42;
      await control(ctx, { profile: data });
      const flow = await callback(
        ctx,
        variant === "mapped" ? "social-paybin-mapped" : "social-paybin-default",
      );
      expect(flow.response.headers.get("location")).toBe("/dashboard");
      const persisted = await state(ctx);
      expect(persisted.users).toHaveLength(1);
      expect(persisted.accounts).toHaveLength(1);
      expect(persisted.sessions).toHaveLength(1);
      expect(persisted.accounts[0]!.accountId).toBe(String(data.sub));
      const mapped = variant === "mapped";
      const name = ["missing-name", "null-name", "empty-name", "zero-name"].includes(variant)
        ? ""
        : variant === "username-fallback"
          ? "Username"
          : variant === "numeric-name" || variant === "numeric-username"
            ? "42"
            : "Paybin Name";
      expect(persisted.users[0]).toMatchObject({
        name: mapped ? "Mapped Paybin Name" : name,
        email: mapped ? "mapped-paybin@example.invalid" : data.email,
        emailVerified: mapped || variant === "verified",
        image: mapped
          ? "https://images.example.invalid/mapped-paybin.png"
          : data.picture == null
            ? null
            : String(data.picture),
      });
      const info = await flow.actor.client.$fetch("/account-info", {
        query: { accountId: String(persisted.accounts[0]!.id) },
      });
      expect(info.error).toBeNull();
      expect(info.data).toEqual({
        user: mapped
          ? {
              id: "cannot-replace-account-subject",
              name: "Mapped Paybin Name",
              email: "mapped-paybin@example.invalid",
              emailVerified: true,
              image: "https://images.example.invalid/mapped-paybin.png",
            }
          : {
              name: data.name || data.preferred_username || "",
              email: data.email,
              emailVerified: data.email_verified || false,
              ...(Object.hasOwn(data, "picture") ? { image: data.picture } : {}),
            },
        data,
        account: {
          id: persisted.accounts[0]!.id,
          providerId: "paybin",
          accountId: String(data.sub),
        },
      });
      expect(await state(ctx)).toEqual(persisted);
      expect(await receipts(ctx)).toHaveLength(1);
      return {
        start: ctx.snapshot(flow.start),
        persisted,
        info: ctx.snapshot(info),
        receipts: await receipts(ctx),
      };
    },
    ["POST /sign-in/social", "GET /callback/{}", "GET /account-info"],
  );
}

for (const variant of [
  "missing-subject",
  "null-subject",
  "empty-subject",
  "missing-email",
  "null-email",
  "empty-email",
  "missing-idtoken",
  "token-status",
  "token-redirect",
  "implicit-disabled",
  "signup-disabled",
] as const) {
  compatScenario(
    `paybin rejects ${variant} without foreign writes`,
    async (ctx) => {
      const foreign = ctx.actor("foreign");
      expect(
        (
          await foreign.client.signUp.email({
            email: ctx.uniqueEmail("foreign"),
            password: "Password123!",
            name: "Foreign Owner",
          })
        ).error,
      ).toBeNull();

      const before = await state(ctx);
      const data: Record<string, unknown> = profile(ctx);

      if (variant === "missing-subject") {
        delete data.sub;
      }

      if (variant === "null-subject") {
        data.sub = null;
      }

      if (variant === "empty-subject") {
        data.sub = "";
      }

      if (variant === "missing-email") {
        delete data.email;
      }

      if (variant === "null-email") {
        data.email = null;
      }

      if (variant === "empty-email") {
        data.email = "";
      }

      await control(ctx, {
        profile: data,
        ...(variant === "missing-idtoken"
          ? { tokenResponse: { access_token: "fixture-paybin-access" }, profile: undefined }
          : {}),
        ...(variant === "token-status" ? { tokenStatus: 400 } : {}),
        ...(variant === "token-redirect" ? { tokenStatus: 307, tokenRedirect: true } : {}),
      });
      const flow = await callback(
        ctx,
        variant === "implicit-disabled"
          ? "social-paybin-implicit-disabled"
          : variant === "signup-disabled"
            ? "social-paybin-signup-disabled"
            : "social-paybin-default",
      );
      expect(flow.response.status).toBe(302);
      expect(
        new URL(flow.response.headers.get("location")!, ctx.baseURL).searchParams.get("error"),
      ).toBe(
        variant.endsWith("email")
          ? "email_not_found"
          : variant.startsWith("token-")
            ? "invalid_code"
            : variant.endsWith("disabled")
              ? "signup_disabled"
              : "unable_to_get_user_info",
      );

      const after = await state(ctx);
      expect(after).toEqual(before);

      if (variant === "token-redirect") {
        expect(await receipts(ctx)).toHaveLength(1);
      }

      expect((await flow.actor.client.getSession()).data).toBeNull();

      return {
        start: ctx.snapshot(flow.start),
        callback: { status: flow.response.status, location: flow.response.headers.get("location") },
        before,
        after,
        receipts: await receipts(ctx),
      };
    },
    ["GET /callback/{}"],
  );
}

compatScenario(
  "paybin explicit signup admits disabled implicit signup",
  async (ctx) => {
    await control(ctx, { profile: profile(ctx) });
    const flow = await callback(ctx, "social-paybin-implicit-disabled", true);
    expect(flow.response.headers.get("location")).toBe("/dashboard");

    const persisted = await state(ctx);
    expect(persisted.users).toHaveLength(1);
    expect(persisted.accounts).toHaveLength(1);
    expect(persisted.sessions).toHaveLength(1);

    return {
      start: ctx.snapshot(flow.start),
      callback: { status: flow.response.status, location: flow.response.headers.get("location") },
      persisted,
      receipts: await receipts(ctx),
    };
  },
  ["POST /sign-in/social", "GET /callback/{}"],
);

compatScenario(
  "paybin unverified email gate stores account without issuing session",
  async (ctx) => {
    await control(ctx, { profile: profile(ctx) });
    const flow = await callback(ctx, "social-paybin-required");
    expect(
      new URL(flow.response.headers.get("location")!, ctx.baseURL).searchParams.get("error"),
    ).toBe("email_not_verified");

    const persisted = await state(ctx);
    expect(persisted.users).toHaveLength(1);
    expect(persisted.users[0]!.emailVerified).toBeFalse();
    expect(persisted.accounts).toHaveLength(1);
    expect(persisted.sessions).toHaveLength(0);
    expect((await flow.actor.client.getSession()).data).toBeNull();

    return {
      callback: { status: flow.response.status, location: flow.response.headers.get("location") },
      persisted,
      receipts: await receipts(ctx),
    };
  },
  ["POST /sign-in/social", "GET /callback/{}"],
);

for (const expiry of ["absent", "zero", "fractional"] as const) {
  compatScenario(
    `paybin ${expiry} token expiry has no fabricated default`,
    async (ctx) => {
      const started = Date.now();
      const tokenResponse = {
        access_token: "fixture-paybin-access",
        refresh_token: "fixture-paybin-refresh",
        token_type: "Bearer",
        scope: "user-details.read",
        ...(expiry === "absent" ? {} : { expires_in: expiry === "zero" ? 0 : 120.5 }),
      };
      await control(ctx, { profile: profile(ctx), tokenResponse });
      const flow = await callback(ctx);
      expect(flow.response.headers.get("location")).toBe("/dashboard");

      const persisted = await state(ctx);
      const expires = persisted.accounts[0]!.accessTokenExpiresAt;

      if (expiry === "fractional") {
        expect(typeof expires).toBe("string");
        expect(Date.parse(String(expires))).toBeGreaterThanOrEqual(started + 120500);
        expect(Date.parse(String(expires))).toBeLessThanOrEqual(Date.now() + 120500);
      } else {
        expect(expires).toBeNull();
      }

      return { persisted, receipts: await receipts(ctx) };
    },
    ["POST /sign-in/social", "GET /callback/{}"],
  );
}

compatScenario(
  "paybin unsupported ID token and invalid provider state produce no requests",
  async (ctx) => {
    const before = await state(ctx);
    const actor = ctx.actor("paybin", "social-paybin-default");
    const direct = await actor.client.signIn.social({
      provider: "paybin",
      idToken: { token: "untrusted.not-signed.token" },
    });
    expect(direct.error?.code).toBe("ID_TOKEN_NOT_SUPPORTED");

    const wrong = await actor.client.signIn.social({ provider: "google" });
    expect(wrong.error?.code).toBe("PROVIDER_NOT_FOUND");

    const response = await actor.fetch(
      ctx.baseURL +
        authProfilePath("social-paybin-default") +
        "/callback/paybin?code=fixture-code&state=unissued",
      { redirect: "manual" },
    );
    expect(response.status).toBe(302);
    expect(new URL(response.headers.get("location")!, ctx.baseURL).searchParams.get("error")).toBe(
      "state_mismatch",
    );
    expect(await state(ctx)).toEqual(before);
    expect(await receipts(ctx)).toEqual([]);

    return {
      direct: ctx.snapshot(direct),
      wrong: ctx.snapshot(wrong),
      persisted: await state(ctx),
      receipts: await receipts(ctx),
    };
  },
  ["POST /sign-in/social", "GET /callback/{}"],
);

for (const mode of ["public", "empty-clients"] as const) {
  compatScenario(
    `paybin rejects ${mode} authorization before issuing state or contacting issuer`,
    async (ctx) => {
      const before = await state(ctx);
      const result = await ctx
        .actor("paybin", `social-paybin-${mode}`)
        .client.signIn.social({ provider: "paybin" });
      expect(result.error).toBeTruthy();
      expect(await state(ctx)).toEqual(before);
      expect(await receipts(ctx)).toEqual([]);
      return {
        result: ctx.snapshot(result),
        before,
        after: await state(ctx),
        receipts: await receipts(ctx),
      };
    },
  );
}

compatScenario(
  "paybin grant profile decodes foreign issuer audience nonce and signature without claiming verification",
  async (ctx) => {
    const data = {
      ...profile(ctx),
      iss: "https://foreign.example.invalid",
      aud: "foreign-client",
      nonce: "foreign-nonce",
      exp: 1,
    };
    // A real signed token reaches the trusted grant transport; these claims are
    // intentionally not verified by the published Paybin getUserInfo factory.
    const idToken = await new SignJWT(data)
      .setProtectedHeader({ alg: "HS256" })
      .sign(new TextEncoder().encode("different-independent-signing-key-32"));
    await control(ctx, {
      tokenResponse: { access_token: "fixture-paybin-access", id_token: idToken },
    });
    const flow = await callback(ctx);
    expect(flow.response.headers.get("location")).toBe("/dashboard");
    const persisted = await state(ctx);
    expect(persisted.accounts[0]!.accountId).toBe(data.sub);
    expect(persisted.accounts[0]!.idToken).toBe(idToken);
    expect(persisted.sessions).toHaveLength(1);
    expect(await receipts(ctx)).toHaveLength(1);
    return { persisted, receipts: await receipts(ctx) };
  },
  ["POST /sign-in/social", "GET /callback/{}"],
);

compatScenario(
  "paybin configured prompt reaches authorization without caller replacement",
  async (ctx) => {
    const result = await ctx
      .actor("paybin", "social-paybin-prompt")
      .client.signIn.social({ provider: "paybin" });
    expect(result.error).toBeNull();
    expect(new URL(result.data!.url!).searchParams.get("prompt")).toBe("consent");
    return {
      result: ctx.snapshot(result),
      persisted: await state(ctx),
      receipts: await receipts(ctx),
    };
  },
);

compatScenario(
  "paybin reserved authorization parameters reject before issuer requests",
  async (ctx) => {
    const before = await state(ctx);
    const result = await ctx.actor("paybin", "social-paybin-default").client.signIn.social({
      provider: "paybin",
      additionalParams: {
        state: "forged",
        scope: "forged",
        client_id: "forged",
        redirect_uri: "https://foreign.example.invalid",
        response_type: "token",
        code_challenge: "forged",
        code_challenge_method: "plain",
        nonce: "forged",
      },
    });
    expect(result.error?.code).toBe("VALIDATION_ERROR");
    expect(await state(ctx)).toEqual(before);
    expect(await receipts(ctx)).toEqual([]);
    return {
      result: ctx.snapshot(result),
      before,
      after: await state(ctx),
      receipts: await receipts(ctx),
    };
  },
);

compatScenario(
  "paybin issued state without bound cookie cannot admit or exchange tokens",
  async (ctx) => {
    await control(ctx, { profile: profile(ctx) });
    const before = await state(ctx);
    const legitimate = ctx.actor("legitimate", "social-paybin-default");
    const start = await legitimate.client.signIn.social({
      provider: "paybin",
      callbackURL: "/dashboard",
    });
    expect(start.error).toBeNull();
    const issued = new URL(start.data!.url!).searchParams.get("state")!;
    const attacker = ctx.actor("attacker", "social-paybin-default");
    const response = await attacker.fetch(
      ctx.baseURL +
        authProfilePath("social-paybin-default") +
        `/callback/paybin?code=fixture-code&state=${encodeURIComponent(issued)}`,
      { redirect: "manual" },
    );
    expect(response.status).toBe(302);
    expect(new URL(response.headers.get("location")!, ctx.baseURL).searchParams.get("error")).toBe(
      "state_mismatch",
    );
    expect(await state(ctx)).toEqual(before);
    expect(await receipts(ctx)).toEqual([]);
    return {
      start: ctx.snapshot(start),
      callback: { status: response.status, location: response.headers.get("location") },
      before,
      after: await state(ctx),
      receipts: await receipts(ctx),
    };
  },
  ["GET /callback/{}"],
);
