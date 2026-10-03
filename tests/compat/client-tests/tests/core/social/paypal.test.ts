import { expect } from "bun:test";
import { createHash } from "node:crypto";

import { authProfilePath, type FixtureProfile } from "../../../support/profiles";
import { compatScenario as ownerScenario, type ScenarioContext } from "../../../support/scenario";

// Retain complete observations on request without changing the shared comparator.
function compatScenario(...args: Parameters<typeof ownerScenario>) {
  const [name, run, ...options] = args;
  return ownerScenario(
    name,
    async (ctx) => {
      const result = await run(ctx);
      if (process.env.PAYPAL_EVIDENCE_DIR) {
        await Bun.write(
          `${process.env.PAYPAL_EVIDENCE_DIR}/${Bun.hash(ctx.baseURL + name)}.json`,
          JSON.stringify({ name, baseURL: ctx.baseURL, result }, null, 2),
        );
      }
      return result;
    },
    ...options,
  );
}

compatScenario(
  "paypal mapped invalid subjects reach application mapper before denial",
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
        delete original.user_id;
      } else {
        original.user_id = variant === "null" ? null : "";
      }

      originals.push(original);
      await control(ctx, { profile: original });
      const flow = await callback(ctx, "social-paypal-mapped");
      const observed = await ctx.rawRequest({ path: "/__test/paypal/mapper-receipts" });
      expect(observed.status).toBe(200);
      expect(observed.body).toEqual(originals);
      expect(flow.response.status).toBe(302);

      const error = new URL(flow.response.headers.get("location")!, ctx.baseURL).searchParams.get(
        "error",
      );
      expect(error).toBe("unable_to_get_user_info");
      expect(await state(ctx)).toEqual(before);
      expect((await flow.actor.client.getSession()).data).toBeNull();
      expect(await receipts(ctx)).toHaveLength(originals.length * 2);

      callbacks.push({ status: flow.response.status, error });
    }

    const mapperReceipts = (await ctx.rawRequest({ path: "/__test/paypal/mapper-receipts" }))
      .body as Record<string, unknown>[];
    return {
      before,
      after: await state(ctx),
      callbacks,
      mapperReceipts: mapperReceipts.map(({ user_id: rawSubject, ...fields }) => ({
        ...fields,
        rawSubject,
      })),
    };
  },
  ["GET /callback/{}"],
);

async function state(ctx: ScenarioContext) {
  const r = await ctx.rawRequest({ path: "/__test/social-provider/state" });
  expect(r.status).toBe(200);
  return r.body as {
    users: Array<Record<string, unknown>>;
    accounts: Array<Record<string, unknown>>;
    sessions: Array<Record<string, unknown>>;
  };
}

async function control(ctx: ScenarioContext, value: Record<string, unknown>) {
  expect(
    (await ctx.rawRequest({ path: "/__test/paypal/control", method: "POST", json: value })).status,
  ).toBe(200);
}

async function receipts(ctx: ScenarioContext) {
  const r = await ctx.rawRequest({ path: "/__test/paypal/receipts" });
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
    user_id: ctx.uniqueToken("paypal-subject"),
    name: "PayPal Name",
    email: ctx.uniqueEmail("paypal"),
    email_verified: true,
    country: "Synthetic Country",
    two_factor_authentication_enabled: true,
  };
}

async function callback(
  ctx: ScenarioContext,
  mode: FixtureProfile = "social-paypal-default",
  requestSignUp = false,
  extraQuery = "",
) {
  const actor = ctx.actor("paypal", mode);
  const start = await actor.client.signIn.social({
    provider: "paypal",
    callbackURL: "/dashboard",
    requestSignUp,
  });
  expect(start.error).toBeNull();

  const url = new URL(start.data!.url!);
  const path =
    authProfilePath(mode) +
    `/callback/paypal?code=fixture-code&state=${encodeURIComponent(url.searchParams.get("state")!)}${extraQuery}`;
  const response = await actor.fetch(ctx.baseURL + path, { redirect: "manual" });
  return { actor, start, url, path, response };
}

for (const mode of [
  "default",
  "configured",
  "disabled-scope",
  "disabled-configured",
  "configured-endpoint",
  "live",
  "shipping",
  "prompt",
  "empty-prompt",
] as const) {
  compatScenario(
    `paypal published ${mode} authorization omits all scopes and retains PKCE`,
    async (ctx) => {
      const result = await ctx.actor("paypal", `social-paypal-${mode}`).client.signIn.social({
        provider: "paypal",
        callbackURL: "/dashboard",
        scopes: ["requested-scope", "shared-scope", "requested-scope"],
        loginHint: "login@example.invalid",
        additionalParams: { owner: "workspace", prompt: "caller-prompt", custom: "caller-value" },
      });
      expect(result.error).toBeNull();

      const url = new URL(result.data!.url!);
      expect(url.origin).toBe(
        mode === "configured-endpoint"
          ? "https://configured.example.invalid"
          : mode === "live"
            ? "https://www.paypal.com"
            : "https://www.sandbox.paypal.com",
      );
      expect(url.pathname).toBe(
        mode === "configured-endpoint" ? "/authorize" : "/signin/authorize",
      );
      expect(url.searchParams.get("response_type")).toBe("code");
      expect(url.searchParams.get("response_mode")).toBeNull();
      expect(url.searchParams.get("login_hint")).toBeNull();
      expect(url.searchParams.get("owner")).toBe("workspace");
      expect(url.searchParams.get("custom")).toBe("caller-value");
      expect(url.searchParams.get("prompt")).toBe("caller-prompt");
      expect(url.searchParams.get("code_challenge_method")).toBe("S256");
      expect(url.searchParams.get("code_challenge")).toMatch(/^[A-Za-z0-9_-]{43}$/);
      expect(url.searchParams.get("scope")).toBeNull();
      expect(url.searchParams.get("nonce")).toBeNull();
      expect(url.searchParams.get("redirect_uri")).toBe(
        mode === "configured-endpoint"
          ? "https://configured.example.invalid/callback"
          : ctx.baseURL + authProfilePath(`social-paypal-${mode}`) + "/callback/paypal",
      );

      return {
        result: ctx.snapshot(result),
        persisted: await state(ctx),
        receipts: await receipts(ctx),
      };
    },
  );
}

compatScenario("paypal disabled defaults with no requested scopes omits scope", async (ctx) => {
  const result = await ctx
    .actor("paypal", "social-paypal-disabled-scope")
    .client.signIn.social({ provider: "paypal", loginHint: "" });
  expect(result.error).toBeNull();
  expect(new URL(result.data!.url!).searchParams.get("scope")).toBeNull();
  expect(new URL(result.data!.url!).searchParams.get("login_hint")).toBeNull();

  return { result: ctx.snapshot(result) };
});

for (const mode of ["default", "live", "encoded", "configured-endpoint", "client-key"] as const) {
  compatScenario(
    `paypal ${mode} credentials reach real token exchange refresh and owned persistence`,
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
      await control(ctx, { profile: data });
      const fixtureMode = `social-paypal-${mode}` as const;
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
        name: "PayPal Name",
        email: data.email,
        emailVerified: true,
        image: null,
      });

      const account = after.accounts.find((row) => row.userId === owner.id)!;
      expect(account).toMatchObject({
        providerId: "paypal",
        accountId: data.user_id,
        accessToken: "fixture-paypal-access",
        refreshToken: "fixture-paypal-refresh",
        idToken: null,
        scope: "user-details.read",
      });

      const raw = await ctx.rawRequest({ path: "/__test/paypal/receipts" });
      const rows = raw.body as Array<{
        path: string;
        authorization: string | null;
        body: Record<string, string>;
      }>;
      const exchange = rows[0]!.body;
      expect(exchange).toEqual({
        grant_type: "authorization_code",
        code: "fixture-code",
        code_verifier: exchange.code_verifier!,
        redirect_uri:
          mode === "configured-endpoint"
            ? "https://configured.example.invalid/callback"
            : ctx.baseURL + authProfilePath(fixtureMode) + "/callback/paypal",
      });

      expect(exchange.code_verifier).toMatch(/^[A-Za-z0-9_-]{128}$/);
      expect(createHash("sha256").update(exchange.code_verifier!).digest("base64url")).toBe(
        flow.url.searchParams.get("code_challenge")!,
      );
      const authorization =
        mode === "encoded"
          ? "Basic Y2xpZW50KyUzQSUyQiUyMSolMjclMjglMjk6c2VjcmV0KyUzQSUyQiUyMSolMjclMjglMjk="
          : "Basic Zml4dHVyZS1zb2NpYWwtY2xpZW50OmZpeHR1cmUtc29jaWFsLXNlY3JldA==";
      expect(rows[0]!.authorization).toBe(authorization);
      expect(rows[1]).toMatchObject({
        path: "/user",
        authorization: "Bearer fixture-paypal-access",
        accept: "application/json",
        query: { schema: "paypalv1.1" },
        body: null,
      });

      const replay = await flow.actor.fetch(ctx.baseURL + flow.path, { redirect: "manual" });
      expect(replay.status).toBe(302);
      expect(await state(ctx)).toEqual(after);
      expect(await receipts(ctx)).toHaveLength(2);

      const denied = await foreign.client.refreshToken({ accountId: String(account.id) });
      expect(denied.error).toBeTruthy();
      expect(await state(ctx)).toEqual(after);
      expect(await receipts(ctx)).toHaveLength(2);

      await control(ctx, {
        tokenResponse: {
          access_token: "rotated-paypal-access",
          refresh_token: "rotated-paypal-refresh",
          token_type: "Bearer",
          expires_in: 1800,
          scope: "user-details.read updated",
        },
      });
      const refreshed = await flow.actor.client.refreshToken({ accountId: String(account.id) });
      expect(refreshed.error).toBeNull();

      const rotated = await state(ctx);
      expect(rotated.accounts.find((row) => row.id === account.id)).toMatchObject({
        accessToken: "rotated-paypal-access",
        refreshToken: "rotated-paypal-refresh",
        scope: "user-details.read",
      });
      expect(rotated.users).toEqual(after.users);
      expect(rotated.sessions).toEqual(after.sessions);
      expect(rotated.accounts.find((row) => row.id === before.accounts[0]!.id)).toEqual(
        before.accounts[0],
      );

      const refreshRequests = await receipts(ctx);
      expect(refreshRequests[2]).toMatchObject({
        path: "/token",
        authorization,
        body: {
          grant_type: "refresh_token",
          refresh_token: "fixture-paypal-refresh",
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
  "zero-subject",
  "missing-image",
  "null-image",
  "empty-image",
  "numeric-image",
  "missing-verified",
  "null-verified",
  "zero-verified",
  "numeric-verified",
  "mapped",
] as const) {
  compatScenario(
    `paypal ${variant} profile preserves raw owner and account info`,
    async (ctx) => {
      const data: Record<string, unknown> = {
        ...profile(ctx),
        picture: "https://images.example.invalid/paypal.png",
      };
      if (variant === "missing-name") delete data.name;
      if (variant === "null-name") data.name = null;
      if (variant === "empty-name") data.name = "";
      if (variant === "zero-name") data.name = 0;
      if (variant === "numeric-name") data.name = 42;
      if (variant === "numeric-subject") data.user_id = 42;
      if (variant === "zero-subject") data.user_id = 0;
      if (variant === "missing-image") delete data.picture;
      if (variant === "null-image") data.picture = null;
      if (variant === "empty-image") data.picture = "";
      if (variant === "numeric-image") data.picture = 42;
      if (variant === "missing-verified") delete data.email_verified;
      if (variant === "null-verified") data.email_verified = null;
      if (variant === "zero-verified") data.email_verified = 0;
      if (variant === "numeric-verified") data.email_verified = 1;
      await control(ctx, { profile: data });
      const flow = await callback(
        ctx,
        variant === "mapped" ? "social-paypal-mapped" : "social-paypal-default",
      );
      expect(flow.response.headers.get("location")).toBe("/dashboard");
      const persisted = await state(ctx);
      expect(persisted.users).toHaveLength(1);
      expect(persisted.accounts).toHaveLength(1);
      expect(persisted.sessions).toHaveLength(1);
      expect(persisted.accounts[0]!.accountId).toBe(String(data.user_id));
      const mapped = variant === "mapped";
      const name = ["missing-name", "null-name", "empty-name", "zero-name"].includes(variant)
        ? ""
        : variant === "numeric-name"
          ? String(data.name)
          : "PayPal Name";
      expect(persisted.users[0]).toMatchObject({
        name: mapped ? "Mapped PayPal Name" : name,
        email: mapped ? "mapped-paypal@example.invalid" : data.email,
        emailVerified: mapped || !!data.email_verified,
        image: mapped
          ? "https://images.example.invalid/mapped-paypal.png"
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
              name: "Mapped PayPal Name",
              email: "mapped-paypal@example.invalid",
              emailVerified: true,
              image: "https://images.example.invalid/mapped-paypal.png",
            }
          : {
              ...(Object.hasOwn(data, "name") ? { name: data.name } : {}),
              email: data.email,
              ...(Object.hasOwn(data, "email_verified")
                ? { emailVerified: data.email_verified }
                : {}),
              ...(Object.hasOwn(data, "picture") ? { image: data.picture } : {}),
            },
        data,
        account: {
          id: persisted.accounts[0]!.id,
          providerId: "paypal",
          accountId: String(data.user_id),
        },
      });
      expect(await state(ctx)).toEqual(persisted);
      expect((await receipts(ctx))[2]).toMatchObject({
        path: "/user",
        authorization: "Bearer fixture-paypal-access",
        accept: "application/json",
        query: { schema: "paypalv1.1" },
      });
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
  "blank-subject",
  "null-string-subject",
  "missing-email",
  "null-email",
  "empty-email",
  "api-null-profile",
  "userinfo-status",
  "token-status",
  "token-redirect",
  "implicit-disabled",
  "signup-disabled",
] as const) {
  compatScenario(
    `paypal rejects ${variant} without foreign writes`,
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
        delete data.user_id;
      }

      if (variant === "null-subject") {
        data.user_id = null;
      }

      if (variant === "empty-subject") {
        data.user_id = "";
      }

      if (variant === "blank-subject") data.user_id = " \uFEFF";
      if (variant === "null-string-subject") data.user_id = "null";
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
        ...(variant === "api-null-profile" ? { profile: null } : {}),
        ...(variant === "userinfo-status" ? { profileStatus: 500 } : {}),
        ...(variant === "token-status" ? { tokenStatus: 400 } : {}),
        ...(variant === "token-redirect" ? { tokenStatus: 307, tokenRedirect: true } : {}),
      });
      const flow = await callback(
        ctx,
        variant === "implicit-disabled"
          ? "social-paypal-implicit-disabled"
          : variant === "signup-disabled"
            ? "social-paypal-signup-disabled"
            : "social-paypal-default",
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
  "paypal explicit signup admits disabled implicit signup",
  async (ctx) => {
    await control(ctx, { profile: profile(ctx) });
    const flow = await callback(ctx, "social-paypal-implicit-disabled", true);
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
  "paypal unverified email gate stores account without issuing session",
  async (ctx) => {
    await control(ctx, { profile: { ...profile(ctx), email_verified: false } });
    const flow = await callback(ctx, "social-paypal-required");
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
    `paypal ${expiry} token expiry has no fabricated default`,
    async (ctx) => {
      const started = Date.now();
      const tokenResponse = {
        access_token: "fixture-paypal-access",
        refresh_token: "fixture-paypal-refresh",
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
  "paypal unsupported ID token and invalid provider state produce no requests",
  async (ctx) => {
    const before = await state(ctx);
    const actor = ctx.actor("paypal", "social-paypal-default");
    const direct = await actor.client.signIn.social({
      provider: "paypal",
      idToken: { token: "untrusted.not-signed.token" },
    });
    expect(direct.error?.code).toBe("ID_TOKEN_NOT_SUPPORTED");

    const wrong = await actor.client.signIn.social({ provider: "google" });
    expect(wrong.error?.code).toBe("PROVIDER_NOT_FOUND");

    const response = await actor.fetch(
      ctx.baseURL +
        authProfilePath("social-paypal-default") +
        "/callback/paypal?code=fixture-code&state=unissued",
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

for (const mode of ["public", "empty-client"] as const) {
  compatScenario(`paypal ${mode} credentials deny before provider HTTP`, async (ctx) => {
    const before = await state(ctx);
    const result = await ctx.actor("paypal", `social-paypal-${mode}`).client.signIn.social({
      provider: "paypal",
      scopes: ["openid", "email"],
    });
    expect(result.error).toBeTruthy();
    expect(await state(ctx)).toEqual(before);
    expect(await receipts(ctx)).toEqual([]);
    return {
      result: ctx.snapshot(result),
      before,
      after: await state(ctx),
      receipts: await receipts(ctx),
    };
  });
}

for (const mode of ["prompt", "empty-prompt"] as const) {
  compatScenario(`paypal ${mode} factory prompt preserves configured truthiness`, async (ctx) => {
    const result = await ctx
      .actor("paypal", `social-paypal-${mode}`)
      .client.signIn.social({ provider: "paypal" });
    expect(result.error).toBeNull();
    expect(new URL(result.data!.url!).searchParams.get("prompt")).toBe(
      mode === "prompt" ? "consent" : null,
    );
    return { result: ctx.snapshot(result), persisted: await state(ctx) };
  });
}

function idToken(claims: Record<string, unknown>) {
  // Intentionally unsigned: the actual published factory performs decode-only
  // subject consistency on trusted token-endpoint output, never jwtVerify.
  return `${Buffer.from(JSON.stringify({ alg: "none" })).toString("base64url")}.${Buffer.from(JSON.stringify(claims)).toString("base64url")}.`;
}
for (const variant of [
  "matching-user-id",
  "matching-numeric-sub",
  "null-sub-fallback",
  "different-account-subject",
  "wrong-issuer-audience-nonce",
  "mismatch",
  "empty-sub-blocks-fallback",
  "missing-token-sub",
  "null-token-sub",
  "empty-token-sub",
  "numeric-token-sub-mismatch",
  "malformed",
  "non-object",
] as const) {
  compatScenario(
    `paypal token-endpoint ID token ${variant} enforces decoded subject contract`,
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
      const subject = data.user_id;
      let claims: Record<string, unknown> = { sub: subject };
      if (variant === "matching-numeric-sub" || variant === "different-account-subject") {
        data.sub = variant === "matching-numeric-sub" ? 42 : "oidc-subject";
        claims.sub = data.sub;
      }
      if (variant === "null-sub-fallback") data.sub = null;
      if (variant === "wrong-issuer-audience-nonce") {
        claims = {
          sub: subject,
          iss: "https://wrong.example.invalid",
          aud: "wrong-audience",
          nonce: "wrong-nonce",
          exp: 1,
        };
      }
      if (variant === "mismatch") claims.sub = "other-subject";
      if (variant === "empty-sub-blocks-fallback") data.sub = "";
      if (variant === "missing-token-sub") delete claims.sub;
      if (variant === "null-token-sub") claims.sub = null;
      if (variant === "empty-token-sub") claims.sub = "";
      if (variant === "numeric-token-sub-mismatch") {
        data.user_id = "42";
        claims.sub = 42;
      }
      const token =
        variant === "malformed"
          ? "invalid.not-json.token"
          : variant === "non-object"
            ? "e30.W10."
            : idToken(claims);
      await control(ctx, {
        profile: data,
        tokenResponse: {
          access_token: "fixture-paypal-access",
          refresh_token: "fixture-paypal-refresh",
          token_type: "Bearer",
          expires_in: 3600,
          id_token: token,
        },
      });
      const flow = await callback(
        ctx,
        "social-paypal-default",
        false,
        variant === "wrong-issuer-audience-nonce" ? "&iss=https%3A%2F%2Fwrong.example.invalid" : "",
      );
      const admitted = [
        "matching-user-id",
        "matching-numeric-sub",
        "null-sub-fallback",
        "different-account-subject",
        "wrong-issuer-audience-nonce",
      ].includes(variant);
      const after = await state(ctx);
      expect(flow.response.status).toBe(302);
      if (admitted) {
        expect(flow.response.headers.get("location")).toBe("/dashboard");
        const account = after.accounts.find((row) => row.providerId === "paypal")!;
        expect(account.accountId).toBe(String(data.user_id));
        expect(account.idToken).toBe(token);
        for (const table of ["users", "accounts", "sessions"] as const) {
          expect(after[table]).toHaveLength(before[table].length + 1);
          expect(after[table].find((row) => row.id === before[table][0]!.id)).toEqual(
            before[table][0],
          );
        }
        expect((await flow.actor.client.getSession()).data?.user).toBeTruthy();
      } else {
        expect(
          new URL(flow.response.headers.get("location")!, ctx.baseURL).searchParams.get("error"),
        ).toBe("unable_to_get_user_info");
        expect(after).toEqual(before);
        expect((await flow.actor.client.getSession()).data).toBeNull();
      }
      expect(await receipts(ctx)).toHaveLength(2);
      return {
        start: ctx.snapshot(flow.start),
        callback: { status: flow.response.status, location: flow.response.headers.get("location") },
        token,
        data,
        before,
        after,
        receipts: await receipts(ctx),
      };
    },
    ["POST /sign-in/social", "GET /callback/{}"],
  );
}

for (const variant of ["wrong-state", "wrong-provider"] as const) {
  compatScenario(
    `paypal issued callback ${variant} denies without provider requests or foreign writes`,
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
      const actor = ctx.actor("paypal", "social-paypal-default");
      const start = await actor.client.signIn.social({
        provider: "paypal",
        callbackURL: "/dashboard",
      });
      expect(start.error).toBeNull();
      const issued = new URL(start.data!.url!).searchParams.get("state")!;
      const response = await actor.fetch(
        ctx.baseURL +
          authProfilePath("social-paypal-default") +
          `/callback/${variant === "wrong-provider" ? "unknown-paypal" : "paypal"}?code=fixture-code&state=${encodeURIComponent(variant === "wrong-state" ? ctx.uniqueToken("wrong-state") : issued)}`,
        { redirect: "manual" },
      );
      expect(response.status).toBe(302);
      expect(
        new URL(response.headers.get("location")!, ctx.baseURL).searchParams.get("error"),
      ).toBe(variant === "wrong-state" ? "state_mismatch" : "oauth_provider_not_found");
      expect(await state(ctx)).toEqual(before);
      expect(await receipts(ctx)).toEqual([]);
      expect((await actor.client.getSession()).data).toBeNull();
      return {
        start: ctx.snapshot(start),
        callback: { status: response.status, location: response.headers.get("location") },
        before,
        after: await state(ctx),
        receipts: await receipts(ctx),
      };
    },
    ["POST /sign-in/social", "GET /callback/{}"],
  );
}

for (const variant of ["numeric-email", "empty-string-verified"] as const) {
  compatScenario(
    `paypal existing account info ${variant} preserves raw fields without new admission`,
    async (ctx) => {
      const data = profile(ctx);
      await control(ctx, { profile: data });
      const flow = await callback(ctx);
      expect(flow.response.headers.get("location")).toBe("/dashboard");
      const before = await state(ctx);
      const account = before.accounts[0]!;
      const changed = {
        ...data,
        user_id: "must-not-rebind-existing-account",
        ...(variant === "numeric-email" ? { email: 42 } : { email_verified: "" }),
      };
      await control(ctx, { profile: changed });
      const info = await flow.actor.client.$fetch("/account-info", {
        query: { accountId: String(account.id) },
      });
      expect(info.error).toBeNull();
      expect(info.data).toEqual({
        user: { name: changed.name, email: changed.email, emailVerified: changed.email_verified },
        data: changed,
        account: { id: account.id, providerId: "paypal", accountId: data.user_id },
      });
      expect(await state(ctx)).toEqual(before);
      expect(await receipts(ctx)).toHaveLength(3);
      return {
        start: ctx.snapshot(flow.start),
        before,
        info: ctx.snapshot(info),
        changed,
        after: await state(ctx),
        receipts: await receipts(ctx),
      };
    },
    ["POST /sign-in/social", "GET /callback/{}", "GET /account-info"],
  );
}
