import { expect } from "bun:test";
import { authProfilePath, type FixtureProfile } from "../../support/profiles";
import { compatScenario, type ScenarioContext } from "../../support/scenario";
import { credential, issuedAt } from "../one-tap/helpers";

async function state(ctx: ScenarioContext) {
  const result = await ctx.rawRequest({ path: "/__test/social-provider/state" });
  expect(result.status).toBe(200);
  return result.body as {
    users: Array<Record<string, unknown>>;
    accounts: Array<Record<string, unknown>>;
    sessions: Array<Record<string, unknown>>;
  };
}
async function receipts(ctx: ScenarioContext) {
  const result = await ctx.rawRequest({ path: "/__test/apple/receipts" });
  expect(result.status).toBe(200);
  const rows = result.body as Array<{ body: Record<string, string> | null }>;
  return rows.map((row) => ({
    ...row,
    body: row.body?.code_verifier
      ? {
          ...row.body,
          code_verifier: { token: row.body.code_verifier, length: row.body.code_verifier.length },
        }
      : row.body,
  }));
}
async function proof(ctx: ScenarioContext, claims: Record<string, unknown> = {}, wrong = false) {
  return credential(
    {
      iss: "https://appleid.apple.com",
      aud: "fixture-social-client",
      sub: ctx.uniqueToken("apple-subject"),
      email: ctx.uniqueEmail("apple"),
      email_verified: "true",
      name: "JWT Apple Name",
      picture: "https://images.example.invalid/ignored-jwt-picture.png",
      ...claims,
    },
    {},
    wrong,
  );
}
async function control(ctx: ScenarioContext, value: Record<string, unknown>) {
  const result = await ctx.rawRequest({
    path: "/__test/apple/control",
    method: "POST",
    json: value,
  });
  expect(result.status).toBe(200);
}

for (const mode of ["default", "configured", "disabled-scope", "disabled-configured"] as const) {
  compatScenario(
    `apple published ${mode} authorization scopes and form-post PKCE`,
    async (ctx) => {
      const actor = ctx.actor("apple", `social-apple-${mode}`);
      const before = await state(ctx);
      const result = await actor.client.signIn.social({
        provider: "apple",
        callbackURL: "/dashboard",
        scopes: ["requested-scope"],
        loginHint: "ignored@example.invalid",
      });
      expect(result.error).toBeNull();
      const url = new URL(result.data!.url!);
      expect(url.origin).toBe("https://appleid.apple.com");
      expect(url.pathname).toBe("/auth/authorize");
      expect(url.searchParams.get("response_type")).toBe("code id_token");
      expect(url.searchParams.get("response_mode")).toBe("form_post");
      expect(url.searchParams.get("code_challenge_method")).toBe("S256");
      expect(url.searchParams.get("code_challenge")).toBeTruthy();
      expect(url.searchParams.has("login_hint")).toBeFalse();
      expect(url.searchParams.get("scope")).toBe(
        [
          ...(mode.startsWith("disabled-") ? [] : ["email", "name"]),
          ...(["configured", "disabled-configured"].includes(mode) ? ["configured-scope"] : []),
          "requested-scope",
        ].join(" "),
      );
      const persisted = await state(ctx);
      expect(persisted).toEqual(before);
      return { result: ctx.snapshot(result), before, persisted };
    },
    ["POST /sign-in/social"],
  );
}

for (const mapping of [
  "named",
  "numeric-name",
  "zero-name",
  "missing-name",
  "null-name",
  "empty-name",
  "supplied-name",
  "js-trim",
  "numeric",
  "missing-email",
  "null-email",
  "unverified",
  "false-string",
] as const) {
  compatScenario(
    `apple signed ID token ${mapping} profile and ownership`,
    async (ctx) => {
      const foreign = ctx.actor("foreign");
      const foreignSignup = await foreign.client.signUp.email({
        email: ctx.uniqueEmail("foreign"),
        password: "Password123!",
        name: "Foreign Owner",
      });
      expect(foreignSignup.error).toBeNull();
      const before = await state(ctx);
      const claims =
        mapping === "numeric-name"
          ? { name: 7 }
          : mapping === "zero-name"
            ? { name: 0 }
            : mapping === "missing-name"
              ? { name: undefined }
              : mapping === "null-name"
                ? { name: null }
                : mapping === "empty-name"
                  ? { name: "" }
                  : mapping === "numeric"
                    ? { sub: 42 }
                    : mapping === "missing-email"
                      ? { email: undefined }
                      : mapping === "null-email"
                        ? { email: null }
                        : mapping === "unverified"
                          ? { email_verified: false }
                          : mapping === "false-string"
                            ? { email_verified: "false" }
                            : {};
      const token = await proof(ctx, claims);
      const actor = ctx.actor("apple", "social-apple-default");
      const result = await actor.client.signIn.social({
        provider: "apple",
        idToken: {
          token,
          ...(mapping === "supplied-name"
            ? { user: { name: { firstName: "Ada", lastName: "Apple" } } }
            : mapping === "js-trim"
              ? { user: { name: { firstName: "\uFEFF\u0085Ada\u0085\uFEFF", lastName: "" } } }
              : {}),
        },
      });
      const after = await state(ctx);
      if (mapping.endsWith("email")) {
        expect(result.error?.code).toBe("USER_EMAIL_NOT_FOUND");
        expect(after).toEqual(before);
      } else {
        expect(result.error).toBeNull();
        expect(after.users).toHaveLength(before.users.length + 1);
        expect(after.accounts).toHaveLength(before.accounts.length + 1);
        expect(after.sessions).toHaveLength(before.sessions.length + 1);
        expect(after.users.find((row) => row.id === before.users[0]!.id)).toEqual(before.users[0]);
        expect(after.accounts.find((row) => row.id === before.accounts[0]!.id)).toEqual(
          before.accounts[0],
        );
        expect(after.sessions.find((row) => row.id === before.sessions[0]!.id)).toEqual(
          before.sessions[0],
        );
        const owner = after.users.find((row) => row.id !== before.users[0]!.id)!;
        expect(owner.name).toBe(
          mapping === "js-trim"
            ? "\u0085Ada\u0085"
            : mapping === "numeric-name"
              ? "7"
              : mapping === "zero-name"
                ? ""
                : mapping === "supplied-name"
                  ? "Ada Apple"
                  : ["missing-name", "null-name", "empty-name"].includes(mapping)
                    ? ""
                    : "JWT Apple Name",
        );
        expect(owner.image).toBeNull();
        expect(owner.emailVerified).toBe(!["unverified", "false-string"].includes(mapping));
        const account = after.accounts.find((row) => row.userId === owner.id)!;
        expect(account.providerId).toBe("apple");
        expect(account.idToken).toBe(token);
        expect(account.accountId).toBe(
          mapping === "numeric"
            ? "42"
            : JSON.parse(Buffer.from(token.split(".")[1]!, "base64url").toString()).sub,
        );
      }
      return {
        result: ctx.snapshot(result),
        before,
        after,
        receipts: await receipts(ctx),
        session: ctx.snapshot(await actor.client.getSession()),
      };
    },
    ["POST /sign-in/social"],
  );
}

for (const variant of [
  "signature",
  "issuer",
  "audience",
  "expired",
  "old",
  "nonce",
  "subject",
  "blank-subject",
  "disabled",
  "implicit-disabled",
] as const) {
  compatScenario(
    `apple signed ID token rejects ${variant} without writes`,
    async (ctx) => {
      const claims =
        variant === "issuer"
          ? { iss: "https://untrusted.invalid" }
          : variant === "audience"
            ? { aud: "foreign-client" }
            : variant === "expired"
              ? { exp: issuedAt - 10 }
              : variant === "old"
                ? { iat: issuedAt - 7200 }
                : variant === "nonce"
                  ? { nonce: "foreign-nonce" }
                  : variant === "blank-subject"
                    ? { sub: "\uFEFF " }
                    : variant === "subject"
                      ? { sub: null }
                      : {};
      const token = await proof(ctx, claims, variant === "signature");
      const profile: FixtureProfile =
        variant === "disabled"
          ? "social-apple-disabled-idtoken"
          : variant === "implicit-disabled"
            ? "social-apple-implicit-disabled"
            : "social-apple-default";
      const actor = ctx.actor("apple", profile);
      const before = await state(ctx);
      const result = await actor.client.signIn.social({
        provider: "apple",
        idToken: { token, ...(variant === "nonce" ? { nonce: "requested-nonce" } : {}) },
      });
      expect(result.error).not.toBeNull();
      expect(result.error?.code).toBe(
        variant === "disabled"
          ? "ID_TOKEN_NOT_SUPPORTED"
          : variant === "implicit-disabled"
            ? "OAUTH_LINK_ERROR"
            : ["subject", "blank-subject"].includes(variant)
              ? "FAILED_TO_GET_USER_INFO"
              : "INVALID_TOKEN",
      );
      const after = await state(ctx);
      expect(after).toEqual(before);
      return { result: ctx.snapshot(result), before, after, receipts: await receipts(ctx) };
    },
    ["POST /sign-in/social"],
  );
}

compatScenario(
  "apple real code exchange persists tokens and consumes callback state",
  async (ctx) => {
    const actor = ctx.actor("apple", "social-apple-default");
    const token = await proof(ctx);
    await control(ctx, { idToken: token });
    const start = await actor.client.signIn.social({
      provider: "apple",
      callbackURL: "/dashboard",
    });
    expect(start.error).toBeNull();
    const stateToken = new URL(start.data!.url!).searchParams.get("state")!;
    const path =
      authProfilePath("social-apple-default") +
      `/callback/apple?code=fixture-code&state=${encodeURIComponent(stateToken)}`;
    const callback = await actor.fetch(ctx.baseURL + path, { redirect: "manual" });
    expect(callback.status).toBe(302);
    const session = await actor.client.getSession();
    expect(session.data?.user).toBeTruthy();
    const providerRequests = await ctx.rawRequest({ path: "/__test/apple/receipts" });
    const exchange = (providerRequests.body as Array<{ body: Record<string, string> }>)[0]!;
    const verifier = exchange.body.code_verifier!;
    expect(verifier).toHaveLength(128);
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
    expect(new URL(start.data!.url!).searchParams.get("code_challenge")).toBe(
      Buffer.from(digest).toString("base64url"),
    );
    expect(exchange.body).toEqual({
      grant_type: "authorization_code",
      code: "fixture-code",
      client_id: "fixture-social-client",
      client_secret: "fixture-social-secret",
      redirect_uri: ctx.baseURL + authProfilePath("social-apple-default") + "/callback/apple",
      code_verifier: verifier,
    });
    const persisted = await state(ctx);
    expect(persisted.accounts).toHaveLength(1);
    expect(persisted.accounts[0]!.idToken).toBe(token);
    const replay = await actor.fetch(ctx.baseURL + path, { redirect: "manual" });
    const afterReplay = await state(ctx);
    expect(afterReplay).toEqual(persisted);
    return {
      start: ctx.snapshot(start),
      callback: { status: callback.status, location: callback.headers.get("location") },
      session: ctx.snapshot(session),
      persisted,
      replay: { status: replay.status, location: replay.headers.get("location") },
      afterReplay,
      receipts: await receipts(ctx),
    };
  },
  ["GET /callback/{}"],
);

for (const variant of [
  "exact-nonce",
  "hashed-nonce",
  "bundle",
  "audience",
  "client-array",
  "explicit-signup",
] as const) {
  compatScenario(
    `apple signed configured ${variant} admission`,
    async (ctx) => {
      const nonce = "fixture-apple-nonce";
      const nonceHash = Buffer.from(
        await crypto.subtle.digest("SHA-256", new TextEncoder().encode(nonce)),
      ).toString("hex");
      const claims =
        variant === "bundle"
          ? { aud: "fixture-apple-bundle" }
          : variant === "audience"
            ? { aud: ["foreign-audience", "fixture-apple-audience"] }
            : variant === "client-array"
              ? { aud: "fixture-apple-secondary" }
              : variant === "hashed-nonce"
                ? { nonce: nonceHash }
                : variant === "exact-nonce"
                  ? { nonce }
                  : {};
      const token = await proof(ctx, claims);
      const profile: FixtureProfile =
        variant === "bundle"
          ? "social-apple-bundle"
          : variant === "audience"
            ? "social-apple-audience"
            : variant === "client-array"
              ? "social-apple-client-array"
              : variant === "explicit-signup"
                ? "social-apple-implicit-disabled"
                : "social-apple-default";
      const actor = ctx.actor("apple", profile);
      const result = await actor.client.signIn.social({
        provider: "apple",
        requestSignUp: variant === "explicit-signup",
        idToken: { token, ...(variant.endsWith("nonce") ? { nonce } : {}) },
      });
      expect(result.error).toBeNull();
      const persisted = await state(ctx);
      expect(persisted.users).toHaveLength(1);
      expect(persisted.accounts).toHaveLength(1);
      expect(persisted.sessions).toHaveLength(1);
      expect(persisted.accounts[0]!.idToken).toBe(token);
      return { result: ctx.snapshot(result), persisted, receipts: await receipts(ctx) };
    },
    ["POST /sign-in/social"],
  );
}

compatScenario(
  "apple provider refresh rotates stored credentials and excludes foreign owners",
  async (ctx) => {
    const foreign = ctx.actor("foreign");
    expect(
      (
        await foreign.client.signUp.email({
          email: ctx.uniqueEmail("foreign"),
          password: "Password123!",
          name: "Foreign",
        })
      ).error,
    ).toBeNull();
    const actor = ctx.actor("apple", "social-apple-default");
    const token = await proof(ctx);
    await control(ctx, { idToken: token });
    const start = await actor.client.signIn.social({
      provider: "apple",
      callbackURL: "/dashboard",
    });
    expect(start.error).toBeNull();
    const stateToken = new URL(start.data!.url!).searchParams.get("state")!;
    const callback = await actor.fetch(
      authProfilePath("social-apple-default") +
        `/callback/apple?code=fixture-code&state=${encodeURIComponent(stateToken)}`,
      { redirect: "manual" },
    );
    expect(callback.status).toBe(302);
    const before = await state(ctx);
    const account = before.accounts.find((row) => row.providerId === "apple")!;
    await control(ctx, {
      tokenResponse: {
        access_token: "fixture-apple-access-rotated",
        refresh_token: "fixture-apple-refresh-rotated",
        id_token: token,
        token_type: "Bearer",
        expires_in: 1800,
      },
    });
    const denied = await foreign.client.refreshToken({ accountId: String(account.id) });
    expect(denied.error).not.toBeNull();
    expect(await state(ctx)).toEqual(before);
    const refreshed = await actor.client.refreshToken({ accountId: String(account.id) });
    expect(refreshed.error).toBeNull();
    const after = await state(ctx);
    expect(after.users).toEqual(before.users);
    expect(after.sessions).toEqual(before.sessions);
    expect(after.accounts.find((row) => row.id !== account.id)).toEqual(
      before.accounts.find((row) => row.id !== account.id),
    );
    expect(after.accounts.find((row) => row.id === account.id)).toMatchObject({
      accountId: account.accountId,
      userId: account.userId,
      accessToken: "fixture-apple-access-rotated",
      refreshToken: "fixture-apple-refresh-rotated",
      idToken: token,
    });
    const signOut = await actor.client.signOut();
    expect(signOut.error).toBeNull();
    expect((await actor.client.getSession()).data).toBeNull();
    return {
      before,
      denied: ctx.snapshot(denied),
      refreshed: ctx.snapshot(refreshed),
      after,
      signOut: ctx.snapshot(signOut),
      signedOut: await state(ctx),
      receipts: await receipts(ctx),
    };
  },
  ["GET /callback/{}", "POST /refresh-token"],
);

compatScenario(
  "apple JWKS rotation is observed on each signed token admission",
  async (ctx) => {
    const keys = await Bun.file(
      new URL("../../../../fixtures/one-tap/jwks.json", import.meta.url),
    ).json();
    const token = await proof(ctx);
    const actor = ctx.actor("apple", "social-apple-default");
    await control(ctx, { keys });
    const first = await actor.client.signIn.social({ provider: "apple", idToken: { token } });
    expect(first.error).toBeNull();
    const admitted = await state(ctx);
    await control(ctx, { keys: { keys: [] } });
    const retired = await actor.client.signIn.social({ provider: "apple", idToken: { token } });
    expect(retired.error?.code).toBe("INVALID_TOKEN");
    expect(await state(ctx)).toEqual(admitted);
    await control(ctx, { keys });
    const restored = await actor.client.signIn.social({ provider: "apple", idToken: { token } });
    expect(restored.error).toBeNull();
    const after = await state(ctx);
    expect(after.users).toEqual(admitted.users);
    expect(after.accounts).toHaveLength(admitted.accounts.length);
    expect(after.accounts[0]).toEqual({
      ...admitted.accounts[0],
      updatedAt: after.accounts[0]!.updatedAt,
    });
    expect(Date.parse(String(after.accounts[0]!.updatedAt))).toBeGreaterThanOrEqual(
      Date.parse(String(admitted.accounts[0]!.updatedAt)),
    );
    expect(after.sessions).toHaveLength(admitted.sessions.length + 1);
    return {
      first: ctx.snapshot(first),
      admitted,
      retired: ctx.snapshot(retired),
      restored: ctx.snapshot(restored),
      after,
      receipts: await receipts(ctx),
    };
  },
  ["POST /sign-in/social"],
);

compatScenario(
  "apple profile mapping receives supplied name and cannot replace raw subject",
  async (ctx) => {
    const token = await proof(ctx);
    const actor = ctx.actor("apple", "social-apple-mapped");
    const result = await actor.client.signIn.social({
      provider: "apple",
      idToken: { token, user: { name: { firstName: "Ada", lastName: "Apple" } } },
    });
    expect(result.error).toBeNull();
    const persisted = await state(ctx);
    expect(persisted.users[0]).toMatchObject({
      name: "Mapped Ada Apple",
      email: "mapped-apple@example.invalid",
      emailVerified: false,
      image: "https://images.example.invalid/mapped-apple.png",
    });
    expect(persisted.accounts[0]!.accountId).toBe(
      JSON.parse(Buffer.from(token.split(".")[1]!, "base64url").toString()).sub,
    );
    return { result: ctx.snapshot(result), persisted, receipts: await receipts(ctx) };
  },
  ["POST /sign-in/social"],
);

for (const variant of ["absent", "zero", "fractional", "array-scope", "comma-scope"] as const) {
  compatScenario(
    `apple token transport preserves ${variant} expiry and scope`,
    async (ctx) => {
      const actor = ctx.actor("apple", "social-apple-default");
      const token = await proof(ctx);
      const response = {
        access_token: "fixture-apple-access",
        id_token: token,
        token_type: "Bearer",
        ...(variant === "zero"
          ? { expires_in: 0 }
          : variant === "fractional"
            ? { expires_in: 3600.25 }
            : {}),
        ...(variant === "array-scope"
          ? { scope: [" email ", null, "", 42, "name"] }
          : variant === "comma-scope"
            ? { scope: "email,name   custom" }
            : {}),
      };
      await control(ctx, { tokenResponse: response });
      const start = await actor.client.signIn.social({
        provider: "apple",
        callbackURL: "/dashboard",
      });
      expect(start.error).toBeNull();
      const stateToken = new URL(start.data!.url!).searchParams.get("state")!;
      const before = Date.now();
      const callback = await actor.fetch(
        authProfilePath("social-apple-default") +
          `/callback/apple?code=fixture-code&state=${encodeURIComponent(stateToken)}`,
        { redirect: "manual" },
      );
      expect(callback.status).toBe(302);
      const persisted = await state(ctx);
      const account = persisted.accounts[0]!;
      expect(account.scope).toBe(
        variant === "array-scope"
          ? "email,name"
          : variant === "comma-scope"
            ? "email,name,custom"
            : "",
      );
      if (variant === "fractional") {
        expect(Date.parse(String(account.accessTokenExpiresAt))).toBeGreaterThanOrEqual(
          before + 3600250,
        );
        expect(Date.parse(String(account.accessTokenExpiresAt))).toBeLessThanOrEqual(
          Date.now() + 3600250,
        );
      } else expect(account.accessTokenExpiresAt).toBeNull();
      return {
        start: ctx.snapshot(start),
        callback: { status: callback.status, location: callback.headers.get("location") },
        persisted,
        receipts: await receipts(ctx),
      };
    },
    ["GET /callback/{}"],
  );
}

compatScenario(
  "apple rejects wrong provider and callback state without creating identities",
  async (ctx) => {
    const actor = ctx.actor("apple", "social-apple-default");
    const before = await state(ctx);
    const wrongProvider = await actor.client.signIn.social({
      provider: "google",
      idToken: { token: await proof(ctx) },
    });
    expect(wrongProvider.error?.status).toBe(404);
    expect(wrongProvider.error?.code).toBe("PROVIDER_NOT_FOUND");
    const start = await actor.client.signIn.social({
      provider: "apple",
      callbackURL: "/dashboard",
    });
    expect(start.error).toBeNull();
    const invalid = await actor.fetch(
      authProfilePath("social-apple-default") +
        "/callback/apple?code=fixture-code&state=foreign-state",
      { redirect: "manual" },
    );
    expect(invalid.status).toBe(302);
    expect(invalid.headers.get("location")).toContain("error=state_mismatch");
    expect(await state(ctx)).toEqual(before);
    expect(await receipts(ctx)).toEqual([]);
    return {
      wrongProvider: ctx.snapshot(wrongProvider),
      start: ctx.snapshot(start),
      invalid: {
        status: invalid.status,
        location: invalid.headers.get("location"),
        body: await invalid.text(),
      },
      before,
      after: await state(ctx),
      receipts: await receipts(ctx),
    };
  },
  ["POST /sign-in/social", "GET /callback/{}"],
);

compatScenario(
  "apple explicit empty client array rejects empty token audience without writes",
  async (ctx) => {
    const actor = ctx.actor("apple", "social-apple-empty-clients");
    const token = await proof(ctx, { aud: "" });
    const before = await state(ctx);
    const result = await actor.client.signIn.social({ provider: "apple", idToken: { token } });
    expect(result.error?.code).toBe("INVALID_TOKEN");
    expect(await state(ctx)).toEqual(before);
    return {
      result: ctx.snapshot(result),
      before,
      after: await state(ctx),
      receipts: await receipts(ctx),
    };
  },
  ["POST /sign-in/social"],
);
