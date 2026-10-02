import { expect } from "bun:test";
import { createPublicKey, sign } from "node:crypto";
import { credential, issuedAt } from "../../support/id-token";
import { authProfilePath, type FixtureProfile } from "../../support/profiles";
import { compatScenario, type ScenarioContext } from "../../support/scenario";

type Row = Record<string, unknown>;
type Stored = {
  users: Array<Row & { id: string }>;
  accounts: Array<Row & { id: string }>;
  sessions: Array<Row & { id: string }>;
};
async function state(ctx: ScenarioContext) {
  const response = await ctx.rawRequest({ path: "/__test/social-provider/state" });
  expect(response.status).toBe(200);
  return response.body as Stored;
}
async function control(ctx: ScenarioContext, value: Row) {
  const response = await ctx.rawRequest({
    path: "/__test/cognito/control",
    method: "POST",
    json: value,
  });
  expect(response.status).toBe(200);
  return response;
}
async function receipts(ctx: ScenarioContext) {
  const response = await ctx.rawRequest({ path: "/__test/cognito/receipts" });
  expect(response.status).toBe(200);
  return (
    response.body as Array<{
      path: string;
      method: string;
      authorization: string | null;
      contentType: string | null;
      body: Record<string, string> | null;
    }>
  ).map((row) => ({
    ...row,
    body: row.body?.code_verifier
      ? {
          ...row.body,
          code_verifier: { token: row.body.code_verifier, length: row.body.code_verifier.length },
        }
      : row.body,
  }));
}
async function proof(ctx: ScenarioContext, claims: Row = {}, header: Row = {}, wrong = false) {
  return credential(
    {
      iss: "https://cognito-idp.fixture-region.amazonaws.com/fixture-pool",
      aud: "fixture-social-client",
      sub: ctx.uniqueToken("cognito-subject"),
      email: ctx.uniqueEmail("cognito"),
      email_verified: true,
      name: "Cognito JWT Name",
      picture: "https://images.example.invalid/cognito.png",
      ...claims,
    },
    header,
    wrong,
  );
}
async function foreign(ctx: ScenarioContext) {
  const actor = ctx.actor("foreign"),
    signup = await actor.client.signUp.email({
      email: ctx.uniqueEmail("foreign"),
      password: "Password123!",
      name: "Foreign",
    });
  expect(signup.error).toBeNull();
  return { actor, signup, before: await state(ctx) };
}
function unchangedForeign(before: Stored, after: Stored) {
  for (const key of ["users", "accounts", "sessions"] as const)
    for (const row of before[key])
      expect(after[key].find((candidate) => candidate.id === row.id)).toEqual(row);
}
function userProfile(ctx: ScenarioContext): Row {
  return {
    sub: ctx.uniqueToken("cognito-http-subject"),
    name: null,
    given_name: "HTTP Given Name",
    username: "HTTP Username",
    email: ctx.uniqueEmail("cognito-http"),
    email_verified: true,
    picture: "https://images.example.invalid/cognito-http.png",
    originalApplicationField: { retained: true },
  };
}
async function callback(
  ctx: ScenarioContext,
  mode: FixtureProfile = "social-cognito-default",
  requestSignUp = false,
) {
  const actor = ctx.actor("cognito", mode),
    start = await actor.client.signIn.social({
      provider: "cognito",
      callbackURL: "/dashboard",
      requestSignUp,
    });
  expect(start.error).toBeNull();
  const url = new URL(start.data!.url!),
    path =
      authProfilePath(mode) +
      `/callback/cognito?code=fixture-code&state=${encodeURIComponent(url.searchParams.get("state")!)}`,
    response = await actor.fetch(ctx.baseURL + path, { redirect: "manual" });
  return { actor, start, url, path, response };
}

for (const mode of [
  "default",
  "configured",
  "disabled-scope",
  "disabled-configured",
  "http-domain",
  "configured-endpoint",
] as const) {
  compatScenario(
    `cognito published ${mode} authorization preserves ordered scopes PKCE and encoded query`,
    async (ctx) => {
      const other = await foreign(ctx),
        actor = ctx.actor("cognito", `social-cognito-${mode}`),
        result = await actor.client.signIn.social({
          provider: "cognito",
          callbackURL: "/dashboard",
          scopes: ["requested-scope", "openid"],
          loginHint: "ignored@example.invalid",
          additionalParams: { identity_provider: "RequestedIdentity", custom: "value with space" },
        });
      expect(result.error).toBeNull();
      const url = new URL(result.data!.url!);
      expect(url.origin).toBe(
        mode === "configured-endpoint"
          ? "https://alternate-cognito.example.invalid"
          : "https://fixture-cognito.example.invalid",
      );
      expect(url.pathname).toBe(
        mode === "configured-endpoint" ? "/authorize" : "/oauth2/authorize",
      );
      expect(url.searchParams.get("response_type")).toBe("code");
      expect(url.searchParams.get("client_id")).toBe("fixture-social-client");
      expect(url.searchParams.get("code_challenge_method")).toBe("S256");
      expect(url.searchParams.get("code_challenge")).toBeTruthy();
      expect(url.searchParams.has("login_hint")).toBeFalse();
      const configured = ["configured", "disabled-configured"].includes(mode),
        scopes = [
          ...(mode.startsWith("disabled-") ? [] : ["openid", "profile", "email"]),
          ...(configured ? ["configured-scope", "openid", "punctuation-!~*'()"] : []),
          "requested-scope",
          "openid",
        ];
      expect(url.searchParams.get("scope")).toBe(scopes.join(" "));
      expect(result.data!.url).toContain(
        `scope=${encodeURIComponent(scopes.join(" ")).replaceAll("'", "%27")}`,
      );
      expect(url.searchParams.get("identity_provider")).toBe("RequestedIdentity");
      expect(url.searchParams.get("custom")).toBe("value with space");
      expect(url.searchParams.get("prompt")).toBe(configured ? "login" : null);
      expect(url.searchParams.get("redirect_uri")).toBe(
        mode === "configured-endpoint"
          ? "https://client.example.invalid/cognito-return"
          : ctx.baseURL + authProfilePath(`social-cognito-${mode}`) + "/callback/cognito",
      );
      if (mode === "configured-endpoint") expect(url.searchParams.get("retained")).toBe("value");
      const after = await state(ctx);
      expect(after).toEqual(other.before);
      return {
        foreign: ctx.snapshot(other.signup),
        result: ctx.snapshot(result),
        before: other.before,
        after,
        receipts: await receipts(ctx),
      };
    },
    ["POST /sign-in/social"],
  );
}
for (const reserved of [
  "state",
  "client_id",
  "redirect_uri",
  "response_type",
  "code_challenge",
  "code_challenge_method",
  "nonce",
  "scope",
]) {
  compatScenario(
    `cognito rejects caller override of reserved ${reserved} before any credential exchange`,
    async (ctx) => {
      const other = await foreign(ctx),
        actor = ctx.actor("cognito", "social-cognito-configured"),
        result = await actor.client.signIn.social({
          provider: "cognito",
          additionalParams: { [reserved]: "attacker-chosen" },
        });
      expect(result.error).toMatchObject({ status: 400, code: "VALIDATION_ERROR" });
      expect(await state(ctx)).toEqual(other.before);
      expect(await receipts(ctx)).toEqual([]);
      return { result: ctx.snapshot(result), before: other.before, after: await state(ctx) };
    },
  );
}
const mappings = [
  { name: "named", claims: {}, expected: "Cognito JWT Name" },
  {
    name: "empty name falls back to given name",
    claims: { name: "", given_name: "Given Cognito" },
    expected: "Given Cognito",
  },
  {
    name: "null name falls back to username",
    claims: { name: null, given_name: null, username: "Cognito Username" },
    expected: "Cognito Username",
  },
  { name: "missing name", claims: { name: undefined }, expected: "" },
  { name: "numeric name", claims: { name: 7 }, expected: "7" },
  {
    name: "zero name falls back",
    claims: { name: 0, given_name: "After Zero" },
    expected: "After Zero",
  },
  { name: "numeric subject", claims: { sub: 42 }, expected: "Cognito JWT Name" },
  { name: "missing image", claims: { picture: undefined }, expected: "Cognito JWT Name" },
  { name: "null image", claims: { picture: null }, expected: "Cognito JWT Name" },
  { name: "empty image", claims: { picture: "" }, expected: "Cognito JWT Name" },
  { name: "unverified email", claims: { email_verified: false }, expected: "Cognito JWT Name" },
  {
    name: "missing verified email",
    claims: { email_verified: undefined },
    expected: "Cognito JWT Name",
  },
] as const;
for (const mapping of mappings) {
  compatScenario(
    `cognito signed ID-token ${mapping.name} persists exact identity and retains foreign authority`,
    async (ctx) => {
      const other = await foreign(ctx),
        actor = ctx.actor("cognito", "social-cognito-default"),
        token = await proof(ctx, mapping.claims),
        result = await actor.client.signIn.social({ provider: "cognito", idToken: { token } });
      expect(result.error).toBeNull();
      const after = await state(ctx);
      unchangedForeign(other.before, after);
      expect(after.users).toHaveLength(other.before.users.length + 1);
      expect(after.accounts).toHaveLength(other.before.accounts.length + 1);
      expect(after.sessions).toHaveLength(other.before.sessions.length + 1);
      const user = after.users.find((row) => !other.before.users.some((old) => old.id === row.id))!,
        account = after.accounts.find((row) => row.userId === user.id)!;
      expect(user.name).toBe(mapping.expected);
      expect(user.emailVerified).toBe(
        !["unverified email", "missing verified email"].includes(mapping.name),
      );
      expect(user.image).toBe(
        mapping.name === "empty image"
          ? ""
          : mapping.name === "missing image" || mapping.name === "null image"
            ? null
            : "https://images.example.invalid/cognito.png",
      );
      expect(account).toMatchObject({
        providerId: "cognito",
        accountId:
          mapping.name === "numeric subject"
            ? "42"
            : JSON.parse(Buffer.from(token.split(".")[1]!, "base64url").toString()).sub,
        idToken: token,
      });
      const session = await actor.client.getSession();
      expect(session.data?.user.id).toBe(user.id);
      return {
        foreign: ctx.snapshot(other.signup),
        result: ctx.snapshot(result),
        before: other.before,
        after,
        session: ctx.snapshot(session),
        receipts: await receipts(ctx),
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
  "future",
  "nonce",
  "hashed-nonce",
  "unknown-kid",
  "missing-subject",
  "null-subject",
  "blank-subject",
  "missing-email",
  "null-email",
  "empty-email",
  "disabled",
  "implicit-disabled",
] as const) {
  compatScenario(
    `cognito signed admission rejects ${variant} without user account or session writes`,
    async (ctx) => {
      const other = await foreign(ctx),
        nonce = "cognito-request-nonce",
        hash = Buffer.from(
          await crypto.subtle.digest("SHA-256", new TextEncoder().encode(nonce)),
        ).toString("hex"),
        claims: Row =
          variant === "issuer"
            ? { iss: "https://untrusted.invalid" }
            : variant === "audience"
              ? { aud: "foreign-client" }
              : variant === "expired"
                ? { exp: issuedAt - 10 }
                : variant === "old"
                  ? { iat: issuedAt - 7200 }
                  : variant === "future"
                    ? { iat: issuedAt + 7200 }
                    : variant === "nonce"
                      ? { nonce: "wrong-nonce" }
                      : variant === "hashed-nonce"
                        ? { nonce: hash }
                        : variant === "missing-subject"
                          ? { sub: undefined }
                          : variant === "null-subject"
                            ? { sub: null }
                            : variant === "blank-subject"
                              ? { sub: "\uFEFF " }
                              : variant === "missing-email"
                                ? { email: undefined }
                                : variant === "null-email"
                                  ? { email: null }
                                  : variant === "empty-email"
                                    ? { email: "" }
                                    : {};
      const token = await proof(
          ctx,
          claims,
          variant === "unknown-kid" ? { kid: "foreign-kid" } : {},
          variant === "signature",
        ),
        profile: FixtureProfile =
          variant === "disabled"
            ? "social-cognito-disabled-idtoken"
            : variant === "implicit-disabled"
              ? "social-cognito-implicit-disabled"
              : "social-cognito-default",
        actor = ctx.actor("cognito", profile),
        result = await actor.client.signIn.social({
          provider: "cognito",
          idToken: { token, ...(variant.includes("nonce") ? { nonce } : {}) },
        });
      expect(result.error).not.toBeNull();
      expect(result.error?.code).toBe(
        variant === "disabled"
          ? "ID_TOKEN_NOT_SUPPORTED"
          : variant === "implicit-disabled"
            ? "OAUTH_LINK_ERROR"
            : variant.endsWith("email")
              ? "USER_EMAIL_NOT_FOUND"
              : variant.endsWith("subject")
                ? "FAILED_TO_GET_USER_INFO"
                : "INVALID_TOKEN",
      );
      expect(await state(ctx)).toEqual(other.before);
      return {
        foreign: ctx.snapshot(other.signup),
        result: ctx.snapshot(result),
        before: other.before,
        after: await state(ctx),
        receipts: await receipts(ctx),
      };
    },
  );
}
for (const variant of ["exact-nonce", "client-array", "explicit-signup"] as const) {
  compatScenario(
    `cognito configured ${variant} uses genuine signed proof`,
    async (ctx) => {
      const token = await proof(
          ctx,
          variant === "client-array"
            ? { aud: ["foreign-client", "fixture-cognito-secondary"] }
            : variant === "exact-nonce"
              ? { nonce: "matching-nonce" }
              : {},
        ),
        profile: FixtureProfile =
          variant === "client-array"
            ? "social-cognito-client-array"
            : variant === "explicit-signup"
              ? "social-cognito-implicit-disabled"
              : "social-cognito-default",
        actor = ctx.actor("cognito", profile),
        result = await actor.client.signIn.social({
          provider: "cognito",
          requestSignUp: variant === "explicit-signup",
          idToken: { token, ...(variant === "exact-nonce" ? { nonce: "matching-nonce" } : {}) },
        });
      expect(result.error).toBeNull();
      const stored = await state(ctx);
      expect(stored.users).toHaveLength(1);
      expect(stored.accounts).toHaveLength(1);
      expect(stored.sessions).toHaveLength(1);
      expect(stored.accounts[0]!.idToken).toBe(token);
      return { result: ctx.snapshot(result), stored, receipts: await receipts(ctx) };
    },
    ["POST /sign-in/social"],
  );
}

for (const mode of ["default", "public", "mapped", "configured-endpoint", "client-key"] as const)
  compatScenario(
    `cognito ${mode} real exchange refresh replay and logout retain account and foreign authority`,
    async (ctx) => {
      const other = await foreign(ctx),
        original = userProfile(ctx);
      await control(ctx, { profile: original });
      const profile: FixtureProfile = `social-cognito-${mode}`,
        flow = await callback(ctx, profile);
      expect(flow.response.status).toBe(302);
      expect(flow.response.headers.get("location")).toBe("/dashboard");
      const session = await flow.actor.client.getSession();
      expect(session.error).toBeNull();
      const after = await state(ctx);
      unchangedForeign(other.before, after);
      for (const key of ["users", "accounts", "sessions"] as const)
        expect(after[key]).toHaveLength(other.before[key].length + 1);
      const user = after.users.find((row) => !other.before.users.some((old) => old.id === row.id))!,
        account = after.accounts.find((row) => row.userId === user.id)!;
      expect(user).toMatchObject({
        name: mode === "mapped" ? "Mapped HTTP Given Name" : "HTTP Given Name",
        email: mode === "mapped" ? "mapped-cognito@example.invalid" : original.email,
        emailVerified: mode !== "mapped",
        image:
          mode === "mapped"
            ? "https://images.example.invalid/mapped-cognito.png"
            : original.picture,
      });
      expect(account).toMatchObject({
        providerId: "cognito",
        accountId: original.sub,
        accessToken: "fixture-cognito-access",
        refreshToken: "fixture-cognito-refresh",
        idToken: null,
        scope: "",
      });
      expect(account.accessTokenExpiresAt).toBeTruthy();
      expect(session.data?.user.id).toBe(user.id);
      const raw = (await ctx.rawRequest({ path: "/__test/cognito/receipts" })).body as Array<{
          path: string;
          authorization: string | null;
          contentType: string | null;
          body: Record<string, string> | null;
        }>,
        exchange = raw[0]!.body!,
        verifier = exchange.code_verifier!;
      expect(verifier).toHaveLength(128);
      expect(flow.url.searchParams.get("code_challenge")).toBe(
        Buffer.from(
          await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier)),
        ).toString("base64url"),
      );
      expect(exchange).toEqual({
        grant_type: "authorization_code",
        code: "fixture-code",
        code_verifier: verifier,
        ...(mode === "client-key" ? { client_key: "fixture-cognito-client-key" } : {}),
        client_id: "fixture-social-client",
        ...(mode === "public" ? {} : { client_secret: "fixture-social-secret" }),
        redirect_uri:
          mode === "configured-endpoint"
            ? "https://client.example.invalid/cognito-return"
            : ctx.baseURL + authProfilePath(profile) + "/callback/cognito",
      });
      expect(raw[0]!.authorization).toBeNull();
      expect(raw[1]).toMatchObject({
        path: "/userinfo",
        authorization: "Bearer fixture-cognito-access",
        body: null,
      });
      const mapper = (await ctx.rawRequest({ path: "/__test/cognito/mapper-receipts" })).body;
      expect(mapper).toEqual(mode === "mapped" ? [original] : []);
      const replay = await flow.actor.fetch(ctx.baseURL + flow.path, { redirect: "manual" });
      expect(replay.status).toBe(302);
      expect(
        new URL(replay.headers.get("location")!, ctx.baseURL).searchParams.get("error"),
      ).toBeTruthy();
      expect(await state(ctx)).toEqual(after);
      expect(await receipts(ctx)).toHaveLength(2);
      await control(ctx, {
        tokenResponse: {
          access_token: "fixture-cognito-access-rotated",
          refresh_token: "fixture-cognito-refresh-rotated",
          expires_in: 1800,
          scope: "new-scope openid",
        },
      });
      const denied = await other.actor.client.refreshToken({ accountId: account.id });
      expect(denied.error).not.toBeNull();
      expect(await state(ctx)).toEqual(after);
      expect(await receipts(ctx)).toHaveLength(2);
      const refreshed = await flow.actor.client.refreshToken({ accountId: account.id });
      expect(refreshed.error).toBeNull();
      const rotated = await state(ctx);
      expect(rotated.users).toEqual(after.users);
      expect(rotated.sessions).toEqual(after.sessions);
      unchangedForeign(other.before, rotated);
      expect(rotated.accounts.find((row) => row.id === account.id)).toMatchObject({
        accountId: original.sub,
        userId: user.id,
        accessToken: "fixture-cognito-access-rotated",
        refreshToken: "fixture-cognito-refresh-rotated",
        scope: account.scope,
      });
      const requests = await receipts(ctx);
      expect(requests[2]!.body).toEqual({
        grant_type: "refresh_token",
        refresh_token: "fixture-cognito-refresh",
        client_id: "fixture-social-client",
        ...(mode === "public" ? {} : { client_secret: "fixture-social-secret" }),
      });
      const signOut = await flow.actor.client.signOut();
      expect(signOut.error).toBeNull();
      expect((await flow.actor.client.getSession()).data).toBeNull();
      const signedOut = await state(ctx);
      expect(signedOut.users).toEqual(rotated.users);
      expect(signedOut.accounts).toEqual(rotated.accounts);
      expect(signedOut.sessions).toEqual(other.before.sessions);
      expect(await receipts(ctx)).toHaveLength(3);
      return {
        foreign: ctx.snapshot(other.signup),
        before: other.before,
        start: ctx.snapshot(flow.start),
        callback: { status: flow.response.status, location: flow.response.headers.get("location") },
        session: ctx.snapshot(session),
        after,
        replay: { status: replay.status, location: replay.headers.get("location") },
        denied: ctx.snapshot(denied),
        refreshed: ctx.snapshot(refreshed),
        rotated,
        signOut: ctx.snapshot(signOut),
        signedOut,
        mapper,
        receipts: requests,
      };
    },
    ["POST /sign-in/social", "GET /callback/{}", "POST /refresh-token", "POST /sign-out"],
  );
for (const expiry of ["absent", "zero", "fractional"] as const)
  compatScenario(
    `cognito ${expiry} expiry follows actual shared token response semantics`,
    async (ctx) => {
      await control(ctx, {
        profile: userProfile(ctx),
        tokenResponse: {
          access_token: "fixture-cognito-access",
          refresh_token: "fixture-cognito-refresh",
          scope: "openid custom-scope",
          ...(expiry === "zero"
            ? { expires_in: 0 }
            : expiry === "fractional"
              ? { expires_in: 0.5 }
              : {}),
        },
      });
      const flow = await callback(ctx);
      expect(flow.response.headers.get("location")).toBe("/dashboard");
      const stored = await state(ctx);
      expect(stored.accounts).toHaveLength(1);
      expect(stored.accounts[0]!.scope).toBe("openid,custom-scope");
      if (expiry === "fractional") expect(stored.accounts[0]!.accessTokenExpiresAt).toBeTruthy();
      else expect(stored.accounts[0]!.accessTokenExpiresAt).toBeNull();
      return {
        start: ctx.snapshot(flow.start),
        callback: { status: flow.response.status, location: flow.response.headers.get("location") },
        stored,
        receipts: await receipts(ctx),
      };
    },
    ["POST /sign-in/social", "GET /callback/{}"],
  );
for (const variant of [
  "decoded-idtoken",
  "malformed-idtoken",
  "mapped-decoded-idtoken",
  "array-idtoken",
  "null-idtoken",
  "number-idtoken",
] as const)
  compatScenario(
    `cognito ${variant} code exchange uses original ID profile or actual access-token fallback`,
    async (ctx) => {
      const fallback = [
          "malformed-idtoken",
          "array-idtoken",
          "null-idtoken",
          "number-idtoken",
        ].includes(variant),
        nonObject = ["array-idtoken", "null-idtoken", "number-idtoken"].includes(variant);
      const other = await foreign(ctx),
        original = userProfile(ctx),
        idToken = nonObject
          ? await nonObjectToken(
              variant === "array-idtoken" ? [] : variant === "null-idtoken" ? null : 42,
            )
          : variant === "malformed-idtoken"
            ? "malformed-token"
            : await proof(ctx, {
                name: null,
                given_name: "Decoded Given Name",
                originalApplicationField: { retained: true },
              });
      await control(ctx, { profile: original, idToken });
      const flow = await callback(
        ctx,
        variant === "mapped-decoded-idtoken" ? "social-cognito-mapped" : "social-cognito-default",
      );
      expect(flow.response.headers.get("location")).toBe("/dashboard");
      const stored = await state(ctx);
      unchangedForeign(other.before, stored);
      const user = stored.users.find(
          (row) => !other.before.users.some((old) => old.id === row.id),
        )!,
        account = stored.accounts.find((row) => row.userId === user.id)!;
      const decoded = fallback
        ? null
        : JSON.parse(Buffer.from(idToken.split(".")[1]!, "base64url").toString());
      expect(user.name).toBe(
        fallback
          ? "HTTP Given Name"
          : variant === "mapped-decoded-idtoken"
            ? "Mapped Decoded Given Name"
            : "Decoded Given Name",
      );
      expect(account).toMatchObject({ accountId: decoded?.sub ?? original.sub, idToken });
      expect((await flow.actor.client.getSession()).data?.user.id).toBe(user.id);
      const requests = await receipts(ctx);
      expect(requests.map((row) => (row as { path: string }).path)).toEqual(
        fallback ? ["/token", "/userinfo"] : ["/token"],
      );
      const mapper = (await ctx.rawRequest({ path: "/__test/cognito/mapper-receipts" })).body;
      expect(mapper).toEqual(
        variant === "mapped-decoded-idtoken" ? [{ ...decoded, name: "Decoded Given Name" }] : [],
      );
      return {
        before: other.before,
        start: ctx.snapshot(flow.start),
        callback: { status: flow.response.status, location: flow.response.headers.get("location") },
        stored,
        mapper,
        receipts: requests,
      };
    },
    ["POST /sign-in/social", "GET /callback/{}"],
  );
compatScenario(
  "cognito signed mapped profile retains enriched callback receipt and authenticated raw subject",
  async (ctx) => {
    const other = await foreign(ctx),
      token = await proof(ctx, {
        name: null,
        given_name: "Mapped Given Name",
        originalApplicationField: { retained: true },
      }),
      actor = ctx.actor("cognito", "social-cognito-mapped"),
      result = await actor.client.signIn.social({ provider: "cognito", idToken: { token } });
    expect(result.error).toBeNull();
    const stored = await state(ctx);
    unchangedForeign(other.before, stored);
    const decoded = JSON.parse(Buffer.from(token.split(".")[1]!, "base64url").toString()),
      user = stored.users.find((row) => !other.before.users.some((old) => old.id === row.id))!,
      account = stored.accounts.find((row) => row.userId === user.id)!;
    expect(user).toMatchObject({
      name: "Mapped Mapped Given Name",
      email: "mapped-cognito@example.invalid",
      emailVerified: false,
    });
    expect(account.accountId).toBe(decoded.sub);
    expect(account.accountId).not.toBe("cannot-replace-raw-subject");
    const mapper = (await ctx.rawRequest({ path: "/__test/cognito/mapper-receipts" })).body;
    expect(mapper).toEqual([{ ...decoded, name: "Mapped Given Name" }]);
    return {
      before: other.before,
      result: ctx.snapshot(result),
      stored,
      mapper,
      receipts: await receipts(ctx),
    };
  },
  ["POST /sign-in/social"],
);

for (const variant of ["valid", "missing", "null", "blank"] as const)
  compatScenario(
    `cognito application userinfo ${variant} retains raw profile account identity and callback-before-denial`,
    async (ctx) => {
      const other = await foreign(ctx),
        original = userProfile(ctx);
      if (variant === "missing") delete original.sub;
      if (variant === "null") original.sub = null;
      if (variant === "blank") original.sub = " ";
      await control(ctx, { profile: original });
      const token = await proof(ctx),
        actor = ctx.actor("cognito", "social-cognito-userinfo-override"),
        result = await actor.client.signIn.social({ provider: "cognito", idToken: { token } }),
        stored = await state(ctx),
        callbackProfiles = (
          await ctx.rawRequest({ path: "/__test/cognito/userinfo-profile-receipts" })
        ).body;
      expect(callbackProfiles).toEqual([original]);
      if (variant === "valid") {
        expect(result.error).toBeNull();
        unchangedForeign(other.before, stored);
        const user = stored.users.find(
            (row) => !other.before.users.some((old) => old.id === row.id),
          )!,
          account = stored.accounts.find((row) => row.userId === user.id)!;
        expect(user).toMatchObject({
          name: "Application Cognito User",
          email: original.email,
          emailVerified: true,
        });
        expect(account.accountId).toBe(original.sub);
        expect(account.accountId).not.toBe("cannot-replace-raw-subject");
        expect((await actor.client.getSession()).data?.user.id).toBe(user.id);
      } else {
        expect(result.error?.code).toBe("FAILED_TO_GET_USER_INFO");
        expect(stored).toEqual(other.before);
        expect((await actor.client.getSession()).data).toBeNull();
      }
      expect((await receipts(ctx)).map((row) => row.path)).toEqual(["/keys"]);
      return {
        before: other.before,
        result: ctx.snapshot(result),
        stored,
        callbackProfiles,
        receipts: await receipts(ctx),
      };
    },
    ["POST /sign-in/social"],
  );

compatScenario(
  "cognito configured endpoint replaces existing reserved query fields with actual state and PKCE",
  async (ctx) => {
    const other = await foreign(ctx),
      actor = ctx.actor("cognito", "social-cognito-query-overrides"),
      result = await actor.client.signIn.social({
        provider: "cognito",
        callbackURL: "/dashboard",
        additionalParams: { identity_provider: "RequestedIdentity", custom: "new value" },
      });
    expect(result.error).toBeNull();
    const url = new URL(result.data!.url!);
    expect(url.origin).toBe("https://alternate-cognito.example.invalid");
    for (const [key, value] of Object.entries({
      response_type: "code",
      client_id: "fixture-social-client",
      scope: "openid profile email",
      redirect_uri:
        ctx.baseURL + authProfilePath("social-cognito-query-overrides") + "/callback/cognito",
      code_challenge_method: "S256",
      identity_provider: "RequestedIdentity",
      custom: "new value",
      retained: "value",
    }))
      expect(url.searchParams.getAll(key)).toEqual([value]);
    for (const key of ["state", "code_challenge"]) {
      expect(url.searchParams.getAll(key)).toHaveLength(1);
      expect(url.searchParams.get(key)).toBeTruthy();
      expect(url.searchParams.get(key)).not.toBe("stale");
    }
    expect(await state(ctx)).toEqual(other.before);
    expect(await receipts(ctx)).toEqual([]);
    return { result: ctx.snapshot(result), before: other.before, after: await state(ctx) };
  },
  ["POST /sign-in/social"],
);

for (const variant of ["removed-key", "declared-algorithm", "first-duplicate-key"] as const)
  compatScenario(
    `cognito ${variant} rejects genuine proof until application JWKS is restored`,
    async (ctx) => {
      const other = await foreign(ctx),
        original = JSON.parse(
          await Bun.file(new URL("../../../../fixtures/one-tap/jwks.json", import.meta.url)).text(),
        ),
        wrong = createPublicKey(
          await Bun.file(
            new URL("../../../../fixtures/one-tap/wrong-private-key.pem", import.meta.url),
          ).text(),
        ).export({ format: "jwk" }),
        key = original.keys[0];
      await control(ctx, {
        keys: {
          keys:
            variant === "removed-key"
              ? []
              : variant === "declared-algorithm"
                ? [{ ...key, alg: "RS512" }]
                : [{ ...wrong, kid: key.kid, alg: "RS256" }, key],
        },
      });
      const token = await proof(ctx),
        actor = ctx.actor("cognito", "social-cognito-default"),
        denied = await actor.client.signIn.social({ provider: "cognito", idToken: { token } });
      expect(denied.error?.code).toBe("INVALID_TOKEN");
      expect(await state(ctx)).toEqual(other.before);
      expect((await actor.client.getSession()).data).toBeNull();
      expect((await receipts(ctx)).map((row) => row.path)).toEqual(["/keys"]);
      await control(ctx, {});
      const admitted = await actor.client.signIn.social({
        provider: "cognito",
        idToken: { token },
      });
      expect(admitted.error).toBeNull();
      const stored = await state(ctx);
      unchangedForeign(other.before, stored);
      for (const table of ["users", "accounts", "sessions"] as const)
        expect(stored[table]).toHaveLength(other.before[table].length + 1);
      const user = stored.users.find(
        (row) => !other.before.users.some((old) => old.id === row.id),
      )!;
      expect(stored.accounts.find((row) => row.userId === user.id)).toMatchObject({
        providerId: "cognito",
        accountId: JSON.parse(Buffer.from(token.split(".")[1]!, "base64url").toString()).sub,
        idToken: token,
      });
      expect((await actor.client.getSession()).data?.user.id).toBe(user.id);
      expect((await receipts(ctx)).map((row) => row.path)).toEqual(["/keys", "/keys"]);
      return {
        before: other.before,
        denied: ctx.snapshot(denied),
        admitted: ctx.snapshot(admitted),
        stored,
        receipts: await receipts(ctx),
      };
    },
    ["POST /sign-in/social"],
  );
for (const mode of ["required", "empty-clients"] as const)
  compatScenario(
    `cognito configured ${mode} authorization rejects absent credentials without provider or identity writes`,
    async (ctx) => {
      const other = await foreign(ctx),
        actor = ctx.actor("cognito", `social-cognito-${mode}`),
        result = await actor.client.signIn.social({ provider: "cognito" });
      expect(result.error?.status).toBe(500);
      expect(await state(ctx)).toEqual(other.before);
      expect(await receipts(ctx)).toEqual([]);
      return { before: other.before, result: ctx.snapshot(result), after: await state(ctx) };
    },
  );
compatScenario(
  "cognito disabled default scopes omit scope when none were requested",
  async (ctx) => {
    const before = await state(ctx),
      result = await ctx
        .actor("cognito", "social-cognito-disabled-scope")
        .client.signIn.social({ provider: "cognito" });
    expect(result.error).toBeNull();
    const url = new URL(result.data!.url!);
    expect(url.searchParams.has("scope")).toBeFalse();
    expect(await state(ctx)).toEqual(before);
    expect(await receipts(ctx)).toEqual([]);
    return { result: ctx.snapshot(result), stored: await state(ctx) };
  },
  ["POST /sign-in/social"],
);

compatScenario(
  "cognito existing account info reads original profile without applying new identity admission",
  async (ctx) => {
    const other = await foreign(ctx),
      original = userProfile(ctx);
    await control(ctx, { profile: original });
    const flow = await callback(ctx);
    expect(flow.response.headers.get("location")).toBe("/dashboard");
    const before = await state(ctx),
      user = before.users.find((row) => !other.before.users.some((old) => old.id === row.id))!,
      account = before.accounts.find((row) => row.userId === user.id)!;
    delete original.sub;
    await control(ctx, { profile: original });
    const result = await flow.actor.client.$fetch("/account-info", {
      query: { accountId: account.id },
    });
    expect(result.error).toBeNull();
    expect(result.data).toEqual({
      user: {
        name: "HTTP Given Name",
        email: original.email,
        image: original.picture,
        emailVerified: true,
      },
      data: original,
      account: { id: account.id, providerId: "cognito", accountId: account.accountId },
    });
    expect(await state(ctx)).toEqual(before);
    expect((await flow.actor.client.getSession()).data?.user.id).toBe(user.id);
    return {
      before,
      result: ctx.snapshot(result),
      after: await state(ctx),
      receipts: await receipts(ctx),
    };
  },
  ["GET /account-info"],
);

// A valid authorization starts each rejection owner. These controls alter only
// the actual remote response or callback input, preserving state/PKCE guards.
for (const variant of [
  "wrong-state",
  "wrong-provider",
  "token-http-error",
  "userinfo-http-error",
  "missing-subject",
  "null-subject",
  "blank-subject",
  "missing-email-and-subject",
  "signup-disabled",
  "implicit-disabled",
] as const)
  compatScenario(
    `cognito browser ${variant} denies without changing owned or foreign identity`,
    async (ctx) => {
      const other = await foreign(ctx),
        original = userProfile(ctx);
      if (variant === "missing-subject" || variant === "missing-email-and-subject")
        delete original.sub;
      if (variant === "null-subject") original.sub = null;
      if (variant === "blank-subject") original.sub = " ";
      if (variant === "missing-email-and-subject") delete original.email;
      await control(ctx, {
        profile: original,
        ...(variant === "token-http-error" ? { tokenStatus: 503 } : {}),
        ...(variant === "userinfo-http-error" ? { userInfoStatus: 503 } : {}),
      });
      const profile: FixtureProfile =
          variant === "signup-disabled"
            ? "social-cognito-signup-disabled"
            : variant === "implicit-disabled"
              ? "social-cognito-implicit-disabled"
              : "social-cognito-default",
        actor = ctx.actor("cognito", profile),
        start = await actor.client.signIn.social({
          provider: "cognito",
          callbackURL: "/dashboard",
          requestSignUp: variant === "signup-disabled",
        });
      expect(start.error).toBeNull();
      const authorization = new URL(start.data!.url!),
        callbackState =
          variant === "wrong-state"
            ? ctx.uniqueToken("wrong-state")
            : authorization.searchParams.get("state")!,
        provider = variant === "wrong-provider" ? "unknown-cognito" : "cognito",
        path =
          authProfilePath(profile) +
          `/callback/${provider}?code=fixture-code&state=${encodeURIComponent(callbackState)}`,
        response = await actor.fetch(ctx.baseURL + path, { redirect: "manual" });
      expect(response.status).toBe(302);
      const location = response.headers.get("location")!,
        error = new URL(location, ctx.baseURL).searchParams.get("error");
      expect(error).toBe(
        variant === "wrong-state"
          ? "state_mismatch"
          : variant === "wrong-provider"
            ? "oauth_provider_not_found"
            : variant === "token-http-error"
              ? "invalid_code"
              : variant.endsWith("disabled")
                ? "signup_disabled"
                : "unable_to_get_user_info",
      );
      expect(await state(ctx)).toEqual(other.before);
      expect((await actor.client.getSession()).data).toBeNull();
      const requests = await receipts(ctx);
      expect(requests.map((row) => row.path)).toEqual(
        ["wrong-state", "wrong-provider"].includes(variant)
          ? []
          : variant === "token-http-error"
            ? ["/token"]
            : ["/token", "/userinfo"],
      );
      return {
        before: other.before,
        start: ctx.snapshot(start),
        callback: { status: response.status, location },
        after: await state(ctx),
        receipts: requests,
      };
    },
    ["GET /callback/{}"],
  );

async function nonObjectToken(payload: unknown) {
  const header = Buffer.from(
      JSON.stringify({ alg: "RS256", typ: "JWT", kid: "one-tap-local-rs256" }),
    ).toString("base64url"),
    body = Buffer.from(JSON.stringify(payload)).toString("base64url"),
    input = `${header}.${body}`,
    privateKey = await Bun.file(
      new URL("../../../../fixtures/one-tap/private-key.pem", import.meta.url),
    ).text();
  return `${input}.${sign("RSA-SHA256", Buffer.from(input), privateKey).toString("base64url")}`;
}
