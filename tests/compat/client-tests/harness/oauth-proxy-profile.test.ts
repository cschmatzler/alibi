import { expect, test } from "bun:test";
import { symmetricDecrypt, symmetricEncrypt } from "better-auth/crypto";
import { type ComparisonContext, compareValues } from "../support/compare";

const secret = "local-fixture-dedicated-oauth-proxy-secret-32";
const leftBaseURL = "http://localhost:3100",
  rightBaseURL = "http://localhost:3200";
type Payload = Record<string, any>;
async function issue(baseURL: string) {
  const start = Date.now();
  const payload: Payload = {
    userInfo: { id: "777", email: "proxy-owner@fixture.test", name: "Owner", emailVerified: true },
    profile: {
      id: 777,
      state: "active",
      custom: { token: "literal-provider-token", id: "literal-provider-id" },
    },
    scopes: ["read_user", "profile"],
    account: {
      providerId: "gitlab",
      accountId: "777",
      accessToken: "provider-access",
      refreshToken: "provider-refresh",
      scope: "read_user,profile",
      accessTokenExpiresAt: new Date(Date.now() + 3_600_000).toISOString(),
    },
    state: crypto.randomUUID(),
    callbackURL: baseURL + "/complete?application=kept",
    newUserURL: baseURL + "/new",
    errorURL: baseURL + "/error",
    disableSignUp: false,
    timestamp: Date.now(),
  };
  const token = await symmetricEncrypt({ key: secret, data: JSON.stringify(payload) });
  const decrypted = JSON.parse(await symmetricDecrypt({ key: secret, data: token }));
  expect(decrypted).toEqual(payload);
  const url = new URL(
    baseURL + "/__test/profiles/oauth-proxy/api/auth/callback/gitlab/oauth-proxy",
  );
  url.searchParams.append("callbackURL", payload.callbackURL);
  url.searchParams.append("profile", token);
  url.searchParams.append("retained", "one");
  url.searchParams.append("retained", "two");
  url.hash = "#application-fragment";
  return {
    oauthProxyProfile: { token, payload: decrypted },
    location: url.toString(),
    start,
    finish: Date.now(),
  };
}
function values(value: Awaited<ReturnType<typeof issue>>) {
  return { oauthProxyProfile: value.oauthProxyProfile, location: value.location };
}
function context(
  left: Awaited<ReturnType<typeof issue>>,
  right: Awaited<ReturnType<typeof issue>>,
): ComparisonContext {
  return {
    leftBaseURL,
    rightBaseURL,
    leftStartedAt: left.start,
    rightStartedAt: right.start,
    leftFinishedAt: left.finish,
    rightFinishedAt: right.finish,
    oauthProxyProfileSecret: secret,
  };
}
async function mutate(
  value: Awaited<ReturnType<typeof issue>>,
  change: (payload: Payload) => void,
) {
  const payload = structuredClone(value.oauthProxyProfile.payload);
  change(payload);
  const token = await symmetricEncrypt({ key: secret, data: JSON.stringify(payload) });
  const actual = JSON.parse(await symmetricDecrypt({ key: secret, data: token }));
  const url = new URL(value.location);
  url.searchParams.set("profile", token);
  return { ...value, oauthProxyProfile: { token, payload: actual }, location: url.toString() };
}

test("published authenticated OAuth proxy ciphertext links only complete claims and its own callback URL", async () => {
  const left = await issue(leftBaseURL),
    right = await issue(rightBaseURL),
    ctx = context(left, right);
  expect(left.oauthProxyProfile.token).not.toBe(right.oauthProxyProfile.token);
  expect(compareValues(values(left), values(right), ctx)).toEqual([]);
  expect(
    compareValues(values(left), values(right), { ...ctx, oauthProxyProfileSecret: undefined })
      .length,
  ).toBeGreaterThan(0);
  expect(
    compareValues(values(left), values(right), {
      ...ctx,
      oauthProxyProfileSecret: "wrong-fixture-secret",
    }).length,
  ).toBeGreaterThan(0);
  const defaultRoute = (value: typeof left) => ({
    ...values(value),
    location: value.location.replace("/__test/profiles/oauth-proxy", ""),
  });
  expect(compareValues(defaultRoute(left), defaultRoute(right), ctx)).toEqual([]);
  const legacyRoute = (value: typeof left) => ({
    ...values(value),
    location: value.location.replace("/callback/gitlab/oauth-proxy", "/oauth-proxy-callback"),
  });
  expect(compareValues(legacyRoute(left), legacyRoute(right), ctx)).toEqual([]);
  const unknownLiteral = {
    location: leftBaseURL + "/api/auth/callback/gitlab/oauth-proxy?profile=literal",
  };
  expect(
    compareValues(
      unknownLiteral,
      { location: rightBaseURL + "/api/auth/callback/gitlab/oauth-proxy?profile=literal" },
      ctx,
    ),
  ).toEqual([]);
});

test("proxy authentication retains provider JSON claims arrays expiry state and every callback selector", async () => {
  const left = await issue(leftBaseURL),
    right = await issue(rightBaseURL),
    ctx = context(left, right),
    a = values(left);
  for (const change of [
    (p: Payload) => {
      p.userInfo.id = "888";
    },
    (p: Payload) => {
      p.account.accountId = "888";
    },
    (p: Payload) => {
      p.profile.custom.token = "changed-literal";
    },
    (p: Payload) => {
      p.profile.custom.id = "changed-literal";
    },
    (p: Payload) => {
      p.account.providerId = "google";
    },
    (p: Payload) => {
      p.account.accessToken = "changed-access";
    },
    (p: Payload) => {
      p.scopes.reverse();
    },
    (p: Payload) => {
      p.scopes.pop();
    },
    (p: Payload) => {
      p.scopes.push("additional");
    },
    (p: Payload) => {
      delete p.newUserURL;
    },
    (p: Payload) => {
      p.extraClaim = { retained: true };
    },
    (p: Payload) => {
      p.timestamp += 100_000;
    },
    (p: Payload) => {
      p.account.accessTokenExpiresAt = new Date(Date.now() + 86_400_000).toISOString();
    },
    (p: Payload) => {
      p.callbackURL = "https://foreign.fixture.test/leak";
    },
  ])
    expect(compareValues(a, values(await mutate(right, change)), ctx).length).toBeGreaterThan(0);
  const linkedLeft = { ...a, originalState: { state: left.oauthProxyProfile.payload.state } };
  const linkedRight = {
    ...values(right),
    originalState: { state: right.oauthProxyProfile.payload.state },
  };
  expect(compareValues(linkedLeft, linkedRight, ctx)).toEqual([]);
  const wrongState = await mutate(right, (p) => {
    p.state = "wrong-state";
  });
  expect(
    compareValues(
      linkedLeft,
      { ...values(wrongState), originalState: linkedRight.originalState },
      ctx,
    ).length,
  ).toBeGreaterThan(0);
  for (const change of [
    (u: URL) => {
      u.username = "changed-userinfo";
    },
    (u: URL) => {
      u.password = "changed-password";
    },
    (u: URL) => {
      u.host = "foreign.fixture.test";
    },
    (u: URL) => {
      u.pathname = u.pathname.replace("gitlab", "google");
    },
    (u: URL) => {
      u.pathname = "/arbitrary/oauth-proxy";
    },
    (u: URL) => {
      u.protocol = "https:";
    },
    (u: URL) => {
      u.searchParams.delete("callbackURL");
    },
    (u: URL) => {
      u.searchParams.delete("profile");
    },
    (u: URL) => {
      u.searchParams.append("profile", right.oauthProxyProfile.token);
    },
    (u: URL) => {
      u.searchParams.set("retained", "changed");
    },
    (u: URL) => {
      u.hash = "#changed";
    },
  ]) {
    const url = new URL(right.location);
    change(url);
    expect(
      compareValues(a, { ...values(right), location: url.toString() }, ctx).length,
    ).toBeGreaterThan(0);
  }
});

test("proxy atom rejects ciphertext copy tampering substituted URL tokens rotation and application JSON bypass", async () => {
  const left = await issue(leftBaseURL),
    right = await issue(rightBaseURL),
    ctx = context(left, right),
    a = values(left),
    b = values(right),
    atom = right.oauthProxyProfile;
  for (const bad of [
    { ...atom, token: atom.token.slice(0, -2) + (atom.token.endsWith("00") ? "01" : "00") },
    { ...atom, token: atom.token + "00" },
    { ...atom, token: "$ba$0$" + atom.token },
    { ...atom, payload: { ...atom.payload, disableSignUp: true } },
    { ...atom, payload: null },
    { ...atom, unexpected: "extra" },
    { ...atom, payload: { ...atom.payload, extra: undefined } },
  ])
    expect(compareValues(a, { ...b, oauthProxyProfile: bad }, ctx).length).toBeGreaterThan(0);
  const secondLeft = await issue(leftBaseURL),
    secondRight = await issue(rightBaseURL);
  const completeContext = {
    ...ctx,
    leftFinishedAt: secondLeft.finish,
    rightFinishedAt: secondRight.finish,
  };
  expect(
    compareValues(
      { first: a, second: values(secondLeft) },
      { first: b, second: values(secondRight) },
      completeContext,
    ),
  ).toEqual([]);
  const substituted = new URL(secondRight.location);
  substituted.searchParams.set("profile", right.oauthProxyProfile.token);
  expect(
    compareValues(
      { first: a, second: values(secondLeft) },
      { first: b, second: { ...values(secondRight), location: substituted.toString() } },
      completeContext,
    ).some((d) => d.reason.includes("rotation")),
  ).toBe(true);
  const repeatedLeft = { first: a, repeated: a },
    repeatedRight = { first: b, repeated: b };
  expect(compareValues(repeatedLeft, repeatedRight, ctx)).toEqual([]);
  expect(
    compareValues(repeatedLeft, { first: b, repeated: values(secondRight) }, completeContext).some(
      (d) => d.reason.includes("rotation"),
    ),
  ).toBe(true);
  for (const wrap of [
    (v: unknown) => ({ metadata: v }),
    (v: unknown) => ({ additionalFields: v }),
    (v: unknown) => ({ applicationData: v }),
    (v: unknown) => ({ traces: [{ responseBodyShape: v }] }),
  ]) {
    expect(compareValues(wrap(a), wrap(b), ctx).length).toBeGreaterThan(0);
  }
  const unrelatedLeft = {
    oauthProxyProfile: left.oauthProxyProfile,
    arbitrary: { profile: left.oauthProxyProfile.token },
  };
  const unrelatedRight = {
    oauthProxyProfile: right.oauthProxyProfile,
    arbitrary: { profile: right.oauthProxyProfile.token },
  };
  expect(compareValues(unrelatedLeft, unrelatedRight, ctx).length).toBeGreaterThan(0);
});

test("authenticated schema-invalid provider-mismatch and expired proxy inputs remain full rejection evidence", async () => {
  const left = await issue(leftBaseURL),
    right = await issue(rightBaseURL),
    ctx = context(left, right);
  for (const offset of [-61_000, 11_000]) {
    const a = await mutate(left, (p) => {
      p.timestamp += offset;
    });
    const b = await mutate(right, (p) => {
      p.timestamp += offset;
    });
    expect(compareValues(values(a), values(b), ctx)).toEqual([]);
  }
  const wrongProvider = (value: typeof left) => ({
    ...values(value),
    location: value.location.replace("/callback/gitlab/", "/callback/google/"),
  });
  expect(compareValues(wrongProvider(left), wrongProvider(right), ctx)).toEqual([]);
  expect(compareValues(wrongProvider(left), values(right), ctx).length).toBeGreaterThan(0);
  const malformed = async (value: typeof left) => {
    const token = await symmetricEncrypt({ key: secret, data: "{}" });
    const payload = JSON.parse(await symmetricDecrypt({ key: secret, data: token }));
    expect(payload).toEqual({});
    const location = new URL(value.location);
    location.searchParams.set("profile", token);
    return { oauthProxyProfile: { token, payload }, location: location.toString() };
  };
  const malformedLeft = await malformed(left),
    malformedRight = await malformed(right);
  expect(compareValues(malformedLeft, malformedRight, ctx)).toEqual([]);
  expect(
    compareValues(
      malformedLeft,
      {
        ...malformedRight,
        oauthProxyProfile: { ...malformedRight.oauthProxyProfile, payload: { fabricated: true } },
      },
      ctx,
    ).length,
  ).toBeGreaterThan(0);
  const nullCopyLeft = await mutate(left, (p) => {
    p.extra = null;
  });
  const nullCopyRight = await mutate(right, (p) => {
    p.extra = null;
  });
  expect(compareValues(values(nullCopyLeft), values(nullCopyRight), ctx)).toEqual([]);
  for (const extra of [NaN, Infinity, -Infinity, undefined]) {
    const copied = {
      ...nullCopyRight.oauthProxyProfile,
      payload: { ...nullCopyRight.oauthProxyProfile.payload, extra },
    };
    expect(
      compareValues(
        values(nullCopyLeft),
        { ...values(nullCopyRight), oauthProxyProfile: copied },
        ctx,
      ).length,
    ).toBeGreaterThan(0);
  }
});
