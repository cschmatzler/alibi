import { Database } from "bun:sqlite";
import { expect, test } from "bun:test";
import { createHmac } from "node:crypto";
import { betterAuth } from "better-auth";
import { getCookieCache } from "better-auth/cookies";
import { getMigrations } from "better-auth/db/migration";
import { type ComparisonContext, compareValues } from "../support/compare";
import { normalizeClientValue } from "../support/normalize";

const secret = "compact-cache-independent-fixture-secret-32";
type Atom = {
  token: string;
  envelope: any;
  decoded: any;
  observedAt: number;
  effectiveMaxAgeSeconds: number;
};
async function observe(baseURL: string, maxAge = 300.25, version?: string) {
  const database = new Database(":memory:");
  const options = {
    baseURL,
    secret,
    database,
    rateLimit: { enabled: false },
    emailAndPassword: { enabled: true },
    session: {
      cookieCache: {
        enabled: true,
        strategy: "compact" as const,
        maxAge,
        ...(version ? { version } : {}),
      },
    },
  };
  const { runMigrations } = await getMigrations(options);
  await runMigrations();
  const auth = betterAuth(options),
    start = Date.now();
  const response = await auth.handler(
    new Request(baseURL + "/api/auth/sign-up/email", {
      method: "POST",
      headers: { "content-type": "application/json", origin: baseURL },
      body: JSON.stringify({
        email: "real-cache-owner@fixture.test",
        name: "Actual Owner",
        password: "password123",
      }),
    }),
  );
  expect(response.status).toBe(200);
  const signup = await response.json();
  const values = response.headers
    .getSetCookie()
    .filter((value) => value.startsWith("better-auth.session_data"))
    .map((value) => value.split(";")[0]!);
  expect(values.length).toBeGreaterThan(0);
  const token = decodeURIComponent(
    values.map((value) => value.slice(value.indexOf("=") + 1)).join(""),
  );
  const envelope = JSON.parse(Buffer.from(token, "base64url").toString()),
    observedAt = Date.now();
  const decoded = await getCookieCache(new Headers({ cookie: values.join("; ") }), {
    secret,
    strategy: "compact",
    isSecure: false,
  });
  if (Number.isFinite(maxAge) && maxAge >= 0 && !version) {
    expect(decoded).not.toBeNull();
    expect(decoded!.user.id).toBe(signup.user.id);
    expect(decoded!.session.token).toBe(signup.token);
  } else expect(decoded).toBeNull();
  const atom = { token, envelope, decoded, observedAt, effectiveMaxAgeSeconds: maxAge },
    end = Date.now();
  database.close();
  return { signup, compactSessionCache: atom, start, end };
}
function context(
  left: Awaited<ReturnType<typeof observe>>,
  right: Awaited<ReturnType<typeof observe>>,
): ComparisonContext {
  return {
    leftBaseURL: "http://localhost:3100",
    rightBaseURL: "http://localhost:3200",
    leftStartedAt: left.start,
    rightStartedAt: right.start,
    leftFinishedAt: left.end,
    rightFinishedAt: right.end,
    compactSessionCacheSecret: secret,
  };
}
function values(value: Awaited<ReturnType<typeof observe>>) {
  return { signup: value.signup, compactSessionCache: value.compactSessionCache };
}
function signed(atom: Atom, change: (envelope: any) => void): Atom {
  const envelope = structuredClone(atom.envelope);
  change(envelope);
  envelope.signature = createHmac("sha256", secret)
    .update(JSON.stringify({ ...envelope.session, expiresAt: envelope.expiresAt }))
    .digest("base64url");
  return {
    ...atom,
    token: Buffer.from(JSON.stringify(envelope)).toString("base64url"),
    envelope,
    decoded: normalizeClientValue(envelope.session),
  };
}

test("real published compact cache cookies compare complete authenticated claims across independent issuance clocks", async () => {
  const left = await observe("http://localhost:3100"),
    right = await observe("http://localhost:3200");
  expect(left.compactSessionCache.token).not.toBe(right.compactSessionCache.token);
  expect(compareValues(values(left), values(right), context(left, right))).toEqual([]);
  expect(
    compareValues(values(left), values(right), {
      ...context(left, right),
      compactSessionCacheSecret: undefined,
    }).length,
  ).toBeGreaterThan(0);
});
test("compact cache atom catches authentic ownership token lifetime rotation and full-copy corruption", async () => {
  const left = await observe("http://localhost:3100"),
    right = await observe("http://localhost:3200"),
    ctx = context(left, right),
    a = values(left),
    b = values(right),
    original = right.compactSessionCache;
  const arrayLeft = signed(left.compactSessionCache, (v) => {
      v.session.extra = ["first", "second"];
    }),
    arrayRight = signed(original, (v) => {
      v.session.extra = ["first", "second"];
    });
  for (const atom of [arrayLeft, arrayRight])
    atom.decoded = await getCookieCache(
      new Headers({ cookie: `better-auth.session_data=${atom.token}` }),
      { secret, strategy: "compact", isSecure: false },
    );
  expect(arrayRight.decoded.extra).toEqual(["first", "second"]);
  expect(
    compareValues(
      { ...a, compactSessionCache: arrayLeft },
      { ...b, compactSessionCache: arrayRight },
      ctx,
    ),
  ).toEqual([]);
  for (const extra of [["second", "first"], ["first"], ["first", "second", "extra"]])
    expect(
      compareValues(
        { ...a, compactSessionCache: arrayLeft },
        {
          ...b,
          compactSessionCache: signed(original, (v) => {
            v.session.extra = extra;
          }),
        },
        ctx,
      ).length,
    ).toBeGreaterThan(0);
  for (const mutate of [
    (v: any) => {
      v.session.user.id = "wrong-owner";
    },
    (v: any) => {
      v.session.session.userId = "wrong-owner";
    },
    (v: any) => {
      v.session.session.token = "wrong-token";
    },
    (v: any) => {
      v.session.version = "wrong-version";
    },
    (v: any) => {
      v.expiresAt += 999999;
    },
    (v: any) => {
      v.expiresAt -= 999999;
    },
    (v: any) => {
      v.session.user.name = "Changed literal owner";
    },
    (v: any) => {
      v.session.extra = ["retained", "extra"];
    },
  ])
    expect(
      compareValues(a, { ...b, compactSessionCache: signed(original, mutate) }, ctx).length,
    ).toBeGreaterThan(0);
  for (const bad of [
    { ...original, effectiveMaxAgeSeconds: original.effectiveMaxAgeSeconds + 0.001 },
    { ...original, effectiveMaxAgeSeconds: original.effectiveMaxAgeSeconds - 0.001 },
    { ...original, token: original.token + "=" },
    {
      ...original,
      token: original.token.slice(0, -1) + (original.token.endsWith("A") ? "B" : "A"),
    },
    { ...original, envelope: { ...original.envelope, expiresAt: original.envelope.expiresAt + 1 } },
    { ...original, decoded: { ...original.decoded, version: "copied-decoder" } },
    { ...original, decoded: null },
    { ...original, envelope: { ...original.envelope, extra: "unsigned-outer" } },
    { ...original, observedAt: original.envelope.expiresAt + 1 },
    { ...original, unexpected: "extra-container" },
  ])
    expect(compareValues(a, { ...b, compactSessionCache: bad }, ctx).length).toBeGreaterThan(0);
  expect(
    compareValues(
      { ...a, repeated: { compactSessionCache: a.compactSessionCache } },
      { ...b, repeated: { compactSessionCache: b.compactSessionCache } },
      ctx,
    ),
  ).toEqual([]);
  expect(
    compareValues(
      { ...a, repeated: { compactSessionCache: a.compactSessionCache } },
      {
        ...b,
        repeated: {
          compactSessionCache: signed(original, (v) => {
            v.session.session.token = "actual-changed-session-token";
          }),
        },
      },
      ctx,
    ).some((d) => d.reason.includes("rotation")),
  ).toBe(true);
  for (const wrap of [
    (v: any) => ({ applicationData: v }),
    (v: any) => ({ metadata: v }),
    (v: any) => ({ additionalFields: v }),
    (v: any) => ({ traces: [{ responseBodyShape: v }] }),
  ])
    expect(compareValues(wrap(a), wrap(b), ctx).length).toBeGreaterThan(0);
});
test("valid retained compact cache observation stays valid after scenario end while actual expired decoder remains literal", async () => {
  const left = await observe("http://localhost:3100"),
    right = await observe("http://localhost:3200");
  const ctx = {
    ...context(left, right),
    leftFinishedAt: left.compactSessionCache.envelope.expiresAt + 1,
    rightFinishedAt: right.compactSessionCache.envelope.expiresAt + 1,
  };
  expect(compareValues(values(left), values(right), ctx)).toEqual([]);
  const expired = signed(right.compactSessionCache, (v) => {
    v.expiresAt = right.compactSessionCache.observedAt - 1;
  });
  const decoder = await getCookieCache(
    new Headers({ cookie: `better-auth.session_data=${expired.token}` }),
    { secret, strategy: "compact", isSecure: false },
  );
  expect(decoder).toBeNull();
  expect(
    compareValues(
      values(left),
      { ...values(right), compactSessionCache: { ...expired, decoded: decoder } },
      ctx,
    ).length,
  ).toBeGreaterThan(0);
});

test("genuine published negative and nonfinite cache expiry preserves authenticated null decoders and every claim", async () => {
  for (const [ttl, version] of [
    [-1, undefined],
    [-Infinity, undefined],
    [300.25, "2025-01-01T00:00:00.000Z"],
  ] as const) {
    const left = await observe("http://localhost:3100", ttl, version),
      right = await observe("http://localhost:3200", ttl, version);
    expect(left.compactSessionCache.decoded).toBeNull();
    expect(right.compactSessionCache.decoded).toBeNull();
    expect(compareValues(values(left), values(right), context(left, right))).toEqual([]);
    const forged = {
      ...right.compactSessionCache,
      envelope: { ...right.compactSessionCache.envelope, signature: "A".repeat(43) },
    };
    forged.token = Buffer.from(JSON.stringify(forged.envelope)).toString("base64url");
    expect(
      compareValues(
        values(left),
        { ...values(right), compactSessionCache: forged },
        context(left, right),
      ).length,
    ).toBeGreaterThan(0);
  }
});

test("compact authentication rejects declared nonfinite copies of the actual nullable JSON claims", async () => {
  const left = await observe("http://localhost:3100"),
    right = await observe("http://localhost:3200");
  expect(left.compactSessionCache.envelope.session.user.image).toBeNull();
  expect(right.compactSessionCache.envelope.session.user.image).toBeNull();
  for (const invalid of [Infinity, -Infinity, NaN, undefined])
    for (const field of ["envelope", "decoded", "both"]) {
      const wrongCopy = (value: typeof left) => {
        const atom: Atom = structuredClone(value.compactSessionCache);
        if (field !== "decoded") atom.envelope.session.user.image = invalid;
        if (field !== "envelope") atom.decoded.user.image = invalid;
        return { ...values(value), compactSessionCache: atom };
      };
      expect(
        compareValues(wrongCopy(left), wrongCopy(right), context(left, right)).length,
      ).toBeGreaterThan(0);
    }
});
