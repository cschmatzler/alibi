import { createHmac } from "node:crypto";

import { betterAuth } from "better-auth";
import { createAuthMiddleware } from "better-auth/api";
import { getCookieCache } from "better-auth/cookies";
import { getMigrations } from "better-auth/db/migration";
import { expect, test } from "vitest";

import { createDatabase } from "../../reference-server/sqlite.ts";
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

async function observe(
  baseURL: string,
  maxAge = 300.25,
  version?: string,
  captureDetached = false,
) {
  const database = createDatabase(":memory:");
  let detached: { headers: { cookie: string } } | undefined;
  const options = {
    baseURL,
    secret,
    database,
    rateLimit: { enabled: false },
    emailAndPassword: { enabled: true },
    ...(captureDetached
      ? {
          hooks: {
            after: createAuthMiddleware(async (ctx) => {
              if (ctx.path === "/sign-out") {
                detached = { headers: { cookie: ctx.headers!.get("cookie")! } };
              }
            }),
          },
        }
      : {}),
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
  const auth = betterAuth(options);
  const start = Date.now();
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
  const envelope = JSON.parse(Buffer.from(token, "base64url").toString());
  const observedAt = Date.now();
  const decoded = await getCookieCache(new Headers({ cookie: values.join("; ") }), {
    secret,
    strategy: "compact",
    isSecure: false,
  });

  if (Number.isFinite(maxAge) && maxAge >= 0 && !version) {
    expect(decoded).not.toBeNull();
    expect(decoded!.user.id).toBe(signup.user.id);
    expect(decoded!.session.token).toBe(signup.token);
  } else {
    expect(decoded).toBeNull();
  }

  const atom = { token, envelope, decoded, observedAt, effectiveMaxAgeSeconds: maxAge };
  if (captureDetached) {
    const output = await auth.api.signOut({ headers: new Headers({ cookie: values.join("; ") }) });
    expect(output.success).toBe(true);
    expect(output.url).toBeUndefined();
    expect(output.redirect).toBeUndefined();
    expect(detached).toBeDefined();
  }
  const end = Date.now();
  database.close();
  return {
    signup,
    detached,
    compactSessionCache: atom,
    start,
    end,
    rawCookies: response.headers.getSetCookie(),
  };
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
  const left = await observe("http://localhost:3100");
  const right = await observe("http://localhost:3200");
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
  const left = await observe("http://localhost:3100");
  const right = await observe("http://localhost:3200");
  const ctx = context(left, right);
  const a = values(left);
  const b = values(right);
  const original = right.compactSessionCache;
  const arrayLeft = signed(left.compactSessionCache, (v) => {
    v.session.extra = ["first", "second"];
  });
  const arrayRight = signed(original, (v) => {
    v.session.extra = ["first", "second"];
  });

  for (const atom of [arrayLeft, arrayRight]) {
    atom.decoded = await getCookieCache(
      new Headers({ cookie: `better-auth.session_data=${atom.token}` }),
      { secret, strategy: "compact", isSecure: false },
    );
  }

  expect(arrayRight.decoded.extra).toEqual(["first", "second"]);
  expect(
    compareValues(
      { ...a, compactSessionCache: arrayLeft },
      { ...b, compactSessionCache: arrayRight },
      ctx,
    ),
  ).toEqual([]);

  for (const extra of [["second", "first"], ["first"], ["first", "second", "extra"]]) {
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
  }

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
  ]) {
    expect(
      compareValues(a, { ...b, compactSessionCache: signed(original, mutate) }, ctx).length,
    ).toBeGreaterThan(0);
  }

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
  ]) {
    expect(compareValues(a, { ...b, compactSessionCache: bad }, ctx).length).toBeGreaterThan(0);
  }

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
  ]) {
    expect(compareValues(wrap(a), wrap(b), ctx).length).toBeGreaterThan(0);
  }
});

test("valid retained compact cache observation stays valid after scenario end while actual expired decoder remains literal", async () => {
  const left = await observe("http://localhost:3100");
  const right = await observe("http://localhost:3200");
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
    const left = await observe("http://localhost:3100", ttl, version);
    const right = await observe("http://localhost:3200", ttl, version);
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
  const left = await observe("http://localhost:3100");
  const right = await observe("http://localhost:3200");
  expect(left.compactSessionCache.envelope.session.user.image).toBeNull();
  expect(right.compactSessionCache.envelope.session.user.image).toBeNull();

  for (const invalid of [Infinity, -Infinity, NaN, undefined]) {
    for (const field of ["envelope", "decoded", "both"]) {
      const wrongCopy = (value: typeof left) => {
        const atom: Atom = structuredClone(value.compactSessionCache);

        if (field !== "decoded") {
          atom.envelope.session.user.image = invalid;
        }

        if (field !== "envelope") {
          atom.decoded.user.image = invalid;
        }

        return { ...values(value), compactSessionCache: atom };
      };
      expect(
        compareValues(wrongCopy(left), wrongCopy(right), context(left, right)).length,
      ).toBeGreaterThan(0);
    }
  }
});

test("logical getSession callback cache clocks require the exact authenticated input receipt", async () => {
  const left = await observe("http://localhost:3100", 300);
  const right = await observe("http://localhost:3200", 300);
  const window = (value: typeof left) => ({
    startedAt: value.start,
    finishedAt: value.end,
    inputDates: {},
    issuedSessionCookie: value.rawCookies
      .find((cookie) => cookie.startsWith("better-auth.session_token="))!
      .split(";")[0]!,
  });
  const ctx: ComparisonContext = {
    ...context(left, right),
    sessionCookieSecret: secret,
    leftRequestWindows: [window(left)],
    rightRequestWindows: [window(right)],
  };
  const observation = (value: typeof left) => {
    const headers = { cookie: value.rawCookies.map((cookie) => cookie.split(";")[0]).join("; ") };
    const session = normalizeClientValue(value.compactSessionCache.decoded);
    return {
      traces: [
        {
          method: "POST",
          path: "/api/auth/sign-up/email",
          responseStatus: 200,
          responseBody: value.signup,
        },
      ],
      observation: {
        compactSessionCache: {
          ...value.compactSessionCache,
          rawCookies: value.rawCookies.filter((cookie) =>
            cookie.startsWith("better-auth.session_data="),
          ),
        },
        read: {
          events: [
            {
              stage: "user-after",
              path: "/get-session",
              request: null,
              headers,
              session,
              current: {
                path: "/get-session",
                request: null,
                headers,
                session: structuredClone(session),
              },
            },
          ],
        },
      },
    };
  };
  const a = observation(left);
  const b = observation(right);
  expect(compareValues(a, b, ctx)).toEqual([]);
  for (const mutate of [
    (value: any) => {
      value.observation.read.events[0].session.updatedAt += 1;
    },
    (value: any) => {
      value.observation.read.events[0].current.session.updatedAt += 1;
    },
    (value: any) => {
      value.observation.read.events[0].session.user.name = "another owner";
    },
    (value: any) => {
      delete value.observation.compactSessionCache;
    },
    (value: any) => {
      value.observation.read.events[0].headers.cookie = "better-auth.session_data=unissued";
    },
  ]) {
    const bad = structuredClone(b);
    mutate(bad);
    expect(
      compareValues(a, bad, ctx).some(
        (difference) =>
          /\.events\.0\.(?:current\.)?session\.updatedAt$/.test(difference.path) &&
          difference.reason.includes("authenticated input cookie receipt"),
      ),
    ).toBe(true);
  }
});

test("cache-only request headers require real publication proof and preserve literal cookie scaffolding", async () => {
  const left = await observe("http://localhost:3100", 300, undefined, true);
  const right = await observe("http://localhost:3200", 300, undefined, true);
  const window = (value: typeof left) => ({
    startedAt: value.start,
    finishedAt: value.end,
    inputDates: {},
    issuedSessionCookie: value.rawCookies
      .find((raw) => raw.startsWith("better-auth.session_token="))!
      .split(";")[0]!,
  });
  const ctx: ComparisonContext = {
    ...context(left, right),
    sessionCookieSecret: secret,
    leftRequestWindows: [window(left)],
    rightRequestWindows: [window(right)],
  };
  const observation = (value: typeof left) => ({
    traces: [
      {
        method: "POST",
        path: "/api/auth/sign-up/email",
        responseStatus: 200,
        responseBody: value.signup,
      },
    ],
    observation: {
      compactSessionCache: {
        ...value.compactSessionCache,
        rawCookies: value.rawCookies.filter((raw) => raw.startsWith("better-auth.session_data=")),
      },
      detached: value.detached!,
    },
  });
  const a = observation(left);
  const b = observation(right);
  expect(compareValues(a, b, ctx)).toEqual([]);
  const rejectedHeader = (diffs: ReturnType<typeof compareValues>) =>
    expect(diffs.some((diff) => diff.path === "observation.detached.headers.cookie")).toBe(true);
  rejectedHeader(compareValues(a, b, { ...ctx, leftRequestWindows: [], rightRequestWindows: [] }));
  const { compactSessionCache, ...withoutPublication } = b.observation;
  expect(compactSessionCache.token).toBe(right.compactSessionCache.token);
  rejectedHeader(compareValues(a, { ...b, observation: withoutPublication }, ctx));
  for (const cookie of [
    b.observation.detached.headers.cookie + "=",
    b.observation.detached.headers.cookie + "; caller=changed",
    "better-auth.session_data=" +
      signed(right.compactSessionCache, (v) => {
        v.session.user.name = "Changed owner";
      }).token,
    b.observation.detached.headers.cookie + "; better-auth.session_data=unissued",
  ]) {
    rejectedHeader(
      compareValues(
        a,
        { ...b, observation: { ...b.observation, detached: { headers: { cookie } } } },
        ctx,
      ),
    );
  }
});
