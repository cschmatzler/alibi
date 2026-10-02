import { expect } from "bun:test";
import { createHash } from "node:crypto";

import { createAuthClient } from "better-auth/client";
import { oneTimeTokenClient, twoFactorClient } from "better-auth/client/plugins";
import { verifyPassword } from "better-auth/crypto";

import type { FixtureProfile } from "../../support/profiles";
import { authProfilePath } from "../../support/profiles";
import { compatScenario, type ScenarioContext } from "../../support/scenario";

type Row = Record<string, any>;

type State = {
  users: Row[];
  accounts: Row[];
  sessions: Row[];
  verifications: Row[];
  cache: Row[];
  events: Row[];
  cacheEvents: Row[];
  deliveries: Row[];
};

const sha = (value: string) => createHash("sha256").update(value).digest("base64url");
const profile = (mode: string) => `verification-storage-${mode}` as FixtureProfile;
const jsonDates = { createdAt: "2020-01-02T03:04:05.000Z", updatedAt: "2021-02-03T04:05:06.000Z" };

async function call(ctx: ScenarioContext, body: Row) {
  return ctx.rawRequest({
    path: "/__test/server-api/verification-storage",
    method: "POST",
    json: body,
  });
}

async function state(ctx: ScenarioContext): Promise<State> {
  const response = await call(ctx, { operation: "state" });
  expect(response.status).toBe(200);

  return response.body as State;
}

async function configure(ctx: ScenarioContext, action: Row = {}, fault: Row = {}) {
  const response = await call(ctx, { operation: "configure", action, fault });
  expect(response.status).toBe(200);
  return response;
}

function sql(s: State) {
  return {
    users: s.users,
    accounts: s.accounts,
    sessions: s.sessions,
    verifications: s.verifications,
  };
}

function observed(value: unknown): any {
  if (Array.isArray(value)) {
    return value.map(observed);
  }
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([key, child]) => {
        if (key === "password" && typeof child === "string" && child) {
          expect(child).toMatch(/^[a-f0-9]{32}:[a-f0-9]{128}$/);
          return [key, { token: child, encoding: "hex-lower", saltLength: 32, keyLength: 128 }];
        }
        return [key, observed(child)];
      }),
    );
  }
  return value;
}

async function foreign(ctx: ScenarioContext) {
  const result = await ctx.actor("storage-foreign").client.signUp.email({
    email: ctx.uniqueEmail("storage-foreign"),
    name: "Foreign verification principal",
    password: "foreign-password123",
  });
  expect(result.error).toBeNull();

  const physical = await state(ctx);
  const account = physical.accounts.find((row) => row.userId === result.data!.user.id)!;
  expect(
    await verifyPassword({ hash: String(account.password), password: "foreign-password123" }),
  ).toBe(true);

  return { result, physical: sql(physical) };
}

function unchanged(other: Awaited<ReturnType<typeof foreign>>, s: State) {
  for (const table of ["users", "accounts", "sessions"] as const) {
    expect(
      s[table].filter((row) => other.physical[table].some((old) => old.id === row.id)),
    ).toEqual(other.physical[table]);
  }
}

for (const mode of ["plain", "hashed", "custom", "ordered", "numeric", "cache", "mixed"] as const) {
  compatScenario(
    `verification storage ${mode} applies real identifier policy before hooks and physical/cache publication`,
    async (ctx) => {
      const other = await foreign(ctx);
      await configure(ctx);
      const identifier =
        mode === "ordered"
          ? "email-verification-policy-owner"
          : mode === "numeric"
            ? "12-numeric-policy-owner"
            : "verification-policy-owner";
      const stored = ["plain", "ordered", "numeric"].includes(mode)
        ? identifier
        : mode === "custom"
          ? `custom:${sha(identifier)}`
          : sha(identifier);
      const before = await state(ctx);
      const created = await call(ctx, {
        operation: "create",
        profile: profile(mode),
        identifier,
        data: { value: "actual-issued-proof", ...jsonDates },
      });
      expect(created.status).toBe(200);

      const candidate = created.body as Row;
      expect(candidate).toMatchObject({
        identifier: stored,
        value: "actual-issued-proof",
        ...jsonDates,
      });
      expect(Object.hasOwn(candidate, "id")).toBe(mode !== "cache");

      const admitted = await state(ctx);
      unchanged(other, admitted);
      expect(admitted.verifications).toHaveLength(mode === "cache" ? 0 : 1);
      expect(admitted.events.map((row) => row.stage)).toEqual(["create-before", "create-after"]);

      const { id: _physicalId, ...beforeData } = candidate;
      expect(admitted.events[0]!.data).toEqual(beforeData);
      expect(Object.hasOwn(admitted.events[0]!.data, "id")).toBe(false);
      expect(admitted.events[0]!.verifications).toEqual([]);
      expect(admitted.events[0]!.cache).toEqual([]);
      expect(admitted.events[1]!.data).toEqual(candidate);

      if (["cache", "mixed"].includes(mode)) {
        expect(admitted.cache).toHaveLength(1);
        expect(admitted.cache[0]).toMatchObject({
          key: `verification:${stored}`,
          value: candidate,
        });
        expect(admitted.cacheEvents).toEqual([
          { operation: "set", key: `verification:${stored}`, value: candidate, ttl: 60 },
        ]);
        expect(admitted.events[1]!.cache).toEqual(admitted.cache);
      } else {
        expect(admitted.cache).toEqual([]);
      }

      const found = await call(ctx, { operation: "find", profile: profile(mode), identifier });
      expect(found.body).toEqual(candidate);

      const consumed = await call(ctx, {
        operation: "consume",
        profile: profile(mode),
        identifier,
      });
      expect(consumed.body).toEqual(candidate);

      const replay = await call(ctx, { operation: "consume", profile: profile(mode), identifier });
      expect(replay.body).toBeNull();

      const after = await state(ctx);
      unchanged(other, after);
      expect(after.verifications).toEqual([]);
      expect(after.cache).toEqual([]);

      return observed({
        foreign: other,
        before,
        created,
        admitted,
        found,
        consumed,
        replay,
        after,
      });
    },
  );
}

compatScenario(
  "verification storage trusted creation mutation retains genuine ID dates and precomputed cache key",
  async (ctx) => {
    const other = await foreign(ctx);
    const mutation = {
      id: "trusted-storage-primary",
      identifier: "trusted-stored-identifier",
      value: "trusted-proof",
      createdAt: "2010-01-01T00:00:00.000Z",
      updatedAt: "2011-01-01T00:00:00.000Z",
    };
    await configure(ctx, { mutation });
    const identifier = "original-logical-identifier";
    const created = await call(ctx, {
      operation: "create",
      profile: profile("mixed"),
      identifier,
      data: { value: "original-proof", ...jsonDates },
    });
    expect(created.status).toBe(200);
    expect(created.body).toMatchObject(mutation);

    const s = await state(ctx);
    unchanged(other, s);
    expect(s.verifications).toEqual([created.body as Row]);
    expect(s.cache).toHaveLength(1);
    expect(s.cache[0]).toMatchObject({
      key: `verification:${sha(identifier)}`,
      value: created.body as Row,
    });
    expect(s.events[0]!.data).toMatchObject({
      identifier: sha(identifier),
      value: "original-proof",
      ...jsonDates,
    });
    expect(s.events[1]!.data).toEqual(created.body);

    const found = await call(ctx, { operation: "find", profile: profile("mixed"), identifier });
    expect(found.body).toEqual(created.body);

    return observed({ foreign: other, created, s, found });
  },
);

for (const mode of ["hashed", "cache", "mixed"] as const) {
  compatScenario(
    `verification storage ${mode} expired transformed winner blocks live legacy fallback after atomic invalidation`,
    async (ctx) => {
      const other = await foreign(ctx);
      await configure(ctx);
      const identifier = "legacy-fallback-owner";
      const past = {
        value: "expired-transformed",
        expiresAt: "2000-01-01T00:00:00.000Z",
        ...jsonDates,
      };
      const live = { value: "live-plain", expiresAt: "2100-01-01T00:00:00.000Z", ...jsonDates };
      const seeds = [];

      if (mode === "cache") {
        for (const [key, data] of [
          [sha(identifier), past],
          [identifier, live],
        ] as const) {
          seeds.push(
            await call(ctx, {
              operation: "cache-seed",
              key: `verification:${key}`,
              value: JSON.stringify({ identifier: key, ...data }),
            }),
          );
        }
      } else {
        seeds.push(await call(ctx, { operation: "seed", identifier: sha(identifier), data: past }));
        seeds.push(await call(ctx, { operation: "seed", identifier, data: live }));
      }

      const before = await state(ctx);
      const consumed = await call(ctx, {
        operation: "consume",
        profile: profile(mode),
        identifier,
      });
      expect(consumed.status).toBe(200);
      expect(consumed.body).toBeNull();

      const after = await state(ctx);
      unchanged(other, after);

      if (mode === "cache") {
        expect(after.cache).toEqual([]);
      } else {
        expect(after.verifications).toHaveLength(1);
        expect(after.verifications[0]!.identifier).toBe(identifier);
        expect(after.events.map((row) => row.stage)).toEqual(["delete-before", "delete-after"]);
      }

      const fallback = await call(ctx, {
        operation: "consume",
        profile: profile(mode),
        identifier,
      });
      expect(mode === "cache" ? fallback.body : (fallback.body as Row).value).toBe(
        mode === "cache" ? null : "live-plain",
      );

      return observed({
        foreign: other,
        seeds,
        before,
        consumed,
        after,
        fallback,
        final: await state(ctx),
      });
    },
  );
}

compatScenario(
  "verification storage cache find preserves truthy raw data while consume separately hydrates expiry and legacy fallback",
  async (ctx) => {
    const other = await foreign(ctx);
    const observations = [];
    const identifier = "cached-shape-owner";
    const key = `verification:${sha(identifier)}`;

    for (const [kind, raw, expected] of [
      [
        "ISO reviver",
        '{"value":"actual","expiresAt":"2100-02-30T24:00:00.1234Z","nested":{"createdAt":"2020-02-30T00:00:00.12345Z"}}',
        null,
      ],
      ["truthy scalar", '"opaque cache value"', null],
      ["empty object", "{}", null],
      ["invalid date", '{"value":"actual","expiresAt":"not a date"}', null],
      ["numeric future", '{"value":"actual","expiresAt":4102444800000}', "actual"],
      ["zero null expiry", '{"value":"actual","expiresAt":null}', null],
      ["numeric string legacy date", '{"value":"actual","expiresAt":"9999"}', "actual"],
    ] as const) {
      await configure(ctx);
      await call(ctx, { operation: "clear-cache" });
      const seeded = await call(ctx, { operation: "cache-seed", key, value: raw });
      const found = await call(ctx, { operation: "find", profile: profile("cache"), identifier });
      expect(found.status).toBe(200);
      expect(found.body).toBeTruthy();

      const consumed = await call(ctx, {
        operation: "consume",
        profile: profile("cache"),
        identifier,
      });
      expect(consumed.status).toBe(200);

      if (expected === null) {
        expect(consumed.body).toBeNull();
      } else {
        expect((consumed.body as Row).value).toBe(expected);
      }

      // Cached find deliberately accepts schema-invalid truthy JSON. Preserve its
      // entire returned body as JSON text rather than relabeling raw expiresAt as
      // a genuine Date for the ordinary timestamp contract.
      observations.push({
        kind,
        seeded,
        found: { ...found, body: { rawJSON: JSON.stringify(found.body) } },
        consumed,
        state: await state(ctx),
      });
    }

    unchanged(other, await state(ctx));
    return observed({ foreign: other, observations });
  },
);

for (const phase of ["cancel", "cache-error", "after-error"] as const) {
  compatScenario(
    `verification storage ${phase} preserves actual create publication and failure phases`,
    async (ctx) => {
      const other = await foreign(ctx);
      await configure(
        ctx,
        phase === "cancel"
          ? { "create-before": "cancel" }
          : phase === "after-error"
            ? { "create-after": "throw" }
            : {},
        phase === "cache-error" ? { set: true } : {},
      );
      const before = await state(ctx);
      const created = await call(ctx, {
        operation: "create",
        profile: profile("mixed"),
        identifier: "phase-owner",
        data: { value: "actual-proof", ...jsonDates },
      });
      const after = await state(ctx);
      unchanged(other, after);
      expect(created.status).toBe(phase === "cancel" ? 200 : 500);

      if (phase === "cancel") {
        expect(created.body).toBeNull();
        expect(sql(after)).toEqual(sql(before));
        expect(after.cache).toEqual([]);
      } else {
        expect(after.verifications).toHaveLength(1);
        expect(after.cache).toHaveLength(phase === "cache-error" ? 0 : 1);
      }

      expect(after.events.map((row) => row.stage)).toEqual(
        phase === "after-error" ? ["create-before", "create-after"] : ["create-before"],
      );

      return observed({ foreign: other, before, created, after });
    },
  );
}

compatScenario(
  "verification storage mixed update and deletion publish cache before actual database veto and do not mutate plain fallback",
  async (ctx) => {
    const other = await foreign(ctx);
    await configure(ctx);
    const identifier = "update-delete-owner";
    const created = await call(ctx, {
      operation: "create",
      profile: profile("mixed"),
      identifier,
      data: { value: "original", ...jsonDates },
    });
    expect(created.status).toBe(200);

    const seeded = await call(ctx, {
      operation: "seed",
      identifier,
      data: { value: "legacy-plain", ...jsonDates },
    });
    expect(seeded.status).toBe(200);

    await configure(ctx, { "update-before": "cancel" });
    const updated = await call(ctx, {
      operation: "update",
      profile: profile("mixed"),
      identifier,
      data: { value: "cached-patch" },
    });
    expect(updated.body).toBeNull();

    const patched = await state(ctx);
    unchanged(other, patched);
    expect(patched.verifications).toMatchObject([{ value: "original" }, { value: "legacy-plain" }]);
    expect(patched.cache[0]!.value.value).toBe("cached-patch");
    expect(patched.events.map((row) => row.stage)).toEqual(["update-before"]);
    expect(patched.events[0]!.cache).toEqual(patched.cache);

    await configure(ctx, { "delete-before": "cancel" });
    const denied = await call(ctx, { operation: "delete", profile: profile("mixed"), identifier });
    expect(denied.status).toBe(200);

    const vetoed = await state(ctx);
    expect(vetoed.verifications).toEqual(patched.verifications);
    expect(vetoed.cache).toEqual([]);
    expect(vetoed.events[0]!.cache).toEqual([]);

    await configure(ctx);
    const deleted = await call(ctx, { operation: "delete", profile: profile("mixed"), identifier });
    const after = await state(ctx);
    expect(after.verifications).toEqual([seeded.body as Row]);

    unchanged(other, after);
    return observed({
      foreign: other,
      created,
      seeded,
      updated,
      patched,
      denied,
      vetoed,
      deleted,
      after,
    });
  },
);

compatScenario(
  "verification storage reservation uses logical deterministic primary authority without hooks and denies cache-only storage",
  async (ctx) => {
    const other = await foreign(ctx);
    await configure(ctx);
    const identifier = "reserve-logical-owner";
    const observations = [];

    for (const mode of ["mixed", "hashed", "cache"] as const) {
      const result = await call(ctx, {
        operation: "reserve",
        profile: profile(mode),
        identifier,
        data: { value: "reservation-proof", ...jsonDates },
      });
      expect(result.status).toBe(mode === "cache" ? 500 : 200);

      if (mode !== "cache") {
        expect(result.body).toBe(mode === "mixed");
      }

      observations.push({ mode, result, state: await state(ctx) });
    }

    const final = await state(ctx);
    unchanged(other, final);
    expect(final.verifications).toHaveLength(1);
    expect(final.verifications[0]!.id).toBe(sha(`reserve:${identifier}`));
    expect(final.verifications[0]!.identifier).toBe(sha(identifier));
    expect(final.events).toEqual([]);
    expect(final.cache).toHaveLength(1);
    expect(Object.hasOwn(final.cache[0]!.value, "createdAt")).toBe(false);
    expect(Object.hasOwn(final.cache[0]!.value, "updatedAt")).toBe(false);

    return observed({ foreign: other, observations, final });
  },
);

for (const mode of ["plain", "no-cleanup", "limit"] as const) {
  compatScenario(
    `verification storage ${mode} selects the real expired newest generation before bounded hook cleanup`,
    async (ctx) => {
      const other = await foreign(ctx);
      await configure(ctx);
      const identifier = "cleanup-newest-owner";
      const seeds = [];

      for (let index = 0; index < 4; index++) {
        seeds.push(
          await call(ctx, {
            operation: "seed",
            identifier: index < 2 ? identifier : `expired-unrelated-${index}`,
            data: {
              value: `proof-${index}`,
              expiresAt: "2000-01-01T00:00:00.000Z",
              createdAt: `2020-01-0${index + 1}T00:00:00.000Z`,
              updatedAt: jsonDates.updatedAt,
            },
          }),
        );
      }

      const before = await state(ctx);
      const found = await call(ctx, { operation: "find", profile: profile(mode), identifier });
      expect(found.status).toBe(200);
      expect(found.body).toEqual(seeds[1]!.body);

      const after = await state(ctx);
      unchanged(other, after);
      expect(after.verifications).toHaveLength(mode === "no-cleanup" ? 4 : 0);
      expect(after.events.filter((row) => row.stage === "delete-before")).toHaveLength(
        mode === "no-cleanup" ? 0 : mode === "limit" ? 2 : 4,
      );

      return observed({ foreign: other, seeds, before, found, after });
    },
  );
}

compatScenario(
  "verification storage updates all transformed siblings with actual hook mutation and leaves legacy rows untouched",
  async (ctx) => {
    const other = await foreign(ctx);
    await configure(ctx);
    const identifier = "successful-update-owner";
    const created = [];

    for (let index = 0; index < 2; index++) {
      created.push(
        await call(ctx, {
          operation: "create",
          profile: profile("mixed"),
          identifier,
          data: { value: `old-${index}`, ...jsonDates },
        }),
      );
    }

    const legacy = await call(ctx, {
      operation: "seed",
      identifier,
      data: { value: "plain-legacy", ...jsonDates },
    });
    await configure(ctx, { updateMutation: { value: "trusted-update" } });
    const updated = await call(ctx, {
      operation: "update",
      profile: profile("mixed"),
      identifier,
      data: { value: "original-patch" },
    });
    expect(updated.status).toBe(200);
    expect(updated.body).toMatchObject({ identifier: sha(identifier), value: "trusted-update" });

    const after = await state(ctx);
    unchanged(other, after);
    expect(after.verifications.filter((row) => row.identifier === sha(identifier))).toHaveLength(2);

    for (const row of after.verifications.filter((row) => row.identifier === sha(identifier))) {
      expect(row.value).toBe("trusted-update");
      expect(row.updatedAt).not.toBe(jsonDates.updatedAt);
    }

    expect(after.verifications.find((row) => row.identifier === identifier)).toEqual(
      legacy.body as Row,
    );
    expect(after.cache[0]!.value.value).toBe("original-patch");
    expect(after.events.map((row) => row.stage)).toEqual(["update-before", "update-after"]);

    const missing = await call(ctx, {
      operation: "update",
      profile: profile("mixed"),
      identifier: "absent-update",
      data: { value: "absent-patch" },
    });
    expect(missing.body).toBeNull();

    const final = await state(ctx);
    expect(final.events.at(-1)).toMatchObject({ stage: "update-after", data: null });

    return observed({ foreign: other, created, legacy, updated, after, missing, final });
  },
);

for (const phase of ["commit", "rollback", "cache-error"] as const) {
  compatScenario(
    `verification storage transaction ${phase} retains actual publication before commit and after-hook deferral`,
    async (ctx) => {
      const other = await foreign(ctx);
      await configure(ctx, {}, phase === "cache-error" ? { set: true } : {});
      const before = await state(ctx);
      const created = await call(ctx, {
        operation: "transaction",
        profile: profile("mixed"),
        identifier: "transaction-phase-owner",
        rollback: phase === "rollback",
        data: { value: "transaction-proof", ...jsonDates },
      });
      const after = await state(ctx);
      unchanged(other, after);
      expect(created.status).toBe(phase === "commit" ? 200 : 500);
      expect(after.verifications).toHaveLength(phase === "commit" ? 1 : 0);
      expect(after.cache).toHaveLength(phase === "cache-error" ? 0 : 1);
      expect(after.events.map((row) => row.stage)).toEqual(
        phase === "commit" ? ["create-before", "create-after"] : ["create-before"],
      );

      return observed({ foreign: other, before, created, after });
    },
  );
}

compatScenario(
  "verification storage cache omits nonpositive TTL and preserves actual ISO revival and invalid-cache legacy fallback",
  async (ctx) => {
    const other = await foreign(ctx);
    await configure(ctx);
    const expired = await call(ctx, {
      operation: "create",
      profile: profile("cache"),
      identifier: "nonpositive-ttl-owner",
      data: { value: "expired-proof", expiresAt: "2000-01-01T00:00:00.000Z", ...jsonDates },
    });
    expect(expired.status).toBe(200);

    const expiredState = await state(ctx);
    expect(expiredState.cache).toEqual([]);
    expect(expiredState.cacheEvents).toEqual([]);

    const identifier = "revival-owner";
    const raw = {
      identifier: sha(identifier),
      value: "cached-proof",
      expiresAt: "2100-02-30T00:00:00.12345Z",
      nested: { createdAt: "2020-02-30T24:00:00.000Z" },
    };
    await call(ctx, {
      operation: "cache-seed",
      key: `verification:${sha(identifier)}`,
      value: JSON.stringify(raw),
    });
    const found = await call(ctx, { operation: "find", profile: profile("cache"), identifier });
    expect(found.body).toEqual({
      ...raw,
      expiresAt: "2100-03-02T00:00:00.123Z",
      nested: { createdAt: "2020-03-02T00:00:00.000Z" },
    });

    const consumed = await call(ctx, {
      operation: "consume",
      profile: profile("cache"),
      identifier,
    });
    expect(consumed.body).toEqual(found.body);

    await call(ctx, {
      operation: "cache-seed",
      key: `verification:${sha(identifier)}`,
      value: '{"expiresAt":"invalid date","value":"invalid-primary"}',
    });
    await call(ctx, {
      operation: "cache-seed",
      key: `verification:${identifier}`,
      value: JSON.stringify({
        identifier,
        value: "legacy-proof",
        expiresAt: "2100-01-01T00:00:00.000Z",
      }),
    });
    const fallback = await call(ctx, {
      operation: "consume",
      profile: profile("cache"),
      identifier,
    });
    expect(fallback.body).toMatchObject({ identifier, value: "legacy-proof" });

    const after = await state(ctx);
    expect(after.cache).toEqual([]);

    unchanged(other, after);
    return observed({ foreign: other, expired, expiredState, found, consumed, fallback, after });
  },
);

function consumerObservation(
  value: unknown,
  identifiers: ReadonlyMap<string, Row> = new Map(),
  publications: readonly Row[] = [],
): any {
  if (Array.isArray(value)) {
    return value.map((child) => consumerObservation(child, identifiers, publications));
  }

  if (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    (value as Row).operation === "set"
  ) {
    // Supplement the existing projection with the complete actual cache-set
    // receipt. Every projected field must match; none is discarded or changed.
    const admitted = publications.find((publication) =>
      Object.entries(value).every(
        ([key, child]) => JSON.stringify(child) === JSON.stringify(publication.set[key]),
      ),
    );
    if (admitted) {
      return admitted.set;
    }
  }

  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([key, child]) => {
        if (key === "codeVerifier" && typeof child === "string") {
          expect(child).toMatch(/^[a-zA-Z0-9_-]{128}$/);
          return [key, { token: child, length: 128, encoding: "base64url-alphabet" }];
        }

        if (key === "oauthState" && typeof child === "string") {
          return [key, { state: child }];
        }

        if (key === "expiresAt" && typeof child === "number") {
          return [
            key,
            { expiresAt: new Date(child).toISOString(), encoding: "epoch-milliseconds" },
          ];
        }

        if (key === "otp" && typeof child === "string" && /^\d{6}$/.test(child)) {
          return [key, { token: child, encoding: "decimal", length: 6 }];
        }

        if (
          key === "key" &&
          typeof child === "string" &&
          child.startsWith("verification:") &&
          identifiers.has(child.slice(13))
        ) {
          return [
            key,
            { token: child, ...identifiers.get(child.slice(13)), namespace: "verification:" },
          ];
        }

        if (key === "identifier" && typeof child === "string" && identifiers.has(child)) {
          return [key, { token: child, ...identifiers.get(child) }];
        }

        if (key === "value" && typeof child === "string" && /^\d{6}:\d+$/.test(child)) {
          const [otp, counter] = child.split(":");
          return [key, { otp: { token: otp, encoding: "decimal", length: 6 }, counter }];
        }

        if (key === "value" && typeof child === "string" && /^[a-zA-Z0-9_-]{32}$/.test(child)) {
          return [key, { token: child }];
        }

        if (key === "value" && typeof child === "string" && child.startsWith("{")) {
          const parsed = JSON.parse(child);
          return [
            key,
            {
              token: child,
              decoded: consumerObservation(parsed, identifiers, publications),
              encoding: "json",
            },
          ];
        }

        return [key, consumerObservation(child, identifiers, publications)];
      }),
    );
  }

  return value;
}

async function publicationObservation(
  ctx: ScenarioContext,
  value: Row,
  identifiers: ReadonlyMap<string, Row> = new Map(),
) {
  const response = await ctx.rawRequest({
    path: "/__test/verification-publications",
    method: "GET",
  });
  expect(response.status).toBe(200);

  const publications = (response.body as Row).publications as Row[];

  for (const publication of publications) {
    expect(publication.set.rawValue).toBe(JSON.stringify(publication.snapshot));
    expect(publication.set.value).toEqual(publication.snapshot);
    expect(publication.set.key).toBe(`verification:${publication.before.snapshot.identifier}`);

    const expiry = Date.parse(publication.snapshot.expiresAt);
    const earliest = Date.parse(publication.before.executedAt);
    const latest = Date.parse(publication.set.executedAt);
    expect(publication.set.ttl).toBeGreaterThanOrEqual(
      Math.max(Math.floor((expiry - latest) / 1000), 0),
    );
    expect(publication.set.ttl).toBeLessThanOrEqual(
      Math.max(Math.floor((expiry - earliest) / 1000), 0),
    );
    expect(Date.parse(publication.set.storageExpiresAt)).toBe(
      Date.parse(publication.set.storedAt) + publication.set.ttl * 1000,
    );
  }

  return observed({
    ...consumerObservation(value, identifiers, publications),
    verificationPublications: publications,
  });
}

function transformed(mode: string, identifier: string) {
  return mode === "custom" ? `custom:${sha(identifier)}` : sha(identifier);
}

function issued(s: State, mode: string, identifier: string): Row {
  const actual = transformed(mode, identifier);
  const row =
    mode === "cache"
      ? s.cache.find((row) => row.key === `verification:${actual}`)?.value
      : s.verifications.find((row) => row.identifier === actual);
  expect(row).toBeDefined();
  expect(row.identifier).toBe(actual);

  return row;
}

for (const mode of ["hashed", "custom", "cache", "mixed"] as const) {
  compatScenario(
    `verification global ${mode} real OTP admission retains mailbox operation retry counter and replay isolation`,
    async (ctx) => {
      const other = await foreign(ctx);
      await configure(ctx);
      const client = ctx.actor("otp-owner", profile(mode)).client;
      const email = ctx.uniqueEmail("global-otp");
      const identifier = `sign-in-otp-${email}`;
      const sent = await client.emailOtp.sendVerificationOtp({ email, type: "sign-in" });
      expect(sent.error).toBeNull();

      const initial = await state(ctx);
      const delivery = initial.deliveries.at(-1)!;
      expect(delivery).toMatchObject({ email, type: "sign-in" });
      expect(delivery.otp).toMatch(/^\d{6}$/);
      expect(issued(initial, mode, identifier).value).toBe(`${delivery.otp}:0`);

      if (mode === "cache") {
        expect(initial.verifications).toEqual([]);
      }

      const wrongMailbox = await client.signIn.emailOtp({
        email: ctx.uniqueEmail("wrong-mailbox"),
        otp: delivery.otp,
      });
      const wrongOperation = await client.emailOtp.verifyEmail({ email, otp: delivery.otp });
      expect(wrongMailbox.error?.code).toBe("INVALID_OTP");
      expect(wrongOperation.error?.code).toBe("INVALID_OTP");
      expect(issued(await state(ctx), mode, identifier)).toEqual(issued(initial, mode, identifier));

      const wrong = await client.signIn.emailOtp({ email, otp: "wrong" });
      expect(wrong.error?.code).toBe("INVALID_OTP");

      const retry = await state(ctx);
      expect(issued(retry, mode, identifier).value).toBe(`${delivery.otp}:1`);
      expect(issued(retry, mode, identifier).expiresAt).toBe(
        issued(initial, mode, identifier).expiresAt,
      );

      const completed = await client.signIn.emailOtp({
        email,
        otp: delivery.otp,
        name: "Global OTP Owner",
      });
      expect(completed.error).toBeNull();
      expect(completed.data?.user.emailVerified).toBe(true);

      const current = await client.getSession();
      expect(current.data?.user.id).toBe(completed.data?.user.id);

      const replay = await client.signIn.emailOtp({ email, otp: delivery.otp });
      expect(replay.error?.code).toBe("INVALID_OTP");

      const after = await state(ctx);
      unchanged(other, after);
      expect(
        after.verifications.filter((row) => row.identifier === transformed(mode, identifier)),
      ).toEqual([]);
      expect(
        after.cache.filter((row) => row.key === `verification:${transformed(mode, identifier)}`),
      ).toEqual([]);

      return observed(
        consumerObservation({
          foreign: other,
          sent,
          initial,
          wrongMailbox,
          wrongOperation,
          wrong,
          retry,
          completed,
          current,
          replay,
          after,
        }),
      );
    },
    [
      "POST /email-otp/send-verification-otp",
      "POST /sign-in/email-otp",
      "POST /email-otp/verify-email",
    ],
  );
}

compatScenario(
  "verification global OTP delivery retries a genuine failed creation once with the same generated code before sending",
  async (ctx) => {
    const other = await foreign(ctx);
    await configure(ctx, { "create-before": "throw-once" });
    const client = ctx.actor("otp-retry", profile("hashed")).client;
    const email = ctx.uniqueEmail("delivery-retry");
    const sent = await client.emailOtp.sendVerificationOtp({ email, type: "sign-in" });
    expect(sent.error).toBeNull();

    const admitted = await state(ctx);
    expect(admitted.events.map((row) => row.stage)).toEqual([
      "create-before",
      "create-before",
      "create-after",
    ]);
    expect(admitted.deliveries).toHaveLength(1);
    expect(admitted.events[0]!.data.value).toBe(admitted.events[1]!.data.value);
    expect(issued(admitted, "hashed", `sign-in-otp-${email}`).value).toBe(
      `${admitted.deliveries[0]!.otp}:0`,
    );

    await configure(ctx);
    const completed = await client.signIn.emailOtp({
      email,
      otp: admitted.deliveries[0]!.otp,
      name: "Creation Retry Owner",
    });
    expect(completed.error).toBeNull();

    const after = await state(ctx);
    unchanged(other, after);
    return observed(consumerObservation({ foreign: other, sent, admitted, completed, after }));
  },
  ["POST /email-otp/send-verification-otp", "POST /sign-in/email-otp"],
);

for (const mode of ["hashed", "custom"] as const) {
  compatScenario(
    `verification global ${mode} two-factor wrong-code retry uses the original logical identifier and deadline before real completion`,
    async (ctx) => {
      const other = await foreign(ctx);
      await configure(ctx);
      const selected = profile(mode);
      const client = createAuthClient({
        baseURL: `${ctx.baseURL}${authProfilePath(selected)}`,
        plugins: [twoFactorClient()],
        fetchOptions: { customFetchImpl: ctx.actor("factor-owner", selected).fetch },
      });
      const email = ctx.uniqueEmail("global-factor");
      const signup = await client.signUp.email({
        email,
        password: "password123",
        name: "Global Factor Owner",
      });
      expect(signup.error).toBeNull();

      const original = await client.getSession();
      expect(original.data).not.toBeNull();

      const logical = `2fa-otp-${signup.data!.user.id}!${original.data!.session.id}`;
      const stored = transformed(mode, logical);
      const identifiers = new Map([
        [
          stored,
          {
            algorithm: mode,
            logical: {
              prefix: "2fa-otp-",
              userId: signup.data!.user.id,
              sessionId: original.data!.session.id,
            },
          },
        ],
      ]);
      await configure(ctx);
      const sent = await client.twoFactor.sendOtp({});
      expect(sent.error).toBeNull();

      const initial = await state(ctx);
      const code = initial.deliveries.at(-1)!.otp;
      expect(code).toMatch(/^\d{6}$/);
      expect(issued(initial, mode, logical).value).toBe(`${code}:0`);

      const foreignClient = createAuthClient({
        baseURL: `${ctx.baseURL}${authProfilePath(selected)}`,
        plugins: [twoFactorClient()],
        fetchOptions: { customFetchImpl: ctx.actor("factor-guest", selected).fetch },
      });
      const guest = await foreignClient.twoFactor.verifyOtp({ code });
      expect(guest.error?.status).toBe(401);

      const wrong = await client.twoFactor.verifyOtp({ code: "wrong" });
      expect(wrong.error?.code).toBe("INVALID_CODE");

      const retry = await state(ctx);
      expect(issued(retry, mode, logical).value).toBe(`${code}:1`);
      expect(issued(retry, mode, logical).expiresAt).toBe(issued(initial, mode, logical).expiresAt);
      expect(retry.verifications).toHaveLength(1);

      const completed = await client.twoFactor.verifyOtp({ code });
      expect(completed.error).toBeNull();
      expect(completed.data?.user.twoFactorEnabled).toBe(true);

      const current = await client.getSession();
      expect(current.data?.session.token).toBe(completed.data?.token);

      const replay = await client.twoFactor.verifyOtp({ code });
      expect(replay.error?.code).toBe("OTP_HAS_EXPIRED");

      const after = await state(ctx);
      unchanged(other, after);
      expect(after.verifications).toEqual([]);

      return observed(
        consumerObservation(
          {
            foreign: other,
            signup,
            original,
            sent,
            initial,
            guest,
            wrong,
            retry,
            completed,
            current,
            replay,
            after,
          },
          identifiers,
        ),
      );
    },
    ["POST /two-factor/send-otp", "POST /two-factor/verify-otp"],
  );
}

for (const mode of ["hashed", "custom", "cache", "mixed"] as const) {
  compatScenario(
    `verification global ${mode} real magic link preserves origin rejection expiry consumption and foreign state`,
    async (ctx) => {
      const other = await foreign(ctx);
      await configure(ctx);
      const selected = profile(mode);
      const client = ctx.actor("magic-owner", selected).client;
      const email = ctx.uniqueEmail("global-magic");
      const sent = await client.signIn.magicLink({
        email,
        name: "Global Magic Owner",
        metadata: { reason: "verification storage" },
      });
      expect(sent.error).toBeNull();

      const initial = await state(ctx);
      const delivery = initial.deliveries.at(-1)!;
      expect(delivery).toMatchObject({
        email,
        type: "magic",
        token: `magic-proof:${sha(email)}`,
        metadata: { reason: "verification storage" },
      });
      expect(issued(initial, mode, delivery.token).value).toBe(
        JSON.stringify({ email, name: "Global Magic Owner" }),
      );

      const before = sql(initial);
      const forbidden = await ctx.rawRequest({
        actor: `${selected}:magic-owner`,
        path: `${authProfilePath(selected)}/magic-link/verify?${new URLSearchParams({ token: delivery.token, callbackURL: "https://foreign.invalid/steal" })}`,
        redirect: "manual",
      });
      expect(forbidden.status).toBe(403);
      expect(sql(await state(ctx))).toEqual(before);

      const completed = await client.magicLink.verify({ query: { token: delivery.token } });
      expect(completed.error).toBeNull();
      expect(completed.data?.user.email).toBe(email);
      expect(completed.data?.user.emailVerified).toBe(true);

      const current = await client.getSession();
      expect(current.data?.user.id).toBe(completed.data?.user.id);

      const replay = await ctx.rawRequest({
        path: `${authProfilePath(selected)}/magic-link/verify?${new URLSearchParams({ token: delivery.token })}`,
        redirect: "manual",
      });
      expect(replay.status).toBe(302);
      expect(new URL(replay.location!, ctx.baseURL).searchParams.get("error")).toBe(
        "INVALID_TOKEN",
      );

      const expiring = await client.signIn.magicLink({
        email,
        name: "Global Magic Owner",
        metadata: { reason: "expiry" },
      });
      expect(expiring.error).toBeNull();

      const expiry = await call(ctx, {
        operation: "update",
        profile: selected,
        identifier: delivery.token,
        data: { expiresAt: "2000-01-01T00:00:00.000Z" },
      });
      expect(expiry.status).toBe(200);

      if (mode === "cache") {
        await call(ctx, {
          operation: "cache-seed",
          key: `verification:${transformed(mode, delivery.token)}`,
          value: JSON.stringify({
            ...issued(initial, mode, delivery.token),
            expiresAt: "2000-01-01T00:00:00.000Z",
          }),
        });
      }

      const expired = await ctx.rawRequest({
        path: `${authProfilePath(selected)}/magic-link/verify?${new URLSearchParams({ token: delivery.token })}`,
        redirect: "manual",
      });
      expect(expired.status).toBe(302);
      expect(new URL(expired.location!, ctx.baseURL).searchParams.get("error")).toBe(
        "INVALID_TOKEN",
      );

      const after = await state(ctx);
      unchanged(other, after);
      expect(
        after.verifications.filter((row) => row.identifier === transformed(mode, delivery.token)),
      ).toEqual([]);
      expect(
        after.cache.filter(
          (row) => row.key === `verification:${transformed(mode, delivery.token)}`,
        ),
      ).toEqual([]);

      return observed(
        consumerObservation({
          foreign: other,
          sent,
          initial,
          forbidden,
          completed,
          current,
          replay,
          expiring,
          expiry,
          expired,
          after,
        }),
      );
    },
    ["POST /sign-in/magic-link", "GET /magic-link/verify"],
  );
}

for (const mode of ["hashed", "custom", "cache", "mixed"] as const) {
  compatScenario(
    `verification global ${mode} real one-time transfer consumes only the owned original session and rejects expiry revocation and replay`,
    async (ctx) => {
      const other = await foreign(ctx);
      await configure(ctx);
      const selected = profile(mode);
      const client = (name: string) =>
        createAuthClient({
          baseURL: `${ctx.baseURL}${authProfilePath(selected)}`,
          plugins: [oneTimeTokenClient()],
          fetchOptions: { customFetchImpl: ctx.actor(name, selected).fetch },
        });
      const owner = client("ott-owner");
      const consumer = client("ott-consumer");
      const signup = await owner.signUp.email({
        email: ctx.uniqueEmail("global-ott"),
        password: "password123",
        name: "Global OTT Owner",
      });
      expect(signup.error).toBeNull();

      const original = await owner.getSession();
      await configure(ctx);
      const generated = await owner.oneTimeToken.generate();
      expect(generated.error).toBeNull();
      expect(generated.data?.token).toBe(`ott-proof:${sha(signup.data!.user.email)}`);

      const identifier = `one-time-token:${generated.data!.token}`;
      const initial = await state(ctx);
      expect(issued(initial, mode, identifier).value).toBe(original.data!.session.token);

      const invalid = await consumer.oneTimeToken.verify({ token: "wrong-transfer-proof" });
      expect(invalid.error?.message).toBe("Invalid token");
      expect(issued(await state(ctx), mode, identifier)).toEqual(issued(initial, mode, identifier));

      const completed = await consumer.oneTimeToken.verify({ token: generated.data!.token });
      expect(completed.error).toBeNull();
      expect(completed.data?.session.token).toBe(original.data!.session.token);
      expect(completed.data?.user.id).toBe(signup.data!.user.id);

      const current = await consumer.getSession();
      expect(current.data?.session.token).toBe(original.data!.session.token);

      const replay = await consumer.oneTimeToken.verify({ token: generated.data!.token });
      expect(replay.error?.message).toBe("Invalid token");

      const expiring = await owner.oneTimeToken.generate();
      expect(expiring.error).toBeNull();

      const expiry = await call(ctx, {
        operation: "update",
        profile: selected,
        identifier,
        data: { expiresAt: "2000-01-01T00:00:00.000Z" },
      });
      expect(expiry.status).toBe(200);

      if (mode === "cache") {
        await call(ctx, {
          operation: "cache-seed",
          key: `verification:${transformed(mode, identifier)}`,
          value: JSON.stringify({
            ...issued(initial, mode, identifier),
            expiresAt: "2000-01-01T00:00:00.000Z",
          }),
        });
      }

      const expired = await consumer.oneTimeToken.verify({ token: generated.data!.token });
      expect(expired.error?.message).toBe("Invalid token");

      const revocable = await owner.oneTimeToken.generate();
      expect(revocable.error).toBeNull();

      const signout = await owner.signOut();
      expect(signout.error).toBeNull();

      const revoked = await consumer.oneTimeToken.verify({ token: generated.data!.token });
      expect(revoked.error?.message).toBe("Session not found");

      const after = await state(ctx);
      unchanged(other, after);
      expect(
        after.verifications.filter((row) => row.identifier === transformed(mode, identifier)),
      ).toEqual([]);
      expect(
        after.cache.filter((row) => row.key === `verification:${transformed(mode, identifier)}`),
      ).toEqual([]);

      return observed(
        consumerObservation({
          foreign: other,
          signup,
          original,
          generated,
          initial,
          invalid,
          completed,
          current,
          replay,
          expiring,
          expiry,
          expired,
          revocable,
          signout,
          revoked,
          after,
        }),
      );
    },
    ["GET /one-time-token/generate", "POST /one-time-token/verify"],
  );
}

async function callback(
  ctx: ScenarioContext,
  actor: string,
  selected: FixtureProfile,
  state: string,
) {
  const response = await ctx
    .actor(actor, selected)
    .fetch(
      `${ctx.baseURL}${authProfilePath(selected)}/callback/google?${new URLSearchParams({ code: "compat-code", state })}`,
      { redirect: "manual" },
    );
  return {
    status: response.status,
    location: response.headers.get("location"),
    body: await response.text(),
  };
}

for (const mode of ["hashed", "custom", "cache", "mixed"] as const) {
  compatScenario(
    `verification global ${mode} real OAuth state preserves signed correlation and identifier-wide retirement before expiry and replay`,
    async (ctx) => {
      const other = await foreign(ctx);
      await configure(ctx);
      const selected = profile(mode);
      const owner = ctx.actor("oauth-owner", selected).client;
      const email = ctx.uniqueEmail("global-oauth");
      const accountId = ctx.uniqueToken("global-oauth-subject");
      await ctx.setSocialProfile({
        sub: accountId,
        email,
        name: "Global OAuth Owner",
        emailVerified: true,
        idTokenValid: true,
      });
      const initiated = await owner.signIn.social({
        provider: "google",
        callbackURL: "/verification-complete",
        disableRedirect: true,
      });
      expect(initiated.error).toBeNull();

      const oauthState = new URL(initiated.data!.url!).searchParams.get("state")!;
      expect(oauthState).toMatch(/^[a-zA-Z0-9_-]{32}$/);

      const stored = transformed(mode, oauthState);
      const identifiers = new Map([
        [stored, { algorithm: mode, logical: { state: oauthState } }],
        [oauthState, { algorithm: "legacy-plain", logical: { state: oauthState } }],
      ]);
      const initial = await state(ctx);
      const proof = issued(initial, mode, oauthState);
      const payload = JSON.parse(proof.value);
      expect(payload.oauthState).toBe(oauthState);
      expect(payload.callbackURL).toBe("/verification-complete");
      expect(typeof payload.expiresAt).toBe("number");
      expect(sha(payload.codeVerifier)).toBe(
        new URL(initiated.data!.url!).searchParams.get("code_challenge")!,
      );

      const wrongCookie = await callback(ctx, "oauth-foreign-cookie", selected, oauthState);
      expect(wrongCookie.status).toBe(302);
      expect(new URL(wrongCookie.location!, ctx.baseURL).searchParams.get("error")).toBe(
        "state_mismatch",
      );
      expect(sql(await state(ctx))).toEqual(sql(initial));

      if (mode !== "cache") {
        const sibling = await call(ctx, {
          operation: "seed",
          identifier: stored,
          data: { value: proof.value, expiresAt: proof.expiresAt, ...jsonDates },
        });
        expect(sibling.status).toBe(200);
      }

      const before = await state(ctx);
      const completed = await callback(ctx, "oauth-owner", selected, oauthState);
      expect(completed).toMatchObject({ status: 302, location: "/verification-complete" });

      const current = await owner.getSession();
      expect(current.data?.user.email).toBe(email);

      const after = await state(ctx);
      unchanged(other, after);
      expect(after.verifications.filter((row) => row.identifier === stored)).toEqual([]);
      expect(after.cache.filter((row) => row.key === `verification:${stored}`)).toEqual([]);

      const replay = await callback(ctx, "oauth-owner", selected, oauthState);
      expect(replay.status).toBe(302);
      expect(new URL(replay.location!, ctx.baseURL).searchParams.get("error")).toBe(
        "state_mismatch",
      );

      const final = await state(ctx);
      expect(sql(final)).toEqual(sql(after));

      unchanged(other, final);

      // The existing cookie comparer recognizes email issuance, not OAuth's302
      // issuance. Admit the same physical principal through genuine public APIs
      // before the authenticated expiry phase, retaining its original OAuth session.
      const oauthSession = final.sessions.find((row) => row.token === current.data!.session.token)!;
      expect(oauthSession.userId).toBe(current.data!.user.id);

      const passwordMode = await ctx.rawRequest({
        path: "/__test/set-password",
        method: "POST",
        json: { operation: "mode", profile: "set-password-default", mode: "normal" },
      });
      expect(passwordMode).toMatchObject({ status: 200, body: { status: true, mode: "normal" } });

      const password = "verification-owner-password123";
      const setResponse = await ctx
        .actor("oauth-owner", selected)
        .fetch(`${ctx.baseURL}/__test/server-api/set-password`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            operation: "set",
            profile: "set-password-default",
            newPassword: password,
          }),
        });
      const setPassword = { status: setResponse.status, body: await setResponse.json() };
      expect(setPassword).toEqual({ status: 200, body: { status: true } });

      const credentialed = await state(ctx);
      const credential = credentialed.accounts.find(
        (row) => row.providerId === "credential" && row.userId === current.data!.user.id,
      )!;
      expect(credential.accountId).toBe(current.data!.user.id);
      expect(await verifyPassword({ hash: String(credential.password), password })).toBe(true);
      expect(credentialed.sessions.find((row) => row.id === oauthSession.id)).toEqual(oauthSession);

      unchanged(other, credentialed);
      const passwordCallbacks = await ctx.rawRequest({ path: "/__test/set-password/state" });
      expect(passwordCallbacks.status).toBe(200);

      const passwordBody = passwordCallbacks.body as Row;
      expect(passwordBody.events).toEqual([
        { stage: "hash-enter", password },
        { stage: "hash-result", password, hash: credential.password },
      ]);

      const passwordState = {
        ...passwordCallbacks,
        body: {
          ...passwordBody,
          events: passwordBody.events.map((event: Row) => ({
            ...event,
            password: { text: event.password },
            ...(typeof event.hash === "string"
              ? { hash: observed({ password: event.hash }).password }
              : {}),
          })),
        },
      };
      const emailSignIn = await owner.signIn.email({ email, password });
      expect(emailSignIn.error).toBeNull();
      expect(emailSignIn.data!.user.id).toBe(current.data!.user.id);
      expect(emailSignIn.data!.token).not.toBe(oauthSession.token);

      const emailCurrent = await owner.getSession();
      expect(emailCurrent.data!.session.token).toBe(emailSignIn.data!.token);

      const authenticated = await state(ctx);
      expect(authenticated.sessions.find((row) => row.id === oauthSession.id)).toEqual(
        oauthSession,
      );
      expect(
        authenticated.sessions.find((row) => row.token === emailSignIn.data!.token)?.userId,
      ).toBe(oauthSession.userId);

      unchanged(other, authenticated);
      const expiring = await owner.signIn.social({
        provider: "google",
        callbackURL: "/expired-verification-must-not-complete",
        disableRedirect: true,
      });
      expect(expiring.error).toBeNull();

      const expiredState = new URL(expiring.data!.url!).searchParams.get("state")!;
      const expiredStored = transformed(mode, expiredState);
      identifiers.set(expiredStored, { algorithm: mode, logical: { state: expiredState } });
      identifiers.set(expiredState, {
        algorithm: "legacy-plain",
        logical: { state: expiredState },
      });
      const expiryIssued = await state(ctx);
      const live = issued(expiryIssued, mode, expiredState);
      const expiredPayload = {
        ...JSON.parse(live.value),
        expiresAt: Date.parse("2000-01-01T00:00:00.000Z"),
      };
      expect(Date.parse(live.expiresAt)).toBeGreaterThan(Date.now());

      const editedExpired = await call(ctx, {
        operation: "update",
        profile: selected,
        identifier: expiredState,
        data: { value: JSON.stringify(expiredPayload) },
      });
      expect(editedExpired.status).toBe(200);

      const expiryBefore = await state(ctx);
      const expired = await callback(ctx, "oauth-owner", selected, expiredState);
      expect(expired.status).toBe(302);
      expect(new URL(expired.location!, ctx.baseURL).searchParams.get("error")).toBe(
        "state_mismatch",
      );

      const expiredAfter = await state(ctx);
      unchanged(other, expiredAfter);

      for (const table of ["users", "accounts", "sessions"] as const) {
        expect(expiredAfter[table]).toEqual(expiryBefore[table]);
      }

      expect(expiredAfter.verifications.filter((row) => row.identifier === expiredStored)).toEqual(
        [],
      );
      expect(
        expiredAfter.cache.filter((row) => row.key === `verification:${expiredStored}`),
      ).toEqual([]);

      return publicationObservation(
        ctx,
        {
          foreign: other,
          initiated,
          initial,
          wrongCookie,
          before,
          completed,
          current,
          after,
          replay,
          final,
          oauthSession,
          passwordMode,
          setPassword,
          credentialed,
          passwordState,
          emailSignIn,
          emailCurrent,
          authenticated,
          expiring,
          expiryIssued,
          editedExpired,
          expiryBefore,
          expired,
          expiredAfter,
        },
        identifiers,
      );
    },
    ["POST /sign-in/social", "GET /callback/{}"],
  );
}

compatScenario(
  "verification global cache OAuth read failure retains proof and cookie then permits the actual original callback",
  async (ctx) => {
    const other = await foreign(ctx);
    await configure(ctx);
    const selected = profile("cache");
    const owner = ctx.actor("oauth-error-owner", selected).client;
    const email = ctx.uniqueEmail("global-oauth-error");
    await ctx.setSocialProfile({
      sub: ctx.uniqueToken("global-oauth-error-subject"),
      email,
      name: "Cache Read Owner",
      emailVerified: true,
      idTokenValid: true,
    });
    const initiated = await owner.signIn.social({
      provider: "google",
      callbackURL: "/verification-recovered",
      disableRedirect: true,
    });
    expect(initiated.error).toBeNull();

    const oauthState = new URL(initiated.data!.url!).searchParams.get("state")!;
    const stored = sha(oauthState);
    const identifiers = new Map([
      [stored, { algorithm: "hashed", logical: { state: oauthState } }],
      [oauthState, { algorithm: "legacy-plain", logical: { state: oauthState } }],
    ]);
    const before = await state(ctx);
    await configure(ctx, {}, { get: true });
    const failed = await callback(ctx, "oauth-error-owner", selected, oauthState);
    expect(failed.status).toBe(302);
    expect(new URL(failed.location!, ctx.baseURL).searchParams.get("error")).toBe(
      "internal_server_error",
    );

    const preserved = await state(ctx);
    expect(preserved.cache).toEqual(before.cache);
    expect(sql(preserved)).toEqual(sql(before));

    await configure(ctx);
    const completed = await callback(ctx, "oauth-error-owner", selected, oauthState);
    expect(completed).toMatchObject({ status: 302, location: "/verification-recovered" });

    const after = await state(ctx);
    unchanged(other, after);
    return publicationObservation(
      ctx,
      { foreign: other, initiated, before, failed, preserved, completed, after },
      identifiers,
    );
  },
  ["POST /sign-in/social", "GET /callback/{}"],
);

for (const mode of ["hashed", "cache"] as const) {
  compatScenario(
    `verification global ${mode} real concurrent consumers admit one actual snapshot and preserve unrelated proofs`,
    async (ctx) => {
      const other = await foreign(ctx);
      await configure(ctx);
      const selected = profile(mode);
      const identifier = "atomic-global-owner";
      const unrelated = await call(ctx, {
        operation: "create",
        profile: selected,
        identifier: "foreign-verification-owner",
        data: { value: "foreign-proof", ...jsonDates },
      });
      const created = await call(ctx, {
        operation: "create",
        profile: selected,
        identifier,
        data: { value: "winner-proof", ...jsonDates },
      });
      expect(created.status).toBe(200);
      expect(unrelated.status).toBe(200);

      await configure(ctx);
      const before = await state(ctx);
      const responses = await Promise.all(
        Array.from({ length: 16 }, async () => {
          const response = await fetch(`${ctx.baseURL}/__test/server-api/verification-storage`, {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({ operation: "consume", profile: selected, identifier }),
          });
          return {
            status: response.status,
            contentType: response.headers.get("content-type"),
            body: await response.json(),
          };
        }),
      );

      for (const response of responses) {
        expect(response.status).toBe(200);
      }

      expect(responses.filter((row) => row.body !== null)).toHaveLength(1);
      expect(responses.find((row) => row.body !== null)!.body).toEqual(created.body);
      expect(responses.filter((row) => row.body === null)).toHaveLength(15);

      const after = await state(ctx);
      unchanged(other, after);
      expect(after.verifications).toEqual(mode === "cache" ? [] : [unrelated.body as Row]);

      if (mode === "cache") {
        expect(after.cache).toHaveLength(1);
        expect(after.cache[0]!.value).toEqual(unrelated.body);
      }

      expect(after.events.map((row) => row.stage)).toEqual(
        mode === "cache" ? [] : ["delete-before", "delete-after"],
      );

      return observed({
        foreign: other,
        unrelated,
        created,
        before,
        responses: responses.sort(
          (left, right) => Number(right.body !== null) - Number(left.body !== null),
        ),
        after: {
          ...after,
          cacheEvents: {
            ordering: "independent-concurrent-operations",
            events: [...after.cacheEvents].sort((left, right) =>
              JSON.stringify(left) < JSON.stringify(right)
                ? -1
                : JSON.stringify(left) > JSON.stringify(right)
                  ? 1
                  : 0,
            ),
          },
        },
      });
    },
  );
}

compatScenario(
  "verification mixed consume commits physical retirement before cache deletion failure and preserves the real cached proof",
  async (ctx) => {
    const other = await foreign(ctx);
    await configure(ctx);
    const identifier = "consume-cache-failure";
    const created = await call(ctx, {
      operation: "create",
      profile: profile("mixed"),
      identifier,
      data: { value: "committed-retirement", ...jsonDates },
    });
    expect(created.status).toBe(200);

    await configure(ctx, {}, { delete: true });
    const before = await state(ctx);
    const consumed = await call(ctx, {
      operation: "consume",
      profile: profile("mixed"),
      identifier,
    });
    expect(consumed.status).toBe(500);

    const after = await state(ctx);
    unchanged(other, after);
    expect(after.verifications).toEqual([]);
    expect(after.cache).toEqual(before.cache);
    expect(after.events.map((row) => row.stage)).toEqual(["delete-before", "delete-after"]);
    expect(after.events[1]!.verifications).toEqual([]);

    await configure(ctx);
    const replay = await call(ctx, { operation: "consume", profile: profile("mixed"), identifier });
    expect(replay.body).toBeNull();
    expect((await state(ctx)).cache).toEqual(before.cache);

    return observed({
      foreign: other,
      created,
      before,
      consumed,
      after,
      replay,
      final: await state(ctx),
    });
  },
);

for (const mode of ["cache", "mixed"] as const) {
  compatScenario(
    `verification global ${mode} actual OTP cache-write failure retains retry SQL and suppresses delivery and authentication`,
    async (ctx) => {
      const other = await foreign(ctx);
      await configure(ctx, {}, { set: true });
      const selected = profile(mode);
      const client = ctx.actor("cache-fault-owner", selected).client;
      const email = ctx.uniqueEmail("global-write-fault");
      const sent = await client.emailOtp.sendVerificationOtp({ email, type: "sign-in" });
      expect(sent.error?.status).toBe(500);

      const failed = await state(ctx);
      unchanged(other, failed);
      expect(failed.deliveries).toEqual([]);
      expect(failed.cache).toEqual([]);
      expect(failed.verifications).toHaveLength(mode === "mixed" ? 1 : 0);
      expect(failed.events.filter((row) => row.stage === "create-before")).toHaveLength(2);
      expect(failed.events.filter((row) => row.stage === "create-after")).toEqual([]);

      await configure(ctx);
      const denied = await client.signIn.emailOtp({ email, otp: "wrong" });
      expect(denied.error?.code).toBe("INVALID_OTP");

      const after = await state(ctx);
      unchanged(other, after);
      expect(after.users).toEqual(failed.users);
      expect(after.accounts).toEqual(failed.accounts);
      expect(after.sessions).toEqual(failed.sessions);

      return observed(consumerObservation({ foreign: other, sent, failed, denied, after }));
    },
    ["POST /email-otp/send-verification-otp", "POST /sign-in/email-otp"],
  );
}

compatScenario(
  "verification global cache actual OTP creation veto delivers only a non-admissible code without SQL cache or session mutation",
  async (ctx) => {
    const other = await foreign(ctx);
    await configure(ctx, { "create-before": "cancel" });
    const client = ctx.actor("veto-owner", profile("cache")).client;
    const email = ctx.uniqueEmail("global-veto");
    const sent = await client.emailOtp.sendVerificationOtp({ email, type: "sign-in" });
    expect(sent.error).toBeNull();

    const delivered = await state(ctx);
    expect(delivered.deliveries).toHaveLength(1);
    expect(delivered.verifications).toEqual([]);
    expect(delivered.cache).toEqual([]);
    expect(delivered.events.map((row) => row.stage)).toEqual(["create-before"]);

    const denied = await client.signIn.emailOtp({ email, otp: delivered.deliveries[0]!.otp });
    expect(denied.error?.code).toBe("INVALID_OTP");

    const after = await state(ctx);
    unchanged(other, after);
    expect(sql(after)).toEqual(sql(delivered));

    return observed(consumerObservation({ foreign: other, sent, delivered, denied, after }));
  },
  ["POST /email-otp/send-verification-otp", "POST /sign-in/email-otp"],
);

for (const mode of ["cache-default", "mixed-default"] as const) {
  compatScenario(
    `verification global ${mode} retains literal default OTP magic and transfer TTL diagnostics with real publication intervals`,
    async (ctx) => {
      const other = await foreign(ctx);
      await configure(ctx);
      const selected = profile(mode);
      const email = ctx.uniqueEmail("default-publication");
      const owner = ctx.actor("default-owner", selected).client;
      const signup = await owner.signUp.email({
        email,
        password: "password123",
        name: "Default Lifetime Owner",
      });
      expect(signup.error).toBeNull();

      await configure(ctx);
      const otp = await owner.emailOtp.sendVerificationOtp({
        email: ctx.uniqueEmail("default-otp"),
        type: "sign-in",
      });
      expect(otp.error).toBeNull();

      const magic = await owner.signIn.magicLink({
        email: ctx.uniqueEmail("default-magic"),
        metadata: { mode: "actual default" },
      });
      expect(magic.error).toBeNull();

      const ott = createAuthClient({
        baseURL: `${ctx.baseURL}${authProfilePath(selected)}`,
        plugins: [oneTimeTokenClient()],
        fetchOptions: { customFetchImpl: ctx.actor("default-owner", selected).fetch },
      });
      const transfer = await ott.oneTimeToken.generate();
      expect(transfer.error).toBeNull();

      const after = await state(ctx);
      unchanged(other, after);
      const response = await fetch(`${ctx.baseURL}/__test/server-api/verification-storage`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ operation: "backend-state" }),
      });
      expect(response.status).toBe(200);

      const backend = (await response.json()) as Row;
      const sets = backend.cacheEvents.filter(
        (row: Row) => row.operation === "set" && row.key.startsWith("verification:"),
      );
      expect(sets).toHaveLength(3);

      const publications = [];

      for (const publication of sets) {
        const before = backend.events.find(
          (row: Row) =>
            row.stage === "create-before" &&
            row.data.identifier === publication.value.identifier &&
            row.data.expiresAt === publication.value.expiresAt,
        );
        expect(before).toBeDefined();

        const expiry = Date.parse(publication.value.expiresAt);
        const earliest = Date.parse(before.executedAt);
        const latest = Date.parse(publication.executedAt);
        expect(latest).toBeGreaterThanOrEqual(earliest);
        expect(publication.ttl).toBeGreaterThanOrEqual(
          Math.max(Math.floor((expiry - latest) / 1000), 0),
        );
        expect(publication.ttl).toBeLessThanOrEqual(
          Math.max(Math.floor((expiry - earliest) / 1000), 0),
        );

        publications.push({
          publication,
          computationInterval: { startedAt: before.executedAt, finishedAt: publication.executedAt },
          expiresAt: publication.value.expiresAt,
        });
      }

      return publicationObservation(ctx, {
        foreign: other,
        signup,
        otp,
        magic,
        transfer,
        after,
        publications,
      });
    },
    [
      "POST /email-otp/send-verification-otp",
      "POST /sign-in/magic-link",
      "GET /one-time-token/generate",
    ],
  );
}
