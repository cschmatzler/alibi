import { Database } from "bun:sqlite";
import { expect, test } from "bun:test";

import { apiKey } from "@better-auth/api-key";
import { betterAuth } from "better-auth";
import { getMigrations } from "better-auth/db/migration";

import { compareValues } from "../support/compare";
import { normalizeClientValue } from "../support/normalize";

type Data = Record<string, any>;

async function capture(baseURL: string) {
  const startedAt = Date.now();
  const database = new Database(":memory:");
  const entries = new Map<string, { value: string; expiresAt: number | null }>();
  const auth = betterAuth({
    baseURL,
    secret: "application-storage-harness-secret32",
    database,
    emailAndPassword: { enabled: true },
    rateLimit: { enabled: false },
    secondaryStorage: {
      async get(index) {
        return entries.get(index)?.value ?? null;
      },
      async set(index, value, ttl) {
        entries.set(index, {
          value,
          expiresAt: ttl === undefined ? null : Date.now() + ttl * 1000,
        });
      },
      async delete(index) {
        entries.delete(index);
      },
      async getAndDelete(index) {
        const value = entries.get(index)?.value ?? null;
        entries.delete(index);
        return value;
      },
      async increment(index, ttl) {
        const entry = entries.get(index);
        const value = Number(entry?.value ?? 0) + 1;
        entries.set(index, {
          value: String(value),
          expiresAt: entry?.expiresAt ?? Date.now() + ttl * 1000,
        });
        return value;
      },
    },
    plugins: [
      apiKey({
        storage: "secondary-storage",
        enableMetadata: true,
        rateLimit: { enabled: false },
        keyExpiration: { minExpiresIn: 0 },
      }),
    ],
  });
  try {
    await (await getMigrations(auth.options)).runMigrations();
    const owner = await auth.api.signUpEmail({
      body: { email: "owner@storage.local", name: "Owner", password: "password123" },
    });
    const foreign = await auth.api.signUpEmail({
      body: { email: "foreign@storage.local", name: "Foreign", password: "password123" },
    });
    const issued = await auth.api.createApiKey({
      body: {
        userId: owner.user.id,
        name: "owner-key",
        expiresIn: 120,
        metadata: { key: "literal-application-key" },
      },
    });
    const foreignIssued = await auth.api.createApiKey({
      body: { userId: foreign.user.id, name: "foreign-key" },
    });
    const storage = [...entries]
      .filter(([index]) => index.startsWith("api-key:"))
      .map(([index, entry]) => {
        const value = JSON.parse(entry.value);
        if (index.startsWith("api-key:by-ref:")) {
          return {
            namespace: "reference",
            lookup: { referenceId: index.slice(15) },
            value: value.map((id: string) => ({ id })),
            expiresAt: null,
          };
        }
        return {
          namespace: index.startsWith("api-key:by-id:") ? "id" : "hash",
          lookup: index.startsWith("api-key:by-id:")
            ? { id: index.slice(14) }
            : { key: index.slice(8) },
          value,
          expiresAt: entry.expiresAt === null ? null : new Date(entry.expiresAt).toISOString(),
        };
      })
      .sort((a, b) =>
        `${a.namespace}:${a.value.name ?? (a.lookup.referenceId === owner.user.id ? "owner" : "foreign")}`.localeCompare(
          `${b.namespace}:${b.value.name ?? (b.lookup.referenceId === owner.user.id ? "owner" : "foreign")}`,
        ),
      );
    return {
      value: normalizeClientValue({ owner, foreign, issued, foreignIssued, storage }) as Data,
      startedAt,
      finishedAt: Date.now(),
    };
  } finally {
    database.close();
  }
}

test("actual Source application API-key receipts preserve hashes indexes owners lifetimes fields and literal metadata", async () => {
  const left = await capture("http://localhost:3100");
  const right = await capture("http://localhost:3200");
  const context = {
    leftBaseURL: "http://localhost:3100",
    rightBaseURL: "http://localhost:3200",
    leftStartedAt: left.startedAt,
    leftFinishedAt: left.finishedAt,
    rightStartedAt: right.startedAt,
    rightFinishedAt: right.finishedAt,
  };
  expect(compareValues(left.value, right.value, context)).toEqual([]);
  const target = (value: Data) =>
    value.storage.find(
      (entry: Data) => entry.namespace === "hash" && entry.value.id === value.issued.id,
    ) as Data;
  const foreign = (value: Data) =>
    value.storage.find(
      (entry: Data) => entry.namespace === "hash" && entry.value.id === value.foreignIssued.id,
    ) as Data;
  const controls: {
    change(value: Data): void;
    suffix: string;
    reason: RegExp;
    independentlyInvalid?: boolean;
  }[] = [
    {
      change(value) {
        target(value).value.key = foreign(value).value.key;
      },
      suffix: ".value.key",
      reason: /^Application API-key storage is not derived from its observed issuance$/,
      independentlyInvalid: true,
    },
    {
      change(value) {
        target(value).lookup.key = foreign(value).lookup.key;
      },
      suffix: ".lookup",
      reason: /^Application API-key index does not address its stored row$/,
      independentlyInvalid: true,
    },
    {
      change(value) {
        const entry = value.storage.find(
          (entry: Data) => entry.namespace === "id" && entry.value.id === value.issued.id,
        );
        entry.lookup.id = value.foreignIssued.id;
      },
      suffix: ".lookup",
      reason: /^Application API-key index does not address its stored row$/,
      independentlyInvalid: true,
    },
    {
      change(value) {
        target(value).value.start = "invented-prefix";
      },
      suffix: ".value.start",
      reason: /^Application API-key start is not an observed credential prefix$/,
      independentlyInvalid: true,
    },
    {
      change(value) {
        target(value).value.start = value.issued.start.substring(0, 1);
      },
      suffix: ".value.start",
      reason: /^Application API-key start differs from its observed issuance$/,
      independentlyInvalid: true,
    },
    {
      change(value) {
        target(value).value.start = null;
      },
      suffix: ".value.start",
      reason: /^Application API-key start differs from its observed issuance$/,
      independentlyInvalid: true,
    },
    {
      change(value) {
        target(value).value.prefix = "invented-prefix";
      },
      suffix: ".value.prefix",
      reason: /^Application API-key authority differs from its observed issuance$/,
      independentlyInvalid: true,
    },
    {
      change(value) {
        delete value.issued;
      },
      suffix: ".value.key",
      reason: /^Application API-key storage is not derived from its observed issuance$/,
      independentlyInvalid: true,
    },
    {
      change(value) {
        target(value).value.referenceId = value.foreign.user.id;
      },
      suffix: ".value.referenceId",
      reason: /^Application API-key authority differs from its observed issuance$/,
      independentlyInvalid: true,
    },
    {
      change(value) {
        target(value).value.configId = "foreign-configuration";
      },
      suffix: ".value.configId",
      reason: /^Application API-key authority differs from its observed issuance$/,
      independentlyInvalid: true,
    },
    {
      change(value) {
        target(value).value.remaining = 7;
      },
      suffix: ".value.remaining",
      reason: /^value or type differs$/,
    },
    {
      change(value) {
        target(value).expiresAt = new Date(
          Date.parse(target(value).expiresAt) + 60_000,
        ).toISOString();
      },
      suffix: ".expiresAt",
      reason: /^timestamp or lifetime differs:/,
    },
    {
      change(value) {
        target(value).expiresAt = "invalid expiry";
      },
      suffix: ".expiresAt",
      reason: /^Application API-key expiry is not a valid timestamp$/,
      independentlyInvalid: true,
    },
    {
      change(value) {
        target(value).value.metadata.key = "changed-application-key";
      },
      suffix: ".value.metadata.key",
      reason: /^value or type differs$/,
    },
    {
      change(value) {
        delete target(value).value.refillAmount;
      },
      suffix: ".value.refillAmount",
      reason: /^field presence differs$/,
    },
    {
      change(value) {
        value.storage.pop();
      },
      suffix: "storage",
      reason: /^array length differs$/,
    },
  ];
  for (const { change, suffix, reason, independentlyInvalid } of controls) {
    const changed = structuredClone(right.value);
    change(changed);
    expect(
      compareValues(left.value, changed, context).some(
        (difference) => difference.path.endsWith(suffix) && reason.test(difference.reason),
      ),
    ).toBe(true);
    if (independentlyInvalid) {
      const a = structuredClone(left.value);
      const b = structuredClone(right.value);
      change(a);
      change(b);
      expect(
        compareValues(a, b, context).some(
          (difference) => difference.path.endsWith(suffix) && reason.test(difference.reason),
        ),
      ).toBe(true);
    }
  }
});
