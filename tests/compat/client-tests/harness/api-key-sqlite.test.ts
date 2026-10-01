import { Database } from "bun:sqlite";
import { expect, test } from "bun:test";
import { betterAuth } from "better-auth";
import { apiKey } from "@better-auth/api-key";
import { getMigrations } from "better-auth/db/migration";
import { createHash } from "node:crypto";
import { compareValues } from "../support/compare";
import { normalizeClientValue } from "../support/normalize";

type Data = Record<string, any>;
async function capture(baseURL: string) {
  const startedAt = Date.now(), database = new Database(":memory:");
  const auth = betterAuth({ baseURL, secret: "sqlite-key-harness-application-secret32", database,
    emailAndPassword: { enabled: true }, rateLimit: { enabled: false },
    plugins: [apiKey({ defaultPrefix: "😀", defaultKeyLength: 16,
      startingCharactersConfig: { charactersLength: 1 }, rateLimit: { enabled: false } })],
  });
  try {
    await (await getMigrations(auth.options)).runMigrations();
    const owner = await auth.api.signUpEmail({ body: { email: "owner@harness.local", name: "Owner", password: "password123" } });
    const foreign = await auth.api.signUpEmail({ body: { email: "foreign@harness.local", name: "Foreign", password: "password123" } });
    const issued = await auth.api.createApiKey({ body: { userId: owner.user.id, name: "owner-key" } });
    const foreignIssued = await auth.api.createApiKey({ body: { userId: foreign.user.id, name: "foreign-key" } });
    // The direct read is authenticated with the actual signed creation cookie.
    // Use the real API handler response to obtain that cookie, without inventing
    // a session credential from the unsigned token returned by sign-up.
    const login = await auth.api.signInEmail({ body: { email: "owner@harness.local", password: "password123" }, asResponse: true });
    const cookie = login.headers.getSetCookie().map(value => value.split(";")[0]).join("; ");
    const publicRead = await auth.api.getApiKey({ query: { id: issued.id }, headers: new Headers({ cookie }) });
    const rows = database.query('SELECT *,hex(CAST(start AS BLOB)) AS startHex,typeof(start) AS startType FROM apikey ORDER BY name,id').all().map(raw => {
      const row = { ...raw as Data };
      row.enabled = !!row.enabled; row.rateLimitEnabled = !!row.rateLimitEnabled;
      for (const field of ["createdAt", "updatedAt", "expiresAt", "lastRequest", "lastRefillAt"])
        if (row[field] !== null) row[field] = new Date(row[field]).toISOString();
      return row;
    });
    for (const key of [issued, foreignIssued]) {
      const stored = rows.find(row => row.id === key.id)!;
      expect(key.key).toMatch(/^😀[A-Za-z]{16}$/);
      expect(stored.referenceId).toBe(key.referenceId);
      expect(stored.key).toBe(createHash("sha256").update(key.key).digest("base64url"));
      expect(stored.startHex).toBe("EDA0BD"); expect(stored.startType).toBe("text");
      expect(stored.start).toBe("���"); expect(key.start).toBe(stored.start);
    }
    expect(publicRead.start).toBe("���"); expect(publicRead.id).toBe(issued.id);
    expect(issued.key).not.toBe(foreignIssued.key);
    return { value: normalizeClientValue({ owner, foreign, issued, foreignIssued, publicRead, stored: { keys: rows } }) as Data, startedAt, finishedAt: Date.now() };
  } finally { database.close(); }
}

test("actual Source API-key SQLite receipts derive hashes UTF16 cuts readback and foreign credential relationships", async () => {
  const left = await capture("http://localhost:3100"), right = await capture("http://localhost:3200");
  const context = { leftBaseURL: "http://localhost:3100", rightBaseURL: "http://localhost:3200", leftStartedAt: left.startedAt, leftFinishedAt: left.finishedAt, rightStartedAt: right.startedAt, rightFinishedAt: right.finishedAt };
  expect(compareValues(left.value, right.value, context)).toEqual([]);
  const ownerRow = (value: Data) => value.stored.keys.find((row: Data) => row.id === value.issued.id) as Data;
  const foreignRow = (value: Data) => value.stored.keys.find((row: Data) => row.id === value.foreignIssued.id) as Data;
  const mutations: ((value: Data) => void)[] = [
    value => { ownerRow(value).key = foreignRow(value).key; },
    value => { ownerRow(value).key = value.issued.key; },
    value => { ownerRow(value).startHex = "EDA0BC"; },
    value => { ownerRow(value).startHex = "EFBFBDEFBFBDEFBFBD"; },
    value => { ownerRow(value).startType = "blob"; },
    value => { ownerRow(value).start = "�"; },
    value => { value.issued.key = value.foreignIssued.key; },
    value => { value.publicRead.start = "�"; },
    value => { ownerRow(value).referenceId = value.foreign.user.id; },
    value => { ownerRow(value).enabled = false; },
    value => { delete ownerRow(value).startHex; },
    value => { delete value.issued; },
    value => { delete value.foreignIssued; },
    value => { value.metadata = value.stored; delete value.stored; },
  ];
  for (const mutate of mutations) {
    const changed = structuredClone(right.value); mutate(changed);
    expect(compareValues(left.value, changed, context).length).toBeGreaterThan(0);
  }
  // Matching corruption on both sides must still fail independent derivation.
  // Plaintext storage is also a supported configuration: changing its mode on
  // just one side is rejected above, while equal valid modes remain admissible.
  for (const mutate of [mutations[0]!, ...mutations.slice(2, 6)]) {
    const a = structuredClone(left.value), b = structuredClone(right.value); mutate(a); mutate(b);
    expect(compareValues(a, b, context).length).toBeGreaterThan(0);
  }
});
