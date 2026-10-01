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
  const rowPath = (value: Data, foreign: boolean, field: string) =>
    `stored.keys.${value.stored.keys.findIndex((row: Data) => row.id === (foreign ? value.foreignIssued.id : value.issued.id))}.${field}`;
  const ownerPath = (field: string) => (value: Data) => rowPath(value, false, field);
  const mutations: { mutate: (value: Data) => void; path: (value: Data) => string; reason: string; independentlyInvalid?: boolean }[] = [
    { mutate: value => { ownerRow(value).key = foreignRow(value).key; }, path: ownerPath("key"),
      reason: "SQLite API-key storage is not derived from its observed issuance", independentlyInvalid: true },
    { mutate: value => { ownerRow(value).key = value.issued.key; }, path: ownerPath("key"),
      reason: "SQLite API-key plaintext-versus-hashed storage differs" },
    { mutate: value => { ownerRow(value).startHex = "EDA0BC"; }, path: ownerPath("startHex"),
      reason: "SQLite API-key bytes are not an actual UTF-16 credential prefix", independentlyInvalid: true },
    { mutate: value => { ownerRow(value).startHex = "EFBFBDEFBFBDEFBFBD"; }, path: ownerPath("startHex"),
      reason: "SQLite API-key bytes are not an actual UTF-16 credential prefix", independentlyInvalid: true },
    { mutate: value => { ownerRow(value).startType = "blob"; }, path: ownerPath("startType"),
      reason: "SQLite API-key storage type is neither text nor null", independentlyInvalid: true },
    { mutate: value => { ownerRow(value).start = "�"; }, path: ownerPath("start"),
      reason: "SQLite API-key text readback disagrees with its actual bytes", independentlyInvalid: true },
    { mutate: value => { value.issued.key = value.foreignIssued.key; }, path: ownerPath("key"),
      reason: "SQLite API-key storage is not derived from its observed issuance" },
    { mutate: value => { value.publicRead.start = "�"; }, path: () => "publicRead.start",
      reason: "API key stored-prefix relationship differs" },
    { mutate: value => { ownerRow(value).referenceId = value.foreign.user.id; }, path: ownerPath("referenceId"),
      reason: "identity relationship or token rotation differs" },
    { mutate: value => { ownerRow(value).enabled = false; }, path: ownerPath("enabled"), reason: "value or type differs" },
    { mutate: value => { delete ownerRow(value).startHex; }, path: ownerPath("startHex"), reason: "field presence differs" },
    { mutate: value => { delete value.issued; }, path: ownerPath("key"),
      reason: "SQLite API-key storage is not derived from its observed issuance" },
    { mutate: value => { delete value.foreignIssued; }, path: value => rowPath(value, true, "key"),
      reason: "SQLite API-key storage is not derived from its observed issuance" },
    { mutate: value => { value.metadata = value.stored; delete value.stored; }, path: () => "publicRead.start",
      reason: "API key stored-prefix relationship differs" },
  ];
  for (const { mutate, path, reason } of mutations) {
    const changed = structuredClone(right.value); mutate(changed);
    expect(compareValues(left.value, changed, context)).toContainEqual({ path: path(right.value), reason });
  }
  // Matching corruption on both sides must still fail independent derivation.
  // Plaintext storage is also a supported configuration: changing its mode on
  // just one side is rejected above, while equal valid modes remain admissible.
  for (const { mutate, path, reason } of mutations.filter(control => control.independentlyInvalid)) {
    const a = structuredClone(left.value), b = structuredClone(right.value); mutate(a); mutate(b);
    expect(compareValues(a, b, context)).toContainEqual({ path: path(left.value), reason });
  }
});
