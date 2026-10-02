import { Database } from "bun:sqlite";
import { AsyncLocalStorage } from "node:async_hooks";
import { randomBytes, randomInt } from "node:crypto";
import { betterAuth, type BetterAuthOptions } from "better-auth";
import { verifyPassword } from "better-auth/crypto";
import { getMigrations } from "better-auth/db/migration";
import { emailOTP, magicLink, oneTimeToken } from "better-auth/plugins";
import { createAuthClient } from "better-auth/client";
import { emailOTPClient, magicLinkClient, oneTimeTokenClient } from "better-auth/client/plugins";
import { expect, test } from "bun:test";
import { compareValues, type ComparisonContext } from "../support/compare";
import { createTracingFetch, requestWindow, type TraceEntry } from "../support/trace";
import { normalizeClientValue } from "../support/normalize";
import { verificationPublicationObserver } from "../support/verification-publication";

type Row = Record<string, any>;
const secret = "verification-publication-application-secret32";
const clone = <T>(value: T): T => JSON.parse(JSON.stringify(value));
const profile = (mode: "cache" | "mixed") => `/__test/profiles/verification-storage-${mode}-default/api/auth`;

async function source(mode: "cache" | "mixed", generators: {otp: string; magic: string; transfer: string}) {
  const db = new Database(":memory:"), frames = new AsyncLocalStorage<Row>();
  const publications: Row[] = [], deliveries: Row[] = [], backendEvents: Row[] = [];
  const cache = new Map<string, {rawValue: string; expiresAt: string}>();
  let handler: (request: Request) => Promise<Response>;
  const server = Bun.serve({port: 0, hostname: "127.0.0.1", async fetch(request) {
    const path = new URL(request.url).pathname;
    if (path === verificationPublicationObserver && request.method === "GET") return Response.json({publications, deliveries});
    if (path === "/__test/verification-publication-backend" && request.method === "GET") {
      return Response.json({publications, deliveries, backend: {
        events: backendEvents, cache: [...cache].map(([key, entry]) => ({key, ...entry, value: JSON.parse(entry.rawValue)})),
        verificationRows: db.query("SELECT * FROM verification ORDER BY createdAt").all(),
        users: db.query("SELECT * FROM user").all(), accounts: db.query("SELECT * FROM account").all(), sessions: db.query("SELECT * FROM session").all(),
      }});
    }
    const frame: Row = {request: {method: request.method, path, cookie: request.headers.get("cookie"), body: request.method === "GET" ? null : await request.clone().json(), startedAt: new Date().toISOString()}};
    return frames.run(frame, async () => {
      const response = await handler(request);
      frame.request.finishedAt = new Date().toISOString();
      return response;
    });
  }});
  const baseURL = server.url.origin;
  const options = {
    baseURL, basePath: profile(mode), secret, database: db, rateLimit: {enabled: false},
    emailAndPassword: {enabled: true}, session: {storeSessionInDatabase: true}, verification: {storeInDatabase: mode === "mixed", storeIdentifier: "hashed"},
    secondaryStorage: {
      async set(key: string, rawValue: string, ttl?: number) {
        if (typeof ttl !== "number") throw new Error("Actual owner must supply cache TTL");
        const executedAt = new Date().toISOString(), value = JSON.parse(rawValue), storedAt = Date.now();
        const storageExpiresAt = new Date(storedAt + ttl * 1000).toISOString();
        const event = {operation: "set", key, rawValue, value, ttl, executedAt, storedAt: new Date(storedAt).toISOString(), storageExpiresAt};
        backendEvents.push(event); cache.set(key, {rawValue, expiresAt: storageExpiresAt});
        if (key.startsWith("verification:")) {
          const frame = frames.getStore()!;
          frame.pending.set = event; publications.push(frame.pending);
        }
      },
      async get(key: string) { backendEvents.push({operation: "get", key}); const entry = cache.get(key); return entry && Date.parse(entry.expiresAt) > Date.now() ? entry.rawValue : null; },
      async delete(key: string) { backendEvents.push({operation: "delete", key}); cache.delete(key); },
      async getAndDelete(key: string) { const entry = cache.get(key); cache.delete(key); return entry && Date.parse(entry.expiresAt) > Date.now() ? entry.rawValue : null; },
      async increment(key: string) { const value = Number(cache.get(key)?.rawValue ?? "0") + 1; cache.set(key, {rawValue: String(value), expiresAt: new Date(Date.now() + 1000).toISOString()}); return value; },
    },
    databaseHooks: {verification: {create: {
      async before(data) {
        const frame = frames.getStore()!;
        frame.pending = {request: frame.request, before: {snapshot: clone(data), executedAt: new Date().toISOString()}};
      },
      async after(data) { frames.getStore()!.pending.snapshot = clone(data); },
    }}},
    plugins: [emailOTP({generateOTP: () => generators.otp, async sendVerificationOTP(data) { const delivery = clone(data); frames.getStore()!.pending.delivery = delivery; deliveries.push(delivery); }}),
      magicLink({generateToken: async () => generators.magic, async sendMagicLink(data) { const delivery = clone(data); frames.getStore()!.pending.delivery = delivery; deliveries.push(delivery); }}),
      oneTimeToken({generateToken: async () => generators.transfer})],
  } satisfies BetterAuthOptions;
  await (await getMigrations(options)).runMigrations();
  // Cache-only instances omit the adapter verification schema. The full backend
  // diagnostic still observes the independently created physical table.
  db.exec("CREATE TABLE IF NOT EXISTS verification (id TEXT PRIMARY KEY, identifier TEXT, value TEXT, expiresAt INTEGER, createdAt INTEGER, updatedAt INTEGER)");
  handler = betterAuth(options).handler;
  const traces: TraceEntry[] = [], fetch = createTracingFetch(baseURL, "owner", traces, profile(mode));
  const client = createAuthClient({baseURL: `${baseURL}${profile(mode)}`, plugins: [emailOTPClient(), magicLinkClient(), oneTimeTokenClient()], fetchOptions: {customFetchImpl: fetch}});
  return {db, server, baseURL, traces, fetch, client};
}

async function run(mode: "cache" | "mixed", generators: {otp: string; magic: string; transfer: string}, email: string) {
  const instance = await source(mode, generators), startedAt = Date.now();
  try {
    const foreign = await instance.client.signUp.email({email: `foreign-${email}`, password: "password123", name: "Foreign Owner"});
    expect(foreign.error).toBeNull();
    const before = await (await fetch(`${instance.baseURL}/__test/verification-publication-backend`)).json() as Row;
    const signup = await instance.client.signUp.email({email, password: "password123", name: "Publication Owner"});
    expect(signup.error).toBeNull();
    const otp = await instance.client.emailOtp.sendVerificationOtp({email: `otp-${email}`, type: "sign-in"});
    expect(otp.error).toBeNull();
    const magic = await instance.client.signIn.magicLink({email: `magic-${email}`, name: "Mailbox Owner", metadata: {ttl: 17, applicationData: "literal"}});
    expect(magic.error).toBeNull();
    const transfer = await instance.client.oneTimeToken.generate();
    expect(transfer.error).toBeNull();
    const foreignFetch = createTracingFetch(instance.baseURL, "foreign-producer", instance.traces, profile(mode));
    const foreignClient = createAuthClient({baseURL: `${instance.baseURL}${profile(mode)}`, plugins: [emailOTPClient()], fetchOptions: {customFetchImpl: foreignFetch}});
    const foreignOtp = await foreignClient.emailOtp.sendVerificationOtp({email: `foreign-otp-${email}`, type: "sign-in"});
    expect(foreignOtp.error).toBeNull();
    const observer = await instance.fetch(`${instance.baseURL}${verificationPublicationObserver}`);
    expect(observer.status).toBe(200);
    const body = await observer.json() as Row;
    expect(body.publications).toHaveLength(4);
    const complete = await (await fetch(`${instance.baseURL}/__test/verification-publication-backend`)).json() as Row;
    // Retain every backend key, raw serialized value, actual cache deadline, and
    // physical row outside the comparer as well as in the complete trace.
    const artifact = `/tmp/issue302-source-${mode}-${instance.server.port}-${Date.now()}.json`;
    await Bun.write(artifact, JSON.stringify({body, before, complete, traces: instance.traces, windows: instance.traces.map(t => t[requestWindow])}, null, 2));
    for (const publication of body.publications) {
      expect(publication.set.rawValue).toBe(JSON.stringify(publication.snapshot));
      expect(publication.set.value).toEqual(publication.snapshot);
      expect(Date.parse(publication.set.storageExpiresAt)).toBe(Date.parse(publication.set.storedAt) + publication.set.ttl * 1000);
      expect(publication.set.key).toBe(`verification:${publication.before.snapshot.identifier}`);
      const earliest = Date.parse(publication.before.executedAt), latest = Date.parse(publication.set.executedAt), expiry = Date.parse(publication.snapshot.expiresAt);
      expect(publication.set.ttl).toBeGreaterThanOrEqual(Math.floor((expiry - latest) / 1000));
      expect(publication.set.ttl).toBeLessThanOrEqual(Math.floor((expiry - earliest) / 1000));
    }
    expect(complete.backend.users).toHaveLength(2);
    expect(complete.backend.accounts).toHaveLength(2);
    expect(complete.backend.sessions).toHaveLength(2);
    expect(complete.backend.verificationRows).toHaveLength(mode === "mixed" ? 4 : 0);
    for (const field of ["users", "accounts", "sessions"]) {
      const rows = before.backend[field] as Row[];
      expect(rows).toHaveLength(1);
      expect(complete.backend[field].find((r: Row) => r.id === rows[0]!.id)).toEqual(rows[0]);
    }
    for (const entry of before.backend.cache) expect(complete.backend.cache.find((r: Row) => r.key === entry.key)).toEqual(entry);
    for (const account of complete.backend.accounts) expect(await verifyPassword({password: "password123", hash: account.password})).toBe(true);
    return {root: normalizeClientValue({observation: {foreign, signup, otp, magic, transfer, verificationPublications: body.publications, aliases: body.publications.map((p: Row) => p.set)}, traces: instance.traces}), traces: instance.traces, startedAt, finishedAt: Date.now(), baseURL: instance.baseURL, artifact};
  } finally {instance.server.stop(true); instance.db.close();}
}

for (const mode of ["cache", "mixed"] as const) test(`actual Source ${mode} default300/180 verification publications retain exact bounded TTLs and reject forged receipts`, async () => {
  const generators = {otp: String(randomInt(100000, 1000000)), magic: randomBytes(24).toString("base64url"), transfer: randomBytes(24).toString("base64url")};
  const email = `${randomBytes(12).toString("hex")}@test.com`;
  const a = await run(mode, generators, email), b = await run(mode, generators, email);
  const context: ComparisonContext = {leftBaseURL: a.baseURL, rightBaseURL: b.baseURL, leftStartedAt: a.startedAt, rightStartedAt: b.startedAt, leftFinishedAt: a.finishedAt, rightFinishedAt: b.finishedAt, sessionCookieSecret: secret,
    leftRequestWindows: a.traces.map(t => t[requestWindow]), rightRequestWindows: b.traces.map(t => t[requestWindow])};
  const differences = compareValues(a.root, b.root, context);
  expect(differences).toEqual([]);
  const owning = "observation.verificationPublications.0.set.ttl";
  const original = b.root as Row;
  const controls: ((value: Row) => void)[] = [
    value => value.observation.verificationPublications[0].set.ttl -= 2,
    value => value.observation.verificationPublications[0].set.ttl = String(value.observation.verificationPublications[0].set.ttl),
    value => value.observation.verificationPublications[0].set.ttl += 1,
    value => value.observation.verificationPublications[0].snapshot.expiresAt = new Date(Date.parse(value.observation.verificationPublications[0].snapshot.expiresAt) + 1000).toISOString(),
    value => delete value.observation.verificationPublications[0].before.executedAt,
    value => value.observation.verificationPublications[0].before.executedAt = new Date(a.startedAt - 60000).toISOString(),
    value => value.observation.verificationPublications[0].request = clone(value.observation.verificationPublications[1].request),
    value => value.observation.verificationPublications[0] = clone(value.observation.verificationPublications[3]),
    value => value.observation.verificationPublications[0].set.rawValue += " ",
    value => value.observation.verificationPublications[0].set.storageExpiresAt = new Date(Date.parse(value.observation.verificationPublications[0].set.storageExpiresAt) + 1000).toISOString(),
    value => value.observation.verificationPublications[0].set.value.identifier = "foreign-identifier",
  ];
  for (const change of controls) {
    const bad = clone(original); change(bad);
    expect(compareValues(a.root, bad, context).some(d => d.path === owning)).toBe(true);
  }
  const missing = {...context, rightRequestWindows: context.rightRequestWindows!.map((w, i) => i === 2 ? undefined : w)};
  expect(compareValues(a.root, b.root, missing).some(d => d.path === owning)).toBe(true);
  // Even internally self-consistent forged observer records fail their actual
  // request/deadline floor rather than receiving a general one-second tolerance.
  for (const change of [
    (p: Row) => { p.set.ttl -= 2; },
    (p: Row) => { p.set.storageExpiresAt = new Date(Date.parse(p.set.storageExpiresAt) + 1000).toISOString(); },
    (p: Row) => { p.before.executedAt = new Date(Date.parse(p.request.startedAt) - 1).toISOString(); },
    (p: Row) => { delete p.before.executedAt; },
    (p: Row) => { p.set.executedAt = new Date(Date.parse(p.request.finishedAt) + 1).toISOString(); },
    (p: Row) => { p.set.ttl = 0; p.snapshot.expiresAt = p.set.executedAt; p.before.snapshot.expiresAt = p.snapshot.expiresAt; p.set.value.expiresAt = p.snapshot.expiresAt; p.set.rawValue = JSON.stringify(p.snapshot); },
    (p: Row) => { p.request = clone(original.observation.verificationPublications[1].request); },
    (p: Row) => { p.snapshot.expiresAt = new Date(Date.parse(p.snapshot.expiresAt) + 1000).toISOString(); p.before.snapshot.expiresAt = p.snapshot.expiresAt; p.set.value.expiresAt = p.snapshot.expiresAt; p.set.rawValue = JSON.stringify(p.snapshot); },
  ]) {
    const bad = clone(original), p = bad.observation.verificationPublications[0]; change(p);
    const observer = bad.traces.find((t: Row) => t.path === verificationPublicationObserver);
    observer.responseBody.publications[0] = clone(p);
    expect(compareValues(a.root, bad, context).some(d => d.path === owning)).toBe(true);
  }
  const foreign = clone(original);
  foreign.observation.verificationPublications[0] = clone(original.observation.verificationPublications[3]);
  foreign.traces.find((t: Row) => t.path === verificationPublicationObserver).responseBody.publications[0] = clone(foreign.observation.verificationPublications[0]);
  expect(compareValues(a.root, foreign, context).some(d => d.path === owning)).toBe(true);
  for (const key of ["metadata", "applicationData", "additionalFields", "custom"]) {
    const left = {...a.root as Row, [key]: {ttl: 300}}, right = {...original, [key]: {ttl: 299}};
    expect(compareValues(left, right, context).some(d => d.path === `${key}.ttl`)).toBe(true);
  }
  const unknown = {...original, observation: {...original.observation, arbitrary: {ttl: 299}}};
  expect(compareValues({...a.root as Row, observation: {...(a.root as Row).observation, arbitrary: {ttl: 300}}}, unknown, context).some(d => d.path === "observation.arbitrary.ttl")).toBe(true);
  const unrelated = {operation: "set", key: "verification:application", rawValue: "literal", ttl: 300};
  expect(compareValues(unrelated, clone(unrelated), context)).toEqual([]);
  expect(compareValues(unrelated, {...unrelated, ttl: 299}, context).some(d => d.path === "ttl")).toBe(true);
  const alias = clone(original); alias.observation.aliases[0].ttl -= 2;
  expect(compareValues(a.root, alias, context).some(d => d.path === "observation.aliases.0.ttl")).toBe(true);
}, 30000);
