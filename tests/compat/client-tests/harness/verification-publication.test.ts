import { Database } from "bun:sqlite";
import { AsyncLocalStorage } from "node:async_hooks";
import { createHash, randomBytes, randomInt } from "node:crypto";
import { betterAuth, type BetterAuthOptions } from "better-auth";
import { verifyPassword } from "better-auth/crypto";
import { getMigrations } from "better-auth/db/migration";
import { emailOTP, genericOAuth, magicLink, oneTimeToken } from "better-auth/plugins";
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

// For semantic controls, represent an observer that actually returned the
// invalid record. Its integrity receipt stays valid, so the claimed admission
// rule must detect the change rather than the unrelated tamper guard.
function observedMutation(context: ComparisonContext, root: Row): ComparisonContext {
  const index = root.traces.findIndex((trace: Row) => trace.path === verificationPublicationObserver);
  const digest = createHash("sha256").update(JSON.stringify(root.traces[index].responseBody)).digest("hex");
  return { ...context, rightRequestWindows: context.rightRequestWindows!.map((window, i) =>
    i === index ? { ...window!, verificationObserverDigest: digest } : window) };
}

async function source(mode: "cache" | "mixed", generators: {otp: string; magic: string; transfer: string}, extraEvidence = false, oauthEmail?: string) {
  const db = new Database(":memory:"), frames = new AsyncLocalStorage<Row>();
  const publications: Row[] = [], deliveries: Row[] = [], backendEvents: Row[] = [];
  const cache = new Map<string, {rawValue: string; expiresAt: string}>();
  const grants = new Map<string, Row>(), oauthReceipts: Row[] = [];
  let handler: (request: Request) => Promise<Response>;
  const server = Bun.serve({port: 0, hostname: "127.0.0.1", async fetch(request) {
    const path = new URL(request.url).pathname;
    if (oauthEmail && path === "/oauth/authorize") {
      const url = new URL(request.url), code = generators.transfer, accessToken = randomBytes(24).toString("base64url");
      const grant = {code, accessToken, authorization: Object.fromEntries(url.searchParams)};
      grants.set(code, grant); oauthReceipts.push({stage: "authorize", ...grant});
      const callback = new URL(url.searchParams.get("redirect_uri")!);
      callback.searchParams.set("state", url.searchParams.get("state")!); callback.searchParams.set("code", code);
      return Response.redirect(callback, 302);
    }
    if (oauthEmail && path === "/oauth/token") {
      const body = Object.fromEntries(new URLSearchParams(await request.text())), grant = grants.get(body.code!);
      oauthReceipts.push({stage: "grant", body});
      if (!grant || body.client_id !== "publication-client" || body.client_secret !== "publication-secret"
        || body.grant_type !== "authorization_code" || body.redirect_uri !== grant.authorization.redirect_uri
        || createHash("sha256").update(body.code_verifier!).digest("base64url") !== grant.authorization.code_challenge)
        return Response.json({error: "invalid_grant"}, {status: 400});
      return Response.json({access_token: grant.accessToken, token_type: "Bearer", expires_in: 3600});
    }
    if (oauthEmail && path === "/oauth/userinfo") {
      const authorization = request.headers.get("authorization");
      oauthReceipts.push({stage: "userinfo", authorization});
      if (![...grants.values()].some(grant => authorization === `Bearer ${grant.accessToken}`)) return new Response(null, {status: 401});
      return Response.json({id: "actual-publication-owner", name: "Publication Owner", email: `oauth-${oauthEmail}`, email_verified: true});
    }
    if (path === "/ok") return Response.json({completed: true});
    if (path === verificationPublicationObserver && request.method === "GET") return Response.json({publications, deliveries});
    if (path === "/__test/verification-publication-backend" && request.method === "GET") {
      return Response.json({publications, deliveries, oauthReceipts, backend: {
        events: backendEvents, cache: [...cache].map(([key, entry]) => ({key, ...entry, value: JSON.parse(entry.rawValue)})),
        verificationRows: db.query("SELECT * FROM verification ORDER BY createdAt").all(),
        users: db.query("SELECT * FROM user").all(), accounts: db.query("SELECT * FROM account").all(), sessions: db.query("SELECT * FROM session").all(),
      }});
    }
    const frame: Row = {request: {method: request.method, path, cookie: request.headers.get("cookie"), body: request.method === "GET" ? null : await request.clone().json(), startedAt: new Date().toISOString()}};
    if (extraEvidence) frame.request.applicationReceipt = {stage: "request", nested: {kept: true}};
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
        if (extraEvidence) Object.assign(event, {applicationReceipt: {stage: "set", nested: {kept: true}}});
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
        if (extraEvidence) {frame.pending.applicationReceipt = {stage: "outer", nested: {kept: true}}; frame.pending.before.applicationReceipt = {stage: "before", nested: {kept: true}};}
      },
      async after(data) { frames.getStore()!.pending.snapshot = clone(data); },
    }}},
    plugins: [emailOTP({generateOTP: () => generators.otp, async sendVerificationOTP(data) { const delivery = clone(data); frames.getStore()!.pending.delivery = delivery; deliveries.push(delivery); }}),
      magicLink({generateToken: async () => generators.magic, async sendMagicLink(data) { const delivery = clone(data); frames.getStore()!.pending.delivery = delivery; deliveries.push(delivery); }}),
      oneTimeToken({generateToken: async () => generators.transfer}),
      ...(oauthEmail ? [genericOAuth({config: [{providerId: "publication", clientId: "publication-client", clientSecret: "publication-secret",
        authorizationUrl: `${baseURL}/oauth/authorize`, tokenUrl: `${baseURL}/oauth/token`, userInfoUrl: `${baseURL}/oauth/userinfo`, scopes: ["profile", "email"]}]})] : [])],
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

async function run(mode: "cache" | "mixed", generators: {otp: string; magic: string; transfer: string}, email: string, extraEvidence = false) {
  const instance = await source(mode, generators, extraEvidence), startedAt = Date.now();
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
    // Check complete backend values independently of the cross-runtime comparer.
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
    return {root: normalizeClientValue({observation: {foreign, signup, otp, magic, transfer, verificationPublications: body.publications, aliases: body.publications.map((p: Row) => p.set)}, traces: instance.traces}), traces: instance.traces, startedAt, finishedAt: Date.now(), baseURL: instance.baseURL};
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
  // Genuine right-side application receipts are captured before HTTP delivery,
  // so their original private observer digest is valid. They exercise field
  // presence in every admitted dictionary rather than failing digest integrity.
  const extra = await run(mode, generators, email, true);
  const extraContext = {...context, rightBaseURL: extra.baseURL, rightStartedAt: extra.startedAt, rightFinishedAt: extra.finishedAt,
    rightRequestWindows: extra.traces.map(t => t[requestWindow])};
  const fields = compareValues(a.root, extra.root, extraContext);
  for (const path of ["applicationReceipt", "request.applicationReceipt", "before.applicationReceipt", "set.applicationReceipt"])
    expect(fields.some(d => d.path === `observation.verificationPublications.0.${path}` && d.reason === "field presence differs")).toBe(true);
  expect(fields.some(d => d.path === "observation.aliases.0.applicationReceipt" && d.reason === "field presence differs")).toBe(true);
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
  const observerIndex = original.traces.findIndex((t: Row) => t.path === verificationPublicationObserver);
  for (const digest of [undefined, "0".repeat(64), 123]) {
    const changed = {...context, rightRequestWindows: context.rightRequestWindows!.map((w, i) => i === observerIndex ? {...w!, verificationObserverDigest: digest as any} : w)};
    expect(compareValues(a.root, b.root, changed).some(d => d.path === owning)).toBe(true);
  }
  for (const endpoints of [{startedAt: NaN}, {finishedAt: Infinity}, {startedAt: "0"}, {finishedAt: -1}]) {
    const changed = {...context, rightRequestWindows: context.rightRequestWindows!.map((w, i) => i === 2 ? {...w!, ...endpoints} as any : w)};
    expect(compareValues(a.root, b.root, changed).some(d => d.path === owning)).toBe(true);
  }
  // Even internally self-consistent forged observer records fail their actual
  // request/deadline floor rather than receiving a general one-second tolerance.
  for (const change of [
    (p: Row) => { p.set.ttl -= 2; p.set.storageExpiresAt = new Date(Date.parse(p.set.storedAt) + p.set.ttl * 1000).toISOString(); },
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
    bad.observation.aliases[0] = clone(p.set);
    expect(compareValues(a.root, bad, observedMutation(context, bad)).some(d => d.path === owning)).toBe(true);
  }
  const foreign = clone(original);
  foreign.observation.verificationPublications[0] = clone(original.observation.verificationPublications[3]);
  foreign.traces.find((t: Row) => t.path === verificationPublicationObserver).responseBody.publications[0] = clone(foreign.observation.verificationPublications[0]);
  expect(compareValues(a.root, foreign, observedMutation(context, foreign)).some(d => d.path === owning)).toBe(true);
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

async function runOAuth(mode: "cache" | "mixed", email: string, authorizationCode: string, extraEvidence = false) {
  const instance = await source(mode, {otp: "unused", magic: "unused", transfer: authorizationCode}, extraEvidence, email), startedAt = Date.now();
  try {
    const foreign = await instance.client.signUp.email({email: `foreign-${email}`, password: "password123", name: "Foreign Owner"});
    expect(foreign.error).toBeNull();
    const before = await (await fetch(`${instance.baseURL}/__test/verification-publication-backend`)).json() as Row;
    const signup = await instance.client.signUp.email({email, password: "password123", name: "Publication Owner"});
    expect(signup.error).toBeNull();
    const oauth = await instance.client.signIn.social({provider: "publication", callbackURL: `${instance.baseURL}/ok`, disableRedirect: true});
    expect(oauth.error).toBeNull();
    const foreignFetch = createTracingFetch(instance.baseURL, "foreign-producer", instance.traces, profile(mode));
    const foreignClient = createAuthClient({baseURL: `${instance.baseURL}${profile(mode)}`, fetchOptions: {customFetchImpl: foreignFetch}});
    const foreignOauth = await foreignClient.signIn.social({provider: "publication", callbackURL: `${instance.baseURL}/ok`, disableRedirect: true});
    expect(foreignOauth.error).toBeNull();
    const observer = await instance.fetch(`${instance.baseURL}${verificationPublicationObserver}`);
    expect(observer.status).toBe(200);
    const body = await observer.json() as Row;
    expect(body.publications).toHaveLength(2);
    const issued = await (await fetch(`${instance.baseURL}/__test/verification-publication-backend`)).json() as Row;
    expect(typeof oauth.data!.url).toBe("string");
    const completed = await instance.fetch(oauth.data!.url!);
    expect(completed.status).toBe(200);
    expect(await completed.json()).toEqual({completed: true});
    const complete = await (await fetch(`${instance.baseURL}/__test/verification-publication-backend`)).json() as Row;
    for (const publication of body.publications) {
      const value = JSON.parse(publication.snapshot.value), expiry = Date.parse(publication.snapshot.expiresAt);
      expect(value.oauthState).toMatch(/^[a-zA-Z0-9_-]{32}$/);
      expect(value.codeVerifier).toMatch(/^[a-zA-Z0-9_-]{128}$/);
      expect(expiry).toBeGreaterThanOrEqual(Date.parse(publication.request.startedAt) + 600000);
      expect(expiry).toBeLessThanOrEqual(Date.parse(publication.request.finishedAt) + 600000);
      expect(value.expiresAt).toBeGreaterThanOrEqual(Date.parse(publication.request.startedAt) + 600000);
      expect(value.expiresAt).toBeLessThanOrEqual(Date.parse(publication.request.finishedAt) + 600000);
      expect(publication.set.rawValue).toBe(JSON.stringify(publication.snapshot));
      expect(publication.set.value).toEqual(publication.snapshot);
      expect(publication.set.key).toBe(`verification:${createHash("sha256").update(value.oauthState).digest("base64url")}`);
      expect(publication.set.ttl).toBeGreaterThanOrEqual(Math.floor((expiry - Date.parse(publication.set.executedAt)) / 1000));
      expect(publication.set.ttl).toBeLessThanOrEqual(Math.floor((expiry - Date.parse(publication.before.executedAt)) / 1000));
      expect(Date.parse(publication.set.storageExpiresAt)).toBe(Date.parse(publication.set.storedAt) + publication.set.ttl * 1000);
    }
    const primary = body.publications[0], ownedForeign = body.publications[1];
    expect(issued.backend.verificationRows).toHaveLength(mode === "mixed" ? 2 : 0);
    expect(complete.backend.verificationRows).toHaveLength(mode === "mixed" ? 1 : 0);
    expect(complete.backend.cache.some((entry: Row) => entry.key === primary.set.key)).toBe(false);
    expect(complete.backend.cache.find((entry: Row) => entry.key === ownedForeign.set.key)).toEqual(issued.backend.cache.find((entry: Row) => entry.key === ownedForeign.set.key));
    if (mode === "mixed") expect(complete.backend.verificationRows[0]).toEqual(issued.backend.verificationRows.find((entry: Row) => entry.identifier === ownedForeign.snapshot.identifier));
    expect(complete.oauthReceipts.map((receipt: Row) => receipt.stage)).toEqual(["authorize", "grant", "userinfo"]);
    expect(complete.oauthReceipts[1].body.code_verifier).toBe(JSON.parse(primary.snapshot.value).codeVerifier);
    expect(complete.backend.users).toHaveLength(3);
    expect(complete.backend.accounts).toHaveLength(3);
    expect(complete.backend.sessions).toHaveLength(3);
    for (const field of ["users", "accounts", "sessions"]) expect(complete.backend[field].find((entry: Row) => entry.id === before.backend[field][0].id)).toEqual(before.backend[field][0]);
    for (const entry of before.backend.cache) expect(complete.backend.cache.find((item: Row) => item.key === entry.key)).toEqual(entry);
    for (const account of complete.backend.accounts.filter((entry: Row) => entry.providerId === "credential")) expect(await verifyPassword({password: "password123", hash: account.password})).toBe(true);
    const root = normalizeClientValue({observation: {foreign, signup, oauth, foreignOauth, completed: {status: completed.status}, verificationPublications: body.publications, aliases: body.publications.map((publication: Row) => publication.set)}, traces: instance.traces});
    const finishedAt = Date.now(), windows = instance.traces.map(trace => trace[requestWindow]);
    return {root, windows, startedAt, finishedAt, baseURL: instance.baseURL};
  } finally {instance.server.stop(true); instance.db.close();}
}

for (const mode of ["cache", "mixed"] as const) test(`actual Source ${mode} default600 OAuth publications bind signed state PKCE consumption and reject forged receipts`, async () => {
  const email = `${randomBytes(12).toString("hex")}@test.com`;
  const authorizationCode = randomBytes(24).toString("base64url");
  const a = await runOAuth(mode, email, authorizationCode), b = await runOAuth(mode, email, authorizationCode);
  const context: ComparisonContext = {leftBaseURL: a.baseURL, rightBaseURL: b.baseURL, leftStartedAt: a.startedAt, rightStartedAt: b.startedAt,
    leftFinishedAt: a.finishedAt, rightFinishedAt: b.finishedAt, sessionCookieSecret: secret, leftRequestWindows: a.windows, rightRequestWindows: b.windows};
  // Identical request bodies can share a millisecond boundary. Enclose both
  // actual requests in overlapping client windows to force that ambiguity;
  // their signed states and PKCE must still identify the distinct producers.
  const overlap = (run: typeof a) => {
    const windows = run.windows.filter((_, index) => (run.root as Row).traces[index].path.endsWith("/sign-in/social"));
    const startedAt = Math.min(...windows.map(window => window!.startedAt)), finishedAt = Math.max(...windows.map(window => window!.finishedAt));
    return run.windows.map((window, index) => (run.root as Row).traces[index].path.endsWith("/sign-in/social") ? {...window!, startedAt, finishedAt} : window);
  };
  const overlapping = {...context, leftRequestWindows: overlap(a), rightRequestWindows: overlap(b)};
  expect(compareValues(a.root, b.root, overlapping)).toEqual([]);
  expect(compareValues(a.root, b.root, context)).toEqual([]);
  const original = b.root as Row, owning = "observation.verificationPublications.0.set.ttl";
  const observerIndex = original.traces.findIndex((trace: Row) => trace.path === verificationPublicationObserver);
  const producerIndex = original.traces.findIndex((trace: Row) => trace.path.endsWith("/sign-in/social"));
  const foreignProducerIndex = original.traces.findLastIndex((trace: Row) => trace.path.endsWith("/sign-in/social"));
  const foreignState = {...overlapping, rightRequestWindows: overlapping.rightRequestWindows.map((window, index) => index === producerIndex
    ? {...window!, issuedVerificationStateCookie: overlapping.rightRequestWindows[foreignProducerIndex]!.issuedVerificationStateCookie} : window)};
  expect(compareValues(a.root, b.root, foreignState).some(difference => difference.path === owning)).toBe(true);
  for (const change of [
    (p: Row) => {p.set.ttl = Math.floor((Date.parse(p.snapshot.expiresAt) - Date.parse(p.before.executedAt)) / 1000) + 1; p.set.storageExpiresAt = new Date(Date.parse(p.set.storedAt) + p.set.ttl * 1000).toISOString();},
    (p: Row) => {p.set.ttl -= 2; p.set.storageExpiresAt = new Date(Date.parse(p.set.storedAt) + p.set.ttl * 1000).toISOString();},
    (p: Row) => {p.set.ttl = String(p.set.ttl);},
    (p: Row) => {delete p.before.executedAt;},
    (p: Row) => {p.before.executedAt = new Date(Date.parse(p.request.startedAt) - 1).toISOString();},
    (p: Row) => {p.snapshot.expiresAt = new Date(Date.parse(p.snapshot.expiresAt) + 1000).toISOString(); p.before.snapshot.expiresAt = p.snapshot.expiresAt; p.set.value.expiresAt = p.snapshot.expiresAt; p.set.rawValue = JSON.stringify(p.snapshot);},
    (p: Row) => {const payload = JSON.parse(p.snapshot.value); payload.expiresAt += 1000; p.snapshot.value = JSON.stringify(payload); p.before.snapshot.value = p.snapshot.value; p.set.value.value = p.snapshot.value; p.set.rawValue = JSON.stringify(p.snapshot);},
    (p: Row) => {const payload = JSON.parse(p.snapshot.value); payload.codeVerifier = "x".repeat(128); p.snapshot.value = JSON.stringify(payload); p.before.snapshot.value = p.snapshot.value; p.set.value.value = p.snapshot.value; p.set.rawValue = JSON.stringify(p.snapshot);},
    (p: Row) => {const payload = JSON.parse(p.snapshot.value); payload.oauthState = "x".repeat(32); p.snapshot.value = JSON.stringify(payload); p.before.snapshot.value = p.snapshot.value; p.set.value.value = p.snapshot.value; p.set.rawValue = JSON.stringify(p.snapshot);},
    (p: Row) => {p.set.storageExpiresAt = new Date(Date.parse(p.set.storageExpiresAt) + 1000).toISOString();},
  ]) {
    const bad = clone(original), publication = bad.observation.verificationPublications[0]; change(publication);
    bad.traces[observerIndex].responseBody.publications[0] = clone(publication);
    bad.observation.aliases[0] = clone(publication.set);
    expect(compareValues(a.root, bad, observedMutation(context, bad)).some(difference => difference.path === owning)).toBe(true);
  }
  for (const changed of [
    {...context, rightRequestWindows: context.rightRequestWindows!.map((window, index) => index === producerIndex ? {...window!, issuedVerificationStateCookie: undefined} : window)},
    {...context, rightRequestWindows: context.rightRequestWindows!.map((window, index) => index === producerIndex ? {...window!, issuedVerificationStateCookie: "better-auth.state=wrong.invalid"} : window)},
    {...context, rightRequestWindows: context.rightRequestWindows!.map((window, index) => index === observerIndex ? {...window!, verificationObserverDigest: undefined} : window)},
  ]) expect(compareValues(a.root, b.root, changed).some(difference => difference.path === owning)).toBe(true);
  const foreign = clone(original);
  foreign.observation.verificationPublications[0] = clone(original.observation.verificationPublications[1]);
  foreign.traces[observerIndex].responseBody.publications[0] = clone(foreign.observation.verificationPublications[0]);
  expect(compareValues(a.root, foreign, observedMutation(context, foreign)).some(difference => difference.path === owning)).toBe(true);
  const challenge = clone(original), url = new URL(challenge.traces[producerIndex].responseBody.url);
  url.searchParams.set("code_challenge", "x".repeat(43)); challenge.traces[producerIndex].responseBody.url = url.href;
  expect(compareValues(a.root, challenge, context).some(difference => difference.path === owning)).toBe(true);
  const extra = await runOAuth(mode, email, authorizationCode, true);
  const extraContext = {...context, rightBaseURL: extra.baseURL, rightStartedAt: extra.startedAt, rightFinishedAt: extra.finishedAt, rightRequestWindows: extra.windows};
  const fields = compareValues(a.root, extra.root, extraContext);
  for (const path of ["applicationReceipt", "request.applicationReceipt", "before.applicationReceipt", "set.applicationReceipt"])
    expect(fields.some(difference => difference.path === `observation.verificationPublications.0.${path}` && difference.reason === "field presence differs")).toBe(true);
  for (const key of ["metadata", "custom", "additionalFields", "applicationData"])
    expect(compareValues({...a.root as Row, [key]: {expiresAt: 600000, ttl: 600}}, {...original, [key]: {expiresAt: 600001, ttl: 599}}, context).some(difference => difference.path === `${key}.ttl`)).toBe(true);
}, 30000);

// Independent generated codes exercise receipt-to-delivery identity rather than
// changing the original default lifetime owners' shared public generators.
test("actual Source independent OTP codes bind complete publications and delivery while counters and foreign producers remain literal", async () => {
  const leftCode = String(randomInt(100000, 1000000));
  let rightCode = String(randomInt(100000, 1000000));
  while (rightCode === leftCode) rightCode = String(randomInt(100000, 1000000));
  const shared = {magic: randomBytes(24).toString("base64url"), transfer: randomBytes(24).toString("base64url")};
  const email = `${randomBytes(12).toString("hex")}@test.com`;
  const a = await run("cache", {otp: leftCode, ...shared}, email), b = await run("cache", {otp: rightCode, ...shared}, email);
  const context: ComparisonContext = {leftBaseURL: a.baseURL, rightBaseURL: b.baseURL, leftStartedAt: a.startedAt, rightStartedAt: b.startedAt, leftFinishedAt: a.finishedAt, rightFinishedAt: b.finishedAt, sessionCookieSecret: secret,
    leftRequestWindows: a.traces.map(t => t[requestWindow]), rightRequestWindows: b.traces.map(t => t[requestWindow])};
  const differences = compareValues(a.root, b.root, context);
  expect(differences).toEqual([]);
  const original = b.root as Row, observerIndex = original.traces.findIndex((t: Row) => t.path === verificationPublicationObserver);
  const owning = "observation.verificationPublications.0.set.ttl";
  const changedCode = rightCode === "999999" ? "999998" : "999999";
  for (const change of [
    (p: Row) => { p.delivery.otp = changedCode; },
    (p: Row) => { p.snapshot.value = `${rightCode}:1`; p.before.snapshot.value = p.snapshot.value; p.set.value.value = p.snapshot.value; p.set.rawValue = JSON.stringify(p.snapshot); },
    (p: Row) => { p.request = clone(original.observation.verificationPublications[3].request); },
  ]) {
    const bad = clone(original), publication = bad.observation.verificationPublications[0]; change(publication);
    bad.observation.aliases[0] = clone(publication.set);
    bad.traces[observerIndex].responseBody.publications[0] = clone(publication);
    bad.traces[observerIndex].responseBody.deliveries[0] = clone(publication.delivery);
    expect(compareValues(a.root, bad, observedMutation(context, bad)).some(d => d.path === owning)).toBe(true);
  }
  const delivery = clone(original); delivery.traces[observerIndex].responseBody.deliveries[0].otp = changedCode;
  expect(compareValues(a.root, delivery, context).some(d => d.path === `traces.${observerIndex}.responseBody.deliveries.0.otp`)).toBe(true);
  const counter = clone(original); counter.observation.aliases[0].value.value = `${rightCode}:1`;
  expect(compareValues(a.root, counter, context).some(d => d.path === "observation.aliases.0.value.value")).toBe(true);
  for (const key of ["metadata", "applicationData", "additionalFields", "custom"])
    expect(compareValues({[key]: {otp: leftCode, value: `${leftCode}:0`}}, {[key]: {otp: rightCode, value: `${rightCode}:0`}}, context).some(d => d.path === `${key}.otp`)).toBe(true);
}, 30000);
