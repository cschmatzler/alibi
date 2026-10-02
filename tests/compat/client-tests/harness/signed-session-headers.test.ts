import { Database } from "bun:sqlite";
import { expect, test } from "bun:test";
import { betterAuth } from "better-auth";
import { createAuthClient } from "better-auth/client";
import { getMigrations } from "better-auth/db/migration";
import { createAuthMiddleware } from "better-auth/api";
import { jwt, oneTimeToken } from "better-auth/plugins";
import { createHmac } from "node:crypto";
import { createLocalJWKSet, jwtVerify } from "jose";
import { compareValues, type ComparisonContext } from "../support/compare";
import { normalizeClientValue } from "../support/normalize";
import { createTracingFetch, requestWindow, type TraceEntry } from "../support/trace";

const secret = "signed-header-harness-application-secret32";
type Data = Record<string, any>;

async function capture() {
  const database = new Database(":memory:"), traces: TraceEntry[] = [], events: Data[] = [];
  let baseURL = "", active = false;
  const observe = (stage: string, ctx: Data) => {
    if (!active) return;
    events.push({ stage, path: ctx.path, method: ctx.method,
      headers: ctx.headers ? Object.fromEntries(ctx.headers) : null,
      request: ctx.request ? { url: ctx.request.url, method: ctx.request.method,
        headers: Object.fromEntries(ctx.request.headers) } : null,
      session: ctx.context.session });
  };
  const server = Bun.serve({ port: 0, async fetch(request) {
    if (new URL(request.url).pathname !== "/__test/signed-header-call") return auth.handler(request);
    const physical = request.clone();
    events.length = 0; active = true;
    try {
      const headers = new Headers({ cookie: request.headers.get("cookie")! });
      const token = await auth.api.getToken({ headers, request: physical, asResponse: false });
      const generated = await auth.api.generateOneTimeToken({ headers });
      const verified = await auth.api.verifyOneTimeToken({ body: generated, returnHeaders: true });
      return Response.json({ token, generated, verified: { response: verified.response,
        headers: Object.fromEntries(verified.headers) }, events: [...events] });
    } finally { active = false; }
  } });
  baseURL = `http://localhost:${server.port}`;
  const auth = betterAuth({ baseURL, secret, database, rateLimit: { enabled: false },
    emailAndPassword: { enabled: true }, plugins: [jwt(), oneTimeToken()],
    hooks: {
      before: createAuthMiddleware(async ctx => { observe("before", ctx); }),
      after: createAuthMiddleware(async ctx => { observe("after", ctx); }),
    },
  });
  const startedAt = Date.now();
  try {
    await (await getMigrations(auth.options)).runMigrations();
    const signup = async (name: string) => {
      let cookie = "";
      const fetch = createTracingFetch(baseURL, name, traces);
      const client = createAuthClient({ baseURL, fetchOptions: { customFetchImpl: fetch } });
      const result = await client.signUp.email({ name, email: `${name}@signed-header.local`, password: "password123",
        fetchOptions: { onSuccess({ response }) { cookie = response.headers.getSetCookie().map(raw => raw.split(";")[0]).join("; "); } } });
      expect(result.error).toBeNull(); expect(cookie).toContain("better-auth.session_token=");
      const raw = decodeURIComponent(cookie.slice(cookie.indexOf("=") + 1)), dot = raw.lastIndexOf(".");
      expect(raw.slice(0, dot)).toBe(result.data!.token!);
      expect(raw.slice(dot + 1)).toBe(createHmac("sha256", secret).update(result.data!.token!).digest("base64"));
      return { result: result.data, headers: { cookie }, fetch, client };
    };
    const owner = await signup("owner"), foreign = await signup("foreign");
    const response = await owner.fetch(`${baseURL}/__test/signed-header-call`, { method: "POST",
      headers: { "content-type": "application/json", host: "signed-header-owner.example.test",
        origin: "http://signed-header-owner.example.test" }, body: "{}" });
    expect(response.status).toBe(200); const observed = await response.json() as Data;
    const jwks = await auth.api.getJwks({});
    const verifiedToken = await jwtVerify(observed.token.token, createLocalJWKSet(jwks));
    expect(verifiedToken.payload.sub).toBe(owner.result!.user.id);
    expect(observed.verified.response.session.token).toBe(owner.result!.token);
    expect(observed.events.length).toBeGreaterThan(0);
    for (const event of observed.events.filter((event: Data) => event.headers?.cookie))
      expect(event.headers.cookie).toBe(owner.headers.cookie);
    const restoredCookie = observed.verified.headers["set-cookie"].split(";")[0];
    const restored = await auth.api.getSession({ headers: new Headers({ cookie: restoredCookie }) });
    expect(restored!.user.id).toBe(owner.result!.user.id);
    const replay = await auth.api.verifyOneTimeToken({ body: observed.generated }).then(() => null, error => error);
    expect(replay.statusCode).toBe(400); expect(replay.body).toEqual({ message: "Invalid token" });
    expect(database.query("SELECT * FROM verification").all()).toEqual([]);
    let rotatedCookie = "";
    const rotated = await owner.client.signIn.email({ email: "owner@signed-header.local", password: "password123",
      fetchOptions: { onSuccess({ response }) { rotatedCookie = response.headers.getSetCookie().map(raw => raw.split(";")[0]).join("; "); } } });
    expect(rotated.error).toBeNull(); expect(rotated.data!.user.id).toBe(owner.result!.user.id);
    expect(rotated.data!.token).not.toBe(owner.result!.token);
    expect(database.query("SELECT * FROM session").all()).toHaveLength(3);
    const value = normalizeClientValue({ observation: {
      owner: { result: owner.result, headers: owner.headers }, foreign: { result: foreign.result, headers: foreign.headers },
      rotated: { result: rotated.data, headers: { cookie: rotatedCookie } }, observed, verifiedToken, jwks, restored,
    }, traces }) as Data;
    return { value, baseURL, startedAt, finishedAt: Date.now(), windows: traces.map(trace => trace[requestWindow]) };
  } finally { server.stop(true); database.close(); }
}

test("actual Source signed session headers retain HMAC issuance physical and logical cookie relationships", async () => {
  const left = await capture(), right = await capture();
  const context: ComparisonContext = { leftBaseURL: left.baseURL, rightBaseURL: right.baseURL,
    sessionCookieSecret: secret,
    leftStartedAt: left.startedAt, leftFinishedAt: left.finishedAt,
    rightStartedAt: right.startedAt, rightFinishedAt: right.finishedAt,
    leftRequestWindows: left.windows, rightRequestWindows: right.windows,
  };
  if (Bun.env.COMPAT_SIGNED_HEADER_CAPTURE)
    await Bun.write(Bun.env.COMPAT_SIGNED_HEADER_CAPTURE, JSON.stringify({ left: left.value, right: right.value, context }, null, 2));
  // These are complete real Source captures. The comparator must reconcile the
  // independently random credentials without editing any header observation.
  expect(compareValues(left.value, right.value, context)).toEqual([]);
  const cookiePath = "observation.owner.headers.cookie";
  const cookie = (value: Data) => value.observation.owner.headers.cookie as string;
  const setCookiePath = "observation.observed.verified.headers.set-cookie";
  const invalidSignature = (raw: string) => {
    const separator = raw.indexOf("="), decoded = decodeURIComponent(raw.slice(separator + 1));
    const dot = decoded.lastIndexOf("."), signature = decoded.slice(dot + 1);
    return `${raw.slice(0, separator + 1)}${encodeURIComponent(`${decoded.slice(0, dot + 1)}${signature[0] === "A" ? "B" : "A"}${signature.slice(1)}`)}`;
  };
  const mutations: { mutate: (value: Data) => void; path: string; reason: string }[] = [
    { mutate: value => { value.observation.owner.headers.cookie = value.observation.foreign.headers.cookie; }, path: cookiePath,
      reason: "signed session cookie does not match corresponding observed issuance" },
    { mutate: value => { value.observation.owner.headers.cookie = value.observation.rotated.headers.cookie; }, path: cookiePath,
      reason: "signed session cookie does not match corresponding observed issuance" },
    { mutate: value => { value.observation.owner.headers.cookie = left.value.observation.foreign.headers.cookie; }, path: cookiePath,
      reason: "signed session cookie does not match corresponding observed issuance" },
    { mutate: value => { value.observation.owner.headers.cookie = invalidSignature(cookie(value)); }, path: cookiePath,
      reason: "signed session cookie signature is invalid" },
    { mutate: value => { value.observation.owner.headers.cookie = cookie(value).replace("%3D", "%3d"); }, path: cookiePath,
      reason: "signed session cookie encoding is not canonical" },
    { mutate: value => { value.observation.owner.headers.cookie = cookie(value).replace("better-auth.session_token", "__Secure-better-auth.session_token"); }, path: cookiePath,
      reason: "signed session cookie presence or name differs" },
    { mutate: value => { value.observation.owner.headers.cookie = `${cookie(value)}; ${cookie(value)}`; }, path: cookiePath,
      reason: "signed session cookie presence or name differs" },
    { mutate: value => { value.observation.owner.headers.cookie = `${cookie(value)}; application=changed-literal`; }, path: cookiePath,
      reason: "signed session cookie header bytes or attributes differ" },
    ...["Path=/", "HttpOnly", "SameSite=Lax", "Max-Age=604800"].map(attribute => ({
      mutate: (value: Data) => { value.observation.observed.verified.headers["set-cookie"] =
        (value.observation.observed.verified.headers["set-cookie"] as string).replace(attribute, `${attribute}-changed`); },
      path: setCookiePath, reason: "signed session cookie header bytes or attributes differ",
    })),
  ];
  for (const mutation of mutations) {
    const changed = structuredClone(right.value); mutation.mutate(changed);
    expect(compareValues(left.value, changed, context)).toContainEqual({ path: mutation.path, reason: mutation.reason });
  }
  const unrecorded = { ...context, rightRequestWindows: right.windows.map(window => window && { ...window, issuedSessionCookie: undefined }) };
  expect(compareValues(left.value, right.value, unrecorded)).toContainEqual({ path: cookiePath,
    reason: "signed session cookie does not match corresponding observed issuance" });
  const wrongSecret = { ...context, sessionCookieSecret: "another-real-application-secret-for-negative" };
  expect(compareValues(left.value, right.value, wrongSecret)).toContainEqual({ path: cookiePath,
    reason: "signed session cookie signature is invalid" });
  const invalidLeft = structuredClone(left.value), invalidRight = structuredClone(right.value);
  invalidLeft.observation.owner.headers.cookie = invalidRight.observation.owner.headers.cookie = invalidSignature(cookie(right.value));
  expect(compareValues(invalidLeft, invalidRight, context)).toContainEqual({ path: cookiePath,
    reason: "signed session cookie signature is invalid" });
  const orderedLeft = structuredClone(left.value), orderedRight = structuredClone(right.value);
  orderedLeft.observation.owner.headers.cookie += "; application=literal";
  orderedRight.observation.owner.headers.cookie += "; application=literal";
  expect(compareValues(orderedLeft, orderedRight, context)).toEqual([]);
  orderedRight.observation.owner.headers.cookie = `application=literal; ${cookie(right.value)}`;
  expect(compareValues(orderedLeft, orderedRight, context)).toContainEqual({ path: cookiePath,
    reason: "signed session cookie header bytes or attributes differ" });
  for (const field of ["metadata", "additionalFields", "custom", "applicationData"]) {
    const appLeft = { ...left.value, [field]: { headers: left.value.observation.owner.headers } };
    const appRight = { ...right.value, [field]: { headers: right.value.observation.owner.headers } };
    expect(compareValues(appLeft, appRight, context)).toContainEqual({ path: `${field}.headers.cookie`, reason: "value or type differs" });
  }
  expect(compareValues(left.value, right.value, { ...context, sessionCookieSecret: undefined })).toContainEqual({ path: cookiePath, reason: "value or type differs" });
});
