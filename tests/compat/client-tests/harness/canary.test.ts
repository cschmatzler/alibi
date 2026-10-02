import { createHash, createHmac } from "node:crypto";
import { expect, test } from "bun:test";
import { createAuthClient } from "better-auth/client";
import { SignJWT } from "jose";
import { compareValues } from "../support/compare";
import { createTracingFetch, requestWindow, type TraceEntry } from "../support/trace";

// Negative controls go through HTTP, the real SDK, tracing and the production comparator.
// They must fail comparison even though both HTTP responses report success.
test("live response mutations cannot hide broken ownership or cookie security", async () => {
  let mode = "valid";
  const server = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    fetch() {
      return Response.json(
        {
          session: {
            id: "session-1",
            userId: mode === "ownership" ? "some-other-user" : "user-1",
            token: "opaque-session-token",
            expiresAt: "2030-01-01T00:00:00.000Z",
          },
          user: {
            id: "user-1",
            email: "canary@test.com",
            emailVerified: false,
            name: "Canary",
            createdAt: "2026-01-01T00:00:00.000Z",
            updatedAt: "2026-01-01T00:00:00.000Z",
          },
        },
        {
          headers:
            mode === "missing-cookie"
              ? {}
              : {
                  "set-cookie": `better-auth.session_token=opaque-session-token; Path=/; SameSite=Lax${mode === "insecure-cookie" ? "" : "; HttpOnly; Secure"}`,
                },
        },
      );
    },
  });
  try {
    const baseURL = server.url.origin;
    async function observe(mutation: string) {
      mode = mutation;
      const traces: TraceEntry[] = [];
      const tracing = createTracingFetch(baseURL, "canary", traces);
      const client = createAuthClient({
        baseURL,
        fetchOptions: { customFetchImpl: tracing },
      });
      return { result: await client.getSession(), traces };
    }
    const baseline = await observe("valid");
    expect(baseline.result.error).toBeNull();
    const context = {
      leftBaseURL: baseURL,
      rightBaseURL: baseURL,
      leftStartedAt: 0,
      rightStartedAt: 0,
    };
    expect(compareValues(baseline, await observe("valid"), context)).toEqual(
      [],
    );
    for (const mode of ["ownership", "insecure-cookie", "missing-cookie"]) {
      const mutated = await observe(mode);
      expect(mutated.result.error).toBeNull();
      const differences = compareValues(baseline, mutated, context);
      expect(differences.length).toBeGreaterThan(0);
      expect(
        differences.every((entry) =>
          mode === "ownership"
            ? entry.path.startsWith("result.data.") ||
              entry.path.startsWith("traces.0.responseBody.")
            : entry.path.startsWith("traces.0.responseCookies."),
        ),
      ).toBe(true);
    }
  } finally {
    await server.stop(true);
  }
});

test("independently signed JWTs keep application id, token and state claims literal", async () => {
  const claims = {
    exp: 4102444800,
    iss: "https://issuer.example",
    aud: "client",
    custom: { id: "literal-owner", token: "literal-value", state: "approved" },
  };
  const sign = (payload: Record<string, unknown>, key: string) =>
    new SignJWT(payload)
      .setProtectedHeader({ alg: "HS256" })
      .sign(new TextEncoder().encode(key.repeat(32)));
  const left = { token: await sign(claims, "a") },
    context = {
      leftBaseURL: "http://localhost:1",
      rightBaseURL: "http://localhost:2",
      leftStartedAt: 0,
      rightStartedAt: 0,
    };
  expect(
    compareValues(left, { token: await sign(claims, "b") }, context),
  ).toEqual([]);
  for (const field of ["id", "token", "state"] as const) {
    const changed = {
      ...claims,
      custom: { ...claims.custom, [field]: "changed-literal" },
    };
    expect(
      compareValues(left, { token: await sign(changed, "b") }, context).some(
        (diff) => diff.path === `token.payload.custom.${field}`,
      ),
    ).toBe(true);
  }
  // Application claims need no reserved wrapper name. Include decoded copies
  // so a payload cannot supply its own supposedly independent identity proof.
  for (const field of ["id", "userId", "token", "sessionToken", "state", "createdAt", "callbackURL"]) {
    const original = field === "createdAt" ? "2026-01-01T00:00:00.000Z" : field === "callbackURL" ? context.leftBaseURL : "literal-value";
    const changed = field === "createdAt" ? "2026-01-01T00:00:00.001Z" : field === "callbackURL" ? context.rightBaseURL : "changed-literal";
    for (const nested of [false, true]) {
      const first = { ...claims, ...(nested ? { details: { [field]: original } } : { [field]: original }) };
      const second = { ...claims, ...(nested ? { details: { [field]: changed } } : { [field]: changed }) };
      expect(compareValues({ token: await sign(first, "a"), decoded: first }, { token: await sign(second, "b"), decoded: second }, context))
        .toContainEqual({ path: `token.payload.${nested ? "details." : ""}${field}`, reason: "value or type differs" });
    }
  }
  const observed = async (side: string) => {
    const user = { id: `${side}-user`, createdAt: side === "a" ? "2026-01-01T00:00:00.000Z" : "2026-01-01T00:00:00.001Z" };
    const session = { userId: user.id, token: `${side}-session` };
    const payload = { ...claims, ...user, sub: user.id, session };
    return { user, session, token: await sign(payload, side), decoded: payload };
  };
  expect(compareValues(await observed("a"), await observed("b"), context)).toEqual([]);

  // API-key sessions are freshly constructed for each request. Their JWT dates
  // need the real signing request and independently observed key/session owner.
  const virtual = async (side: string, at: number) => {
    const key = { id: `${side}-key`, key: side.repeat(64), referenceId: `${side}-user`, expiresAt: null, configId: "default", enabled: true, remaining: null };
    const session = (time: number) => ({ id: key.id, token: key.key, userId: key.referenceId,
      createdAt: new Date(time).toISOString(), updatedAt: new Date(time).toISOString(), expiresAt: new Date(time + 604800).toISOString() });
    const payload = { ...claims, snapshot: { session: session(at), user: { id: key.referenceId } } };
    const token = await sign(payload, side);
    return { observation: { checked: payload }, traces: [
      { method: "POST", path: "/api/auth/api-key/create", responseStatus: 200, responseBody: key },
      { method: "GET", path: "/api/auth/token", responseStatus: 200, responseBody: { token } },
      { method: "GET", path: "/api/auth/get-session", responseStatus: 200, responseBody: { session: session(at + 1000), user: { id: key.referenceId } } },
    ] };
  };
  const first = await virtual("a", 10100), second = await virtual("b", 30100);
  const clocks = { ...context, leftStartedAt: 10000, rightStartedAt: 20000,
    leftRequestWindows: [9900, 10000, 11000].map(startedAt => ({ startedAt, finishedAt: startedAt + 200, inputDates: {} })),
    rightRequestWindows: [29900, 30000, 31000].map(startedAt => ({ startedAt, finishedAt: startedAt + 200, inputDates: {} })) };
  expect(compareValues(first, second, clocks)).toEqual([]);
  for (const mutation of ["missing-key", "foreign-key", "missing-session", "failed-issuer", "wrong-lifetime", "outside-window"]) {
    const altered = structuredClone(second);
    if (mutation === "missing-key") altered.traces[0]!.path = "/api/auth/unrelated";
    if (mutation === "foreign-key") (altered.traces[0]!.responseBody as typeof second.traces[0]["responseBody"] & { referenceId: string }).referenceId = "foreign";
    if (mutation === "missing-session") altered.traces[2]!.path = "/api/auth/unrelated";
    if (mutation === "failed-issuer") altered.traces[1]!.responseStatus = 500;
    if (["wrong-lifetime", "outside-window"].includes(mutation)) {
      const payload = altered.observation.checked;
      const field = mutation === "wrong-lifetime" ? "expiresAt" : "createdAt";
      payload.snapshot.session[field] = new Date(Date.parse(payload.snapshot.session[field]) + 10000).toISOString();
      (altered.traces[1]!.responseBody as { token: string }).token = await sign(payload, "b");
    }
    expect(compareValues(first, altered, clocks).some(diff => diff.path === "observation.checked.snapshot.session.createdAt" || diff.path === "observation.checked.snapshot.session.expiresAt")).toBe(true);
  }
});

test("complete enrollment responses retain credential formats, relationships and literal extra fields", () => {
  const observe = (secret: string, code: string) => ({
    traces: [
      {
        path: "/api/auth/two-factor/enable",
        responseBody: {
          totpURI: `otpauth://totp/Fixture:user?secret=${secret}&digits=6`,
          backupCodes: [code],
          metadata: {
            backupCodes: ["literal-code"],
            totpURI: "otpauth://totp/app?secret=AAAAAAAA",
          },
        },
      },
      {
        path: "/api/auth/two-factor/get-totp-uri",
        responseBody: {
          totpURI: `otpauth://totp/Fixture:user?secret=${secret}&digits=6`,
        },
      },
    ],
  });
  const context = {
    leftBaseURL: "http://localhost:1",
    rightBaseURL: "http://localhost:2",
    leftStartedAt: 0,
    rightStartedAt: 0,
  };
  const left = observe("AAAAAAAA", "aaaaa-11111"),
    right = observe("BBBBBBBB", "bbbbb-22222");
  expect(compareValues(left, right, context)).toEqual([]);
  const changed = structuredClone(right);
  changed.traces[1]!.responseBody.totpURI =
    changed.traces[1]!.responseBody.totpURI.replace("BBBBBBBB", "CCCCCCCC");
  expect(compareValues(left, changed, context).length).toBeGreaterThan(0);
  const malformed = structuredClone(right);
  malformed.traces[0]!.responseBody.backupCodes = ["wrong-format"];
  expect(compareValues(left, malformed, context).length).toBeGreaterThan(0);
  const literal = structuredClone(right);
  literal.traces[0]!.responseBody.metadata!.backupCodes = ["changed-code"];
  expect(compareValues(left, literal, context).length).toBeGreaterThan(0);
  const duplicate = structuredClone(right);
  duplicate.traces[0]!.responseBody.totpURI += "&secret=WRONG";
  expect(compareValues(left, duplicate, context).length).toBeGreaterThan(0);
});

test("request clocks tolerate slower execution while preserving session lifetime and issuance bounds", async () => {
  const row = (created: number, token: string) => ({
    id: token,
    token,
    userId: "owner",
    createdAt: new Date(created).toISOString(),
    updatedAt: new Date(created).toISOString(),
    expiresAt: new Date(created + 60_000).toISOString(),
  });
  const leftRow = row(100_100, "left"),
    rightRow = row(200_100, "right");
  const observed = (session: typeof leftRow) => ({
    observation: { session },
    traces: [
      {
        method: "GET",
        path: "/api/auth/get-session",
        responseBody: { session },
      },
    ],
  });
  const context = {
    leftBaseURL: "http://localhost:1",
    rightBaseURL: "http://localhost:2",
    leftStartedAt: 100_000,
    rightStartedAt: 190_000,
    leftRequestWindows: [
      { startedAt: 100_000, finishedAt: 100_200, inputDates: {} },
    ],
    rightRequestWindows: [
      { startedAt: 200_000, finishedAt: 200_200, inputDates: {} },
    ],
  };
  expect(compareValues(observed(leftRow), observed(rightRow), context)).toEqual(
    [],
  );
  expect(
    compareValues(
      observed(leftRow),
      observed({ ...rightRow, expiresAt: new Date(300_100).toISOString() }),
      context,
    ).length,
  ).toBeGreaterThan(0);
  expect(
    compareValues(observed(leftRow), observed(row(210_100, "right")), context)
      .length,
  ).toBeGreaterThan(0);
  expect(
    compareValues(
      observed(leftRow),
      observed({ ...rightRow, expiresAt: new Date(250_100).toISOString() }),
      context,
    ).some((diff) => diff.path.endsWith("expiresAt")),
  ).toBe(true);

  const secret = "producer-clock-secret";
  async function capture(side: string) {
    let member: Record<string, unknown>, social: Record<string, unknown>;
    const linkUser = `${side}-link-user`, linkToken = `${side}-link-token`;
    const linkedAccounts: Record<string, unknown>[] = [];
    const server = Bun.serve({ hostname: "127.0.0.1", port: 0, fetch(request) {
      const path = new URL(request.url).pathname, now = Date.now(), iso = (offset = 0) => new Date(now + offset).toISOString();
      if (path.endsWith("/sign-up/email")) {
        const signed = encodeURIComponent(`${linkToken}.${createHmac("sha256", secret).update(linkToken).digest("base64")}`);
        return Response.json({token: linkToken, user: {id: linkUser}}, {headers: {"set-cookie": `better-auth.session_token=${signed}; Path=/; HttpOnly; Max-Age=604800`}});
      }
      if (path === "/__test/profiles/validation/api/auth/callback/gitlab") {
        linkedAccounts.push({id: `${side}-linked-account`, userId: linkUser, providerId: "gitlab", accountId: "1832", accessToken: "fixture-gitlab-access", accessTokenExpiresAt: iso(3600000), createdAt: iso(), updatedAt: iso()});
        return new Response(null, {status: 302, headers: {location: "/done"}});
      }
      if (path === "/__test/user-validation/state") return Response.json({users: [{id: linkUser}], accounts: linkedAccounts, sessions: []});
      if (path.endsWith("/server")) {
        member = { id: `${side}-member`, organizationId: `${side}-org`, userId: `${side}-user`, role: "member", createdAt: iso() };
        return Response.json({ code: "AFTER_HOOK_REJECTED" }, { status: 500 });
      }
      if (path.endsWith("/callback/gitlab")) {
        const token = `${side}-session`, user = { id: `${side}-user`, createdAt: iso(), updatedAt: iso() };
        social = { users: [user], accounts: [{ id: `${side}-account`, userId: user.id, providerId: "gitlab", accessToken: "fixture-gitlab-access", createdAt: iso(), updatedAt: iso(), accessTokenExpiresAt: iso(3600000) }],
          sessions: [{ id: `${side}-session-id`, userId: user.id, token, createdAt: iso(), updatedAt: iso(), expiresAt: iso(604800000) }] };
        const cookie = encodeURIComponent(`${token}.${createHmac("sha256", secret).update(token).digest("base64")}`);
        return new Response(null, { status: 302, headers: { location: "/done", "set-cookie": `better-auth.session_token=${cookie}; Path=/; HttpOnly` } });
      }
      if (path.includes("organization-member-addition")) {
        const {createdAt: _, ...stored} = member!;
        return Response.json({ receipts: [{phase: "after-add", member, user: {id: `${side}-user`}, organization: {id: `${side}-org`}}], snapshot: {members: [stored]} });
      }
      return Response.json(social!);
    } });
    const traces: TraceEntry[] = [], traced = createTracingFetch(server.url.origin, "producer", traces);
    try {
      await traced("/__test/organization-member-addition/server", { method: "POST", headers: {"content-type": "application/json"}, body: JSON.stringify({body: {organizationId: `${side}-org`, userId: `${side}-user`}}) });
      const addition: unknown = await (await traced("/__test/organization-member-addition/state")).json();
      await traced("/__test/profiles/social-gitlab-issuer-slashes/api/auth/callback/gitlab", {redirect: "manual"});
      const oauth: unknown = await (await traced("/__test/social-provider/state")).json();
      await traced("/__test/profiles/validation/api/auth/sign-up/email", {method: "POST"});
      await traced("/__test/user-validation/state");
      await traced("/__test/profiles/validation/api/auth/callback/gitlab", {redirect: "manual"});
      const linked: unknown = await (await traced("/__test/user-validation/state")).json();
      return { value: {observation: {addition, oauth, linked}, traces}, windows: traces.map(trace => trace[requestWindow]!), baseURL: server.url.origin };
    } finally { server.stop(true); }
  }
  const first = await capture("left");
  await Bun.sleep(10);
  const second = await capture("right");
  const producerClocks = { leftBaseURL: first.baseURL, rightBaseURL: second.baseURL, sessionCookieSecret: secret,
    leftStartedAt: first.windows[0]!.startedAt, rightStartedAt: second.windows[0]!.startedAt - 10000,
    leftRequestWindows: first.windows, rightRequestWindows: second.windows };
  expect(compareValues(first.value, second.value, producerClocks)).toEqual([]);
  for (const mutation of ["member-owner", "missing-member", "member-digest", "callback-signature", "callback-status", "session-owner", "oauth-digest", "session-lifetime", "link-owner", "link-path", "link-signature", "link-status", "link-date", "link-digest", "preexisting-link", "link-future-issuer", "link-token", "link-lifetime"]) {
    const value = structuredClone(second.value), clocks = structuredClone(producerClocks);
    const memberControl = clocks.rightRequestWindows[1]!.controlObservation!, oauthControl = clocks.rightRequestWindows[3]!.controlObservation!;
    if (mutation === "member-owner") clocks.rightRequestWindows[0]!.memberAdditionOwner!.userId = "foreign";
    if (mutation === "missing-member") (memberControl.body as {snapshot: {members: unknown[]}}).snapshot.members = [];
    if (mutation === "member-digest") memberControl.digest = "invalid";
    if (mutation === "callback-signature") clocks.rightRequestWindows[2]!.issuedSessionCookie += "invalid";
    if (mutation === "callback-status") value.traces[2]!.responseStatus = 400;
    if (mutation === "session-owner") (oauthControl.body as {sessions: {userId: string}[]}).sessions[0]!.userId = "foreign";
    if (mutation === "oauth-digest") oauthControl.digest = "invalid";
    if (mutation === "session-lifetime") (value.observation.oauth as {sessions: {expiresAt: string}[]}).sessions[0]!.expiresAt = new Date(Date.now() + 123456789).toISOString();
    const linkedControl = clocks.rightRequestWindows[7]!.controlObservation!;
    const linked = value.observation.linked as {accounts: Record<string, unknown>[]};
    if (mutation === "link-owner") linked.accounts[0]!.userId = "foreign";
    if (mutation === "link-path") value.traces[6]!.path = "/__test/profiles/foreign/api/auth/callback/gitlab";
    if (mutation === "link-signature") clocks.rightRequestWindows[6]!.sessionCookie += "invalid";
    if (mutation === "link-status") value.traces[6]!.responseStatus = 400;
    if (mutation === "link-date") linked.accounts[0]!.createdAt = new Date(clocks.rightRequestWindows[6]!.finishedAt + 60000).toISOString();
    if (["link-owner", "link-date"].includes(mutation)) (linkedControl.body as {accounts: unknown[]}).accounts = structuredClone(linked.accounts);
    if (mutation === "link-future-issuer") clocks.rightRequestWindows[4]!.finishedAt = clocks.rightRequestWindows[6]!.finishedAt + 1;
    if (mutation === "link-token") linked.accounts[0]!.accessToken = "unobserved-provider-token";
    if (mutation === "link-lifetime") linked.accounts[0]!.accessTokenExpiresAt = new Date(Date.parse(String(linked.accounts[0]!.accessTokenExpiresAt)) + 1000).toISOString();
    if (["link-token", "link-lifetime"].includes(mutation)) (linkedControl.body as {accounts: unknown[]}).accounts = structuredClone(linked.accounts);
    if (mutation === "link-digest") linkedControl.digest = "invalid";
    const beforeLink = clocks.rightRequestWindows[5]!.controlObservation!;
    if (mutation === "preexisting-link") (beforeLink.body as {accounts: unknown[]}).accounts = structuredClone(linked.accounts);
    for (const control of [memberControl, oauthControl, linkedControl, beforeLink]) if (control.digest !== "invalid") control.digest = createHash("sha256").update(JSON.stringify(control.body)).digest("hex");
    const prefix = mutation.startsWith("member") || mutation === "missing-member" ? "observation.addition.receipts.0.member.createdAt" : mutation.startsWith("link-") || mutation === "preexisting-link" ? "observation.linked.accounts.0." : "observation.oauth.sessions.0.";
    expect(compareValues(first.value, value, clocks).some(diff => diff.path.startsWith(prefix)
      && (!mutation.startsWith("link-") && mutation !== "preexisting-link" || diff.path.endsWith(mutation === "link-token" || mutation === "link-lifetime" ? ".accessTokenExpiresAt" : ".createdAt")))).toBe(true);
  }
});

test("later session and user clocks require their actual issuance and update receipts", () => {
  const iso = (n: number) => new Date(n).toISOString();
  const observe = (side: string, issued: number, updated: number) => ({
    traces: [
      {
        method: "POST",
        path: "/api/auth/sign-in/email",
        responseStatus: 200,
        responseBody: { token: side, user: { id: `${side}-user` } },
      },
      {
        method: "POST",
        path: "/api/auth/update-user",
        responseStatus: 200,
        responseBody: { status: true },
      },
      {
        method: "GET",
        path: "/api/auth/get-session",
        responseStatus: 200,
        responseBody: {
          session: {
            id: `${side}-session`,
            token: side,
            userId: `${side}-user`,
            createdAt: iso(issued),
            updatedAt: iso(issued),
            expiresAt: iso(issued + 60_000),
          },
          user: { id: `${side}-user`, updatedAt: iso(updated) },
        },
      },
    ],
  });
  // The physical observer can expose the same stored row without an auth read.
  const left = observe("left", 100_100, 105_100),
    right = observe("right", 200_100, 210_100);
  const windows = (side: string, issued: number, updated: number) => [
    {
      startedAt: issued,
      finishedAt: issued + 200,
      inputDates: {},
      issuedSessionCookie: `better-auth.session_token=${side}.signed`,
    },
    {
      startedAt: updated,
      finishedAt: updated + 200,
      inputDates: {},
      sessionCookie: `better-auth.session_token=${side}.signed`,
    },
    { startedAt: updated + 500, finishedAt: updated + 600, inputDates: {} },
  ];
  const context = {
    leftBaseURL: "http://localhost:1",
    rightBaseURL: "http://localhost:2",
    leftStartedAt: 100_000,
    rightStartedAt: 190_000,
    leftRequestWindows: windows("left", 100_000, 105_000),
    rightRequestWindows: windows("right", 200_000, 210_000),
  };
  expect(compareValues(left, right, context)).toEqual([]);
  const secret = "lifecycle-secret";
  const cookie = (token: string) => `better-auth.session_token=${encodeURIComponent(`${token}.${createHmac("sha256", secret).update(token).digest("base64")}`)}`;
  const physical = (value: typeof left) => ({
    traces: value.traces.slice(0, 2),
    observation: { sessions: [value.traces[2]!.responseBody.session!] },
  });
  const signed = structuredClone(context);
  signed.leftRequestWindows[0]!.issuedSessionCookie = cookie("left");
  signed.rightRequestWindows[0]!.issuedSessionCookie = cookie("right");
  const receipt = (kind: "session" | "verification", owner: string, body: unknown) => ({kind, owner, body, digest: createHash("sha256").update(JSON.stringify(body)).digest("hex")});
  const receiptContext = { ...signed, sessionCookieSecret: secret,
    leftPhysicalObservations: [receipt("session", "left-user", {user: {id: "left-user"}, sessions: physical(left).observation.sessions})],
    rightPhysicalObservations: [receipt("session", "right-user", {user: {id: "right-user"}, sessions: physical(right).observation.sessions})],
  };
  expect(compareValues(physical(left), physical(right), receiptContext)).toEqual([]);
  for (const change of ["foreign-owner", "unissued-token", "wrong-lifetime", "unrelated-date", "date-shape", "invalid-signature", "failed-issuer", "tampered-control", "copied-application-date"]) {
    const altered = physical(structuredClone(right)), clocks = structuredClone(receiptContext);
    const row = altered.observation.sessions[0]!;
    if (change === "foreign-owner") row.userId = "another-user";
    if (change === "unissued-token") row.token = "another-token";
    if (change === "wrong-lifetime") row.expiresAt = iso(250_100);
    if (change === "unrelated-date") row.createdAt = iso(215_100);
    if (change === "date-shape") row.expiresAt = row.expiresAt.replace("Z", "+00:00");
    if (change === "invalid-signature") clocks.rightRequestWindows[0]!.issuedSessionCookie = cookie("wrong");
    if (change === "failed-issuer") altered.traces[0]!.responseStatus = 401;
    if (change === "tampered-control") clocks.rightPhysicalObservations[0]!.digest = "invalid";
    if (change === "copied-application-date") row.updatedAt = iso(215_100);
    expect(compareValues(physical(left), altered, clocks).some(diff => diff.path.startsWith("observation.sessions"))).toBe(true);
    // The independent control really returned the wrong row. Exact readback
    // alone must not substitute for its signed issuer, owner or lifetime.
    if (["foreign-owner", "unissued-token", "wrong-lifetime", "unrelated-date", "date-shape"].includes(change)) {
      clocks.rightPhysicalObservations = [receipt("session", row.userId, {user: {id: row.userId}, sessions: [row]})];
      expect(compareValues(physical(left), altered, clocks).some(diff => diff.path.startsWith("observation.sessions"))).toBe(true);
    }
  }
  const application = {...physical(right), application: {...physical(right).observation.sessions[0]!, expiresAt: iso(251_100)}};
  expect(compareValues({...physical(left), application: physical(left).observation.sessions[0]}, application, receiptContext).some(diff => diff.path === "application.expiresAt")).toBe(true);
  for (const change of [
    "unknown-cookie",
    "read-endpoint",
    "foreign-owner",
    "wrong-lifetime",
  ]) {
    const altered = structuredClone(right),
      clocks = structuredClone(context);
    if (change === "unknown-cookie")
      clocks.rightRequestWindows[1]!.sessionCookie =
        "better-auth.session_token=unissued.signed";
    if (change === "read-endpoint")
      altered.traces[0]!.path = "/api/auth/get-session";
    if (change === "foreign-owner")
      altered.traces[2]!.responseBody.session!.userId = "another-user";
    if (change === "wrong-lifetime")
      altered.traces[2]!.responseBody.session!.expiresAt = iso(250_100);
    expect(compareValues(left, altered, clocks).length).toBeGreaterThan(0);
  }
  const narrowPhysical = (value: typeof left) => {
    const issued = value.traces[2]!.responseBody.session!;
    return {traces: [{...value.traces[0]!, path: "/__test/profiles/org-member-addition/api/auth/sign-in/email"}],
      observation: {sessions: [{id: issued.id, token: issued.token, userId: issued.userId, expiresAt: iso(Date.parse(issued.createdAt) + 604800000)}]}};
  };
  const narrowContext = {...receiptContext,
    leftPhysicalObservations: [receipt("session", "left-user", {user: {id: "left-user"}, sessions: narrowPhysical(left).observation.sessions})],
    rightPhysicalObservations: [receipt("session", "right-user", {user: {id: "right-user"}, sessions: narrowPhysical(right).observation.sessions})],
    leftRequestWindows: receiptContext.leftRequestWindows.slice(0, 1), rightRequestWindows: receiptContext.rightRequestWindows.slice(0, 1)};
  expect(compareValues(narrowPhysical(left), narrowPhysical(right), narrowContext)).toEqual([]);
  for (const change of ["foreign-owner", "wrong-lifetime", "old-row"]) {
    const altered = narrowPhysical(right);
    if (change === "foreign-owner") altered.observation.sessions[0]!.userId = "another-user";
    if (change === "wrong-lifetime") altered.observation.sessions[0]!.expiresAt = iso(200_100 + 604801000);
    if (change === "old-row") altered.observation.sessions[0]!.expiresAt = iso(190_100 + 604800000);
    expect(compareValues(narrowPhysical(left), altered, narrowContext).some(diff => diff.path.endsWith("expiresAt"))).toBe(true);
    const row = altered.observation.sessions[0]!;
    const observedWrong = {...narrowContext, rightPhysicalObservations: [receipt("session", row.userId, {user: {id: row.userId}, sessions: [row]})]};
    expect(compareValues(narrowPhysical(left), altered, observedWrong).some(diff => diff.path.endsWith("expiresAt"))).toBe(true);
  }
  const pending = (side: string, issued: number) => ({
    traces: [
      {method: "POST", path: "/__test/profiles/two-factor-skip-verification/api/auth/sign-up/email", responseStatus: 200,
        responseBody: {token: side, user: {id: `${side}-user`, email: "owner@test.com"}}},
      {method: "POST", path: "/__test/profiles/two-factor-skip-verification/api/auth/sign-in/email", responseStatus: 200,
        responseBody: {twoFactorRedirect: true}},
    ],
    observation: {
      challenge: {id: `${side}-challenge`, identifier: {token: `2fa-${side.padEnd(20, "x")}`}, value: {userId: `${side}-user`},
        createdAt: iso(issued), updatedAt: iso(issued), expiresAt: iso(issued + 600_000)},
      attempts: {id: `${side}-attempt`, identifier: {token: `2fa-attempts-2fa-${side.padEnd(20, "x")}`}, value: "0",
        createdAt: iso(issued + 1), updatedAt: iso(issued + 1), expiresAt: iso(issued + 600_000)},
    },
  });
  const challengeCookie = (token: string) => cookie(token).replace("session_token=", "two_factor=");
  const pendingWindows = (side: string, issued: number) => [
    {startedAt: issued - 2000, finishedAt: issued - 1000, inputDates: {}, issuedSessionCookie: cookie(side)},
    {startedAt: issued - 10, finishedAt: issued + 10, inputDates: {}, signInEmail: "owner@test.com", issuedTwoFactorCookie: challengeCookie(`2fa-${side.padEnd(20, "x")}`)},
  ];
  const pendingReceipt = (value: ReturnType<typeof pending>) => Object.values(value.observation).map(row => receipt("verification", row.identifier.token, [{...row, identifier: row.identifier.token, value: typeof row.value === "string" ? row.value : row.value.userId}]));
  const pendingContext = {...context, sessionCookieSecret: secret,
    leftPhysicalObservations: pendingReceipt(pending("left", 100_100)), rightPhysicalObservations: pendingReceipt(pending("right", 210_100)), leftRequestWindows: pendingWindows("left", 100_100), rightRequestWindows: pendingWindows("right", 210_100)};
  const leftPending = pending("left", 100_100), rightPending = pending("right", 210_100);
  expect(compareValues(leftPending, rightPending, pendingContext)).toEqual([]);
  for (const change of ["foreign-owner", "unissued-identifier", "wrong-lifetime", "unrelated-date", "old-cookie", "invalid-signature", "foreign-email", "counter-expiry", "failed-issuer", "tampered-control"]) {
    const altered = structuredClone(rightPending), clocks = structuredClone(pendingContext);
    if (change === "foreign-owner") altered.observation.challenge.value.userId = "another-user";
    if (change === "unissued-identifier") altered.observation.challenge.identifier.token = "2fa-unissuedxxxxxxxxxxxx";
    if (change === "wrong-lifetime") for (const row of Object.values(altered.observation)) row.expiresAt = iso(809_100);
    if (change === "unrelated-date") altered.observation.challenge.createdAt = iso(215_100);
    if (change === "old-cookie") clocks.rightRequestWindows[1]!.issuedTwoFactorCookie = challengeCookie("2fa-oldxxxxxxxxxxxxxxxxx");
    if (change === "invalid-signature") clocks.rightRequestWindows[1]!.issuedTwoFactorCookie += "x";
    if (change === "foreign-email") clocks.rightRequestWindows[1]!.signInEmail = "foreign@test.com";
    if (change === "counter-expiry") altered.observation.attempts.expiresAt = iso(811_100);
    if (change === "failed-issuer") altered.traces[1]!.responseStatus = 401;
    if (change === "tampered-control") clocks.rightPhysicalObservations[0]!.digest = "invalid";
    expect(compareValues(leftPending, altered, clocks).some(diff => diff.path.startsWith("observation"))).toBe(true);
    if (["foreign-owner", "unissued-identifier", "wrong-lifetime", "unrelated-date", "counter-expiry"].includes(change)) {
      clocks.rightPhysicalObservations = pendingReceipt(altered);
      expect(compareValues(leftPending, altered, clocks).some(diff => diff.path.startsWith("observation"))).toBe(true);
    }
  }

  const trust = (side: string, issued: number, updated: number) => ({
    traces: [
      {method: "POST", path: "/__test/profiles/two-factor-trust-cleanup-disabled/api/auth/two-factor/verify-otp", responseStatus: 200,
        responseBody: {token: side, user: {id: `${side}-user`}}},
      {method: "POST", path: "/__test/verification-state", responseStatus: 200, responseBody: {status: true}},
    ],
    observation: {expiryRows: [{id: `${side}-trust-row`, identifier: {token: `trust-device-${side}`}, value: {userId: `${side}-user`},
      createdAt: iso(issued), updatedAt: iso(updated), expiresAt: "2020-01-01T00:00:00.000Z"}]},
  });
  const trustCookie = (side: string, owner = `${side}-user`) => {
    const identifier = `trust-device-${side}`, inner = createHmac("sha256", secret).update(`${owner}!${identifier}`).digest("base64url");
    return cookie(`${inner}!${identifier}`).replace("session_token=", "trust_device=");
  };
  const trustWindows = (side: string, issued: number, updated: number) => [
    {startedAt: issued - 10, finishedAt: issued + 10, inputDates: {}, issuedSessionCookie: cookie(side), issuedTrustCookie: trustCookie(side)},
    {startedAt: updated - 10, finishedAt: updated + 10, inputDates: {}, verificationInput: {action: "expire", identifier: `trust-device-${side}`, expiresAt: "2020-01-01T00:00:00.000Z"}},
  ];
  const trustReceipts = (value: ReturnType<typeof trust>) => value.observation.expiryRows.map(row => receipt("verification", row.identifier.token, [{...row, identifier: row.identifier.token, value: row.value.userId}]));
  const leftTrust = trust("left", 100100, 100900), rightTrust = trust("right", 210100, 210900);
  const trustContext = {...context, sessionCookieSecret: secret, leftRequestWindows: trustWindows("left", 100100, 100900), rightRequestWindows: trustWindows("right", 210100, 210900),
    leftPhysicalObservations: trustReceipts(leftTrust), rightPhysicalObservations: trustReceipts(rightTrust)};
  expect(compareValues(leftTrust, rightTrust, trustContext)).toEqual([]);
  for (const change of ["foreign-owner", "invalid-signature", "wrong-inner-owner", "failed-issuer", "wrong-expiry-owner", "wrong-expiry", "created-outside-issuer", "updated-outside-mutation", "tampered-control"]) {
    const altered = structuredClone(rightTrust), clocks = structuredClone(trustContext), row = altered.observation.expiryRows[0]!;
    if (change === "foreign-owner") row.value.userId = "foreign";
    if (change === "invalid-signature") clocks.rightRequestWindows[0]!.issuedTrustCookie += "x";
    if (change === "wrong-inner-owner") clocks.rightRequestWindows[0]!.issuedTrustCookie = trustCookie("right", "foreign");
    if (change === "failed-issuer") altered.traces[0]!.responseStatus = 400;
    if (change === "wrong-expiry-owner") clocks.rightRequestWindows[1]!.verificationInput!.identifier = "unrelated";
    if (change === "wrong-expiry") clocks.rightRequestWindows[1]!.verificationInput!.expiresAt = "2019-01-01T00:00:00.000Z";
    if (change === "created-outside-issuer") row.createdAt = iso(215100);
    if (change === "updated-outside-mutation") row.updatedAt = iso(215900);
    clocks.rightPhysicalObservations = trustReceipts(altered);
    if (change === "tampered-control") clocks.rightPhysicalObservations[0]!.digest = "invalid";
    expect(compareValues(leftTrust, altered, clocks).some(diff => /^observation\.expiryRows\.0\.(?:createdAt|updatedAt)$/.test(diff.path))).toBe(true);
  }

});

test("clock evidence cannot approve another field, entity or a changed lifetime", () => {
  const iso = (milliseconds: number) => new Date(milliseconds).toISOString();
  const session = (expiry: number) => ({
    id: "session",
    token: "token",
    userId: "owner",
    createdAt: iso(10),
    updatedAt: iso(10),
    expiresAt: iso(expiry),
  });
  const trace = (responseBody: unknown) => ({
    method: "GET",
    path: "/api/auth/get-session",
    responseBody,
  });
  const context = {
    leftBaseURL: "http://localhost:1",
    rightBaseURL: "http://localhost:2",
    leftStartedAt: 0,
    rightStartedAt: 0,
    leftRequestWindows: [
      { startedAt: 0, finishedAt: 100, inputDates: {} },
      { startedAt: 50, finishedAt: 100, inputDates: {} },
    ],
    rightRequestWindows: [
      { startedAt: 0, finishedAt: 6000, inputDates: {} },
      { startedAt: 5500, finishedAt: 5600, inputDates: {} },
    ],
  };
  const left = { traces: [trace({ session: session(50) })] };
  const right = { traces: [trace({ session: session(5500) })] };
  for (const extra of [false, true]) {
    const a = structuredClone(left),
      b = structuredClone(right);
    if (extra) {
      a.traces.push(trace({ user: { id: "user", createdAt: iso(50) } }));
      b.traces.push(trace({ user: { id: "user", createdAt: iso(5500) } }));
    }
    expect(
      compareValues(a, b, context).some(
        (diff) => diff.path === "traces.0.responseBody.session.expiresAt",
      ),
    ).toBe(true);
  }
});

test("discarded successful bodies and response policy headers remain observable", async () => {
  let mode = "baseline";
  const server = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    fetch: () =>
      Response.json(
        { result: { enabled: mode !== "body" } },
        {
          headers:
            mode === "headers"
              ? {}
              : {
                  "access-control-allow-origin": "https://client.example",
                  "cache-control": "no-store",
                },
        },
      ),
  });
  try {
    async function observe(next: string) {
      mode = next;
      const traces: TraceEntry[] = [];
      await createTracingFetch(
        server.url.origin,
        "actor",
        traces,
      )("/api/auth/ok");
      return { traces };
    }
    const baseline = await observe("baseline"),
      context = {
        leftBaseURL: server.url.origin,
        rightBaseURL: server.url.origin,
        leftStartedAt: 0,
        rightStartedAt: 0,
      };
    expect(compareValues(baseline, await observe("baseline"), context)).toEqual(
      [],
    );
    expect(
      compareValues(baseline, await observe("body"), context).some(
        (diff) => diff.path === "traces.0.responseBody.result.enabled",
      ),
    ).toBe(true);
    const missing = compareValues(baseline, await observe("headers"), context);
    expect(
      missing.some((diff) => diff.path.endsWith("access-control-allow-origin")),
    ).toBe(true);
    expect(missing.some((diff) => diff.path.endsWith("cache-control"))).toBe(
      true,
    );
  } finally {
    server.stop(true);
  }
});
