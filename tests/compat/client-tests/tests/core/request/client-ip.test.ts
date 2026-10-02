import { expect } from "bun:test";
import { createConnection } from "node:net";

import { apiKeyClient } from "@better-auth/api-key/client";
import { passkeyClient } from "@better-auth/passkey/client";
import { createAuthClient } from "better-auth/client";
import { deviceAuthorizationClient } from "better-auth/client/plugins";

import { Authenticator } from "../../../support/authenticator";
import { authProfilePath, type FixtureProfile } from "../../../support/profiles";
import { compatScenario, type ScenarioContext } from "../../../support/scenario";

type Row = {
  id: string;
  token: string;
  userId: string;
  ipAddress: string | null;
  userAgent: string | null;
  expiresAt: string;
  createdAt: string;
  updatedAt: string;
};

async function sessions(ctx: ScenarioContext) {
  const response = await ctx.rawRequest({ path: "/__test/client-ip/sessions" });
  expect(response.status).toBe(200);
  return response.body as Row[];
}

const cases: Array<{
  name: string;
  profile: FixtureProfile;
  headers: Record<string, string>;
  ip: string;
}> = [
  {
    name: "single IPv4",
    profile: "client-ip-default",
    headers: { "x-forwarded-for": "198.51.100.7" },
    ip: "198.51.100.7",
  },
  {
    name: "untrusted forged leftmost hop",
    profile: "client-ip-default",
    headers: { "x-forwarded-for": "198.51.100.7, 10.0.0.1" },
    ip: "",
  },
  {
    name: "default excludes x-real-ip",
    profile: "client-ip-default",
    headers: { "x-real-ip": "198.51.100.7" },
    ip: "",
  },
  {
    name: "malformed single address",
    profile: "client-ip-default",
    headers: { "x-forwarded-for": "198.51.100.7:9000" },
    ip: "",
  },
  {
    name: "strict IPv4 octets",
    profile: "client-ip-default",
    headers: { "x-forwarded-for": "198.051.100.7" },
    ip: "",
  },
  {
    name: "configured header priority",
    profile: "client-ip-ordered",
    headers: { "x-client-ip": "203.0.113.8", "x-forwarded-for": "198.51.100.7" },
    ip: "203.0.113.8",
  },
  {
    name: "invalid first header falls through",
    profile: "client-ip-ordered",
    headers: { "x-client-ip": "invalid", "x-forwarded-for": "198.51.100.7" },
    ip: "198.51.100.7",
  },
  {
    name: "rightmost untrusted hop",
    profile: "client-ip-trusted",
    headers: { "x-forwarded-for": "203.0.113.99, 198.51.100.7, 10.2.3.4, 192.0.2.9" },
    ip: "198.51.100.7",
  },
  {
    name: "all hops trusted",
    profile: "client-ip-trusted",
    headers: { "x-forwarded-for": "10.1.2.3, 192.0.2.9" },
    ip: "",
  },
  {
    name: "invalid rightmost hop fails closed",
    profile: "client-ip-trusted",
    headers: { "x-forwarded-for": "198.51.100.7, malformed" },
    ip: "",
  },
  {
    name: "empty tokens do not create hops",
    profile: "client-ip-trusted",
    headers: { "x-forwarded-for": ", 198.51.100.7, ,10.1.2.3," },
    ip: "198.51.100.7",
  },
  {
    name: "IPv6 proxy compares full address before grouping",
    profile: "client-ip-v6proxy",
    headers: { "x-forwarded-for": "2001:db8:1234:5678:abcd::7, 2001:db8:ffff::1234" },
    ip: "2001:0db8:1234:5678:0000:0000:0000:0000",
  },
  {
    name: "IPv4-mapped proxy matches IPv4 network",
    profile: "client-ip-mixed",
    headers: { "x-forwarded-for": "198.51.100.7, ::ffff:192.0.2.9" },
    ip: "198.51.100.7",
  },
  {
    name: "invalid networks never trust a chain",
    profile: "client-ip-invalid",
    headers: { "x-forwarded-for": "198.51.100.7, 10.1.2.3" },
    ip: "",
  },
  {
    name: "IPv4-mapped client normalizes to IPv4",
    profile: "client-ip-default",
    headers: { "x-forwarded-for": "::ffff:c633:6407" },
    ip: "198.51.100.7",
  },
  {
    name: "default IPv6 subnet",
    profile: "client-ip-default",
    headers: { "x-forwarded-for": "2001:DB8:1234:5678:abcd::7" },
    ip: "2001:0db8:1234:5678:0000:0000:0000:0000",
  },
  {
    name: "full IPv6 address",
    profile: "client-ip-full",
    headers: { "x-forwarded-for": "2001:DB8::7" },
    ip: "2001:0db8:0000:0000:0000:0000:0000:0007",
  },
  {
    name: "excess prefix retains full address",
    profile: "client-ip-excess",
    headers: { "x-forwarded-for": "2001:DB8::7" },
    ip: "2001:0db8:0000:0000:0000:0000:0000:0007",
  },
  {
    name: "zero IPv6 prefix",
    profile: "client-ip-zero",
    headers: { "x-forwarded-for": "2001:db8::7" },
    ip: "0000:0000:0000:0000:0000:0000:0000:0000",
  },
  {
    name: "negative IPv6 prefix",
    profile: "client-ip-negative",
    headers: { "x-forwarded-for": "2001:db8::7" },
    ip: "0000:0000:0000:0000:0000:0000:0000:0000",
  },
  {
    name: "fractional IPv6 prefix floors",
    profile: "client-ip-fractional",
    headers: { "x-forwarded-for": "2001:db8:1234:5678:ffff::7" },
    ip: "2001:0db8:1234:5678:8000:0000:0000:0000",
  },
  {
    name: "NaN IPv6 prefix retains full address",
    profile: "client-ip-nan",
    headers: { "x-forwarded-for": "2001:DB8::7" },
    ip: "2001:0db8:0000:0000:0000:0000:0000:0007",
  },
  {
    name: "tracking disabled",
    profile: "client-ip-disabled",
    headers: { "x-forwarded-for": "198.51.100.7" },
    ip: "",
  },
  {
    name: "empty configured headers",
    profile: "client-ip-empty",
    headers: { "x-forwarded-for": "198.51.100.7" },
    ip: "",
  },
  {
    name: "uppercase hexadecimal mapped marker retains IPv6 grouping",
    profile: "client-ip-default",
    headers: { "x-forwarded-for": "::FFFF:c633:6407" },
    ip: "0000:0000:0000:0000:0000:0000:0000:0000",
  },
  {
    name: "uppercase dotted mapped marker resolves IPv4",
    profile: "client-ip-default",
    headers: { "x-forwarded-for": "::FFFF:198.51.100.7" },
    ip: "198.51.100.7",
  },
  {
    name: "embedded IPv4 retains full published IPv6 representation",
    profile: "client-ip-full",
    headers: { "x-forwarded-for": "2001:db8::192.0.2.1" },
    ip: "2001:0db8:0000:0000:0000:0000:0000:192.0.2.1",
  },
];

for (const row of cases) {
  compatScenario(
    `client IP ${row.name} persists authoritative session context`,
    async (ctx) => {
      const foreign = ctx.actor("foreign", "client-ip-full");
      const foreignSignup = await foreign.client.signUp.email(
        { email: ctx.uniqueEmail("ip-foreign"), name: "Foreign Owner", password: "Password123!" },
        { headers: { "x-forwarded-for": "203.0.113.77", "user-agent": "foreign-browser" } },
      );
      expect(foreignSignup.error).toBeNull();

      const foreignBefore = await sessions(ctx);
      expect(foreignBefore).toHaveLength(1);
      expect(foreignBefore[0]!.ipAddress).toBe("203.0.113.77");

      const owner = ctx.actor("owner", row.profile);
      const email = ctx.uniqueEmail("ip-owner");
      const headers = { ...row.headers, "user-agent": "configured-browser" };
      const signup = await owner.client.signUp.email(
        { email, name: "IP Owner", password: "Password123!" },
        { headers },
      );
      expect(signup.error).toBeNull();

      const after = await sessions(ctx);
      expect(after).toHaveLength(2);
      expect(after.find((value) => value.id === foreignBefore[0]!.id)).toEqual(foreignBefore[0]);

      const own = after.find((value) => value.id !== foreignBefore[0]!.id)!;
      expect(own).toMatchObject({ ipAddress: row.ip, userAgent: "configured-browser" });

      const current = await owner.client.getSession();
      expect(current.error).toBeNull();
      expect(current.data?.session).toMatchObject({
        id: own.id,
        userId: own.userId,
        token: own.token,
        ipAddress: row.ip,
        userAgent: "configured-browser",
      });

      const beforeDenied = await sessions(ctx);
      const denied = await owner.client.signIn.email(
        { email, password: "wrong-password" },
        { headers },
      );
      expect(denied.error?.status).toBe(401);
      expect(await sessions(ctx)).toEqual(beforeDenied);

      const signOut = await owner.client.signOut();
      expect(signOut.error).toBeNull();
      expect((await owner.client.getSession()).data).toBeNull();
      expect(await sessions(ctx)).toEqual(foreignBefore);

      return {
        foreignSignup: ctx.snapshot(foreignSignup),
        foreignBefore,
        signup: ctx.snapshot(signup),
        after,
        current: ctx.snapshot(current),
        denied: ctx.snapshot(denied),
        beforeDenied,
        signOut: ctx.snapshot(signOut),
        final: await sessions(ctx),
      };
    },
    ["POST /sign-up/email", "GET /get-session", "POST /sign-in/email", "POST /sign-out"],
  );
}

const buckets: Array<{
  name: string;
  profile: FixtureProfile;
  inputs: Record<string, string>[];
  statuses: number[];
}> = [
  {
    name: "normalized IPv6 subnet",
    profile: "client-ip-default",
    inputs: [
      { "x-forwarded-for": "2001:DB8:aaa:1234::1" },
      { "x-forwarded-for": "2001:db8:aaa:1234::2" },
      { "x-forwarded-for": "2001:0db8:0aaa:1234:ffff::3" },
      { "x-forwarded-for": "2001:db8:bbb:1234::1" },
    ],
    statuses: [200, 200, 429, 200],
  },
  {
    name: "IPv4 mapped representations",
    profile: "client-ip-default",
    inputs: [
      { "x-forwarded-for": "198.51.100.202" },
      { "x-forwarded-for": "::ffff:c633:64ca" },
      { "x-forwarded-for": "::ffff:198.51.100.202" },
      { "x-forwarded-for": "198.51.100.203" },
    ],
    statuses: [200, 200, 429, 200],
  },
  {
    name: "unresolved shared bucket resists forged chains",
    profile: "client-ip-default",
    inputs: [
      { "x-forwarded-for": "198.51.100.201, 10.1.2.3" },
      { "x-forwarded-for": "198.51.100.202:9000" },
      {},
      { "x-forwarded-for": "198.51.100.204" },
    ],
    statuses: [200, 200, 429, 200],
  },
  {
    name: "trusted chain ignores forged leftmost values",
    profile: "client-ip-trusted",
    inputs: [
      { "x-forwarded-for": "203.0.113.1, 198.51.100.205, 10.1.2.3" },
      { "x-forwarded-for": "203.0.113.2, 198.51.100.205, 10.3.2.1, 192.0.2.9" },
      { "x-forwarded-for": "198.51.100.205" },
      { "x-forwarded-for": "198.51.100.206" },
    ],
    statuses: [200, 200, 429, 200],
  },
  {
    name: "configured header controls admission",
    profile: "client-ip-ordered",
    inputs: [
      { "x-client-ip": "198.51.100.207", "x-forwarded-for": "203.0.113.1" },
      { "x-client-ip": "198.51.100.207", "x-forwarded-for": "203.0.113.2" },
      { "x-client-ip": "198.51.100.207" },
      { "x-client-ip": "198.51.100.208" },
    ],
    statuses: [200, 200, 429, 200],
  },
  {
    name: "empty headers use shared bucket",
    profile: "client-ip-empty",
    inputs: [
      { "x-forwarded-for": "198.51.100.209" },
      { "x-forwarded-for": "198.51.100.210" },
      { "x-forwarded-for": "198.51.100.211" },
      {},
    ],
    statuses: [200, 200, 429, 429],
  },
  {
    name: "disabled tracking disables IP rate limiting",
    profile: "client-ip-disabled",
    inputs: [
      { "x-forwarded-for": "198.51.100.212" },
      { "x-forwarded-for": "198.51.100.212" },
      { "x-forwarded-for": "198.51.100.212" },
      {},
    ],
    statuses: [200, 200, 200, 200],
  },
  {
    name: "full IPv6 prefix separates interface addresses",
    profile: "client-ip-full",
    inputs: [
      { "x-forwarded-for": "2001:db8:ccc:1234::1" },
      { "x-forwarded-for": "2001:db8:ccc:1234::2" },
      { "x-forwarded-for": "2001:db8:ccc:1234::3" },
      { "x-forwarded-for": "2001:db8:ccc:1234::4" },
    ],
    statuses: [200, 200, 200, 200],
  },
];

for (const row of buckets) {
  compatScenario(
    `client IP ${row.name} selects real HTTP rate buckets`,
    async (ctx) => {
      const foreign = ctx.actor("foreign", "client-ip-full");
      const signup = await foreign.client.signUp.email({
        email: ctx.uniqueEmail("bucket-foreign"),
        password: "Password123!",
        name: "Foreign",
      });
      expect(signup.error).toBeNull();

      const before = await sessions(ctx);
      const responses = [];

      for (const [index, headers] of row.inputs.entries()) {
        const endpoint =
          row.profile === "client-ip-empty" ? "/client-ip-rate-empty" : "/client-ip-rate-check";
        const raw = await ctx
          .actor("bucket")
          .fetch(authProfilePath(row.profile) + endpoint, { headers });
        const response = {
          status: raw.status,
          body: await raw.text(),
          headers: {
            "content-type": raw.headers.get("content-type"),
            "x-retry-after": raw.headers.get("x-retry-after"),
          },
        };
        expect(response.status).toBe(row.statuses[index]!);

        if (response.status === 429) {
          expect(response.body).toBe('{"message":"Too many requests. Please try again later."}');
          expect(response.headers["content-type"]).toBe("text/plain;charset=utf-8");
          expect(response.headers["x-retry-after"]).toBe("60");
        } else {
          expect(JSON.parse(response.body)).toEqual({ ok: true });
        }

        responses.push(response);
        expect(await sessions(ctx)).toEqual(before);
      }

      expect((await foreign.client.getSession()).data?.user.id).toBe(signup.data!.user.id);

      const health = await ctx.rawRequest({ path: authProfilePath(row.profile) + "/ok" });
      expect(health.status).toBe(200);
      expect(health.body).toEqual({ ok: true });

      return {
        signup: ctx.snapshot(signup),
        before,
        responses,
        health,
        after: await sessions(ctx),
      };
    },
    ["GET /ok"],
  );
}

compatScenario(
  "client IP repeated forwarded fields cannot rotate the unresolved rate bucket",
  async (ctx) => {
    const path = authProfilePath("client-ip-default") + "/client-ip-rate-duplicate";
    const responses = [];

    for (const tail of ["10.1.2.3", "192.0.2.9", "203.0.113.9"]) {
      const forwarded = ["198.51.100.219", tail];
      const response = await wireRequest(ctx, path, [
        ["X-Forwarded-For", forwarded[0]!],
        ["X-Forwarded-For", forwarded[1]!],
      ]);
      responses.push({ forwarded, response });
    }

    expect(responses.map((row) => row.response.status)).toEqual([200, 200, 429]);
    expect(responses[2]!.response.body).toEqual({
      message: "Too many requests. Please try again later.",
    });
    expect(await sessions(ctx)).toEqual([]);

    return { responses, sessions: await sessions(ctx) };
  },
);

for (const profile of ["client-ip-trusted", "client-ip-disabled"] as const) {
  compatScenario(
    `client IP ${profile} device redemption stores polling context and preserves foreign authority`,
    async (ctx) => {
      const foreign = ctx.actor("foreign", "client-ip-full");
      const owner = ctx.actor("owner", profile);
      const other = await foreign.client.signUp.email(
        { email: ctx.uniqueEmail("device-ip-foreign"), password: "Password123!", name: "Foreign" },
        { headers: { "x-forwarded-for": "203.0.113.77", "user-agent": "foreign-browser" } },
      );
      const signup = await owner.client.signUp.email(
        { email: ctx.uniqueEmail("device-ip-owner"), password: "Password123!", name: "Owner" },
        {
          headers: { "x-forwarded-for": "198.51.100.217, 10.1.2.3", "user-agent": "owner-browser" },
        },
      );
      expect(other.error).toBeNull();
      expect(signup.error).toBeNull();

      const before = await sessions(ctx);
      const foreignBefore = await ctx.readUserState({ userId: other.data!.user.id });
      const client = (name: string) =>
        createAuthClient({
          baseURL: ctx.baseURL,
          plugins: [deviceAuthorizationClient()],
          fetchOptions: { customFetchImpl: ctx.actor(name, profile).fetch },
        });
      const device = client("poller");
      const browser = client("owner");
      const code = await device.device.code({ client_id: "ip-device-client", scope: "read write" });
      expect(code.error).toBeNull();

      const originalCode = await ctx.readDeviceState({ deviceCode: code.data!.device_code });
      const unauthenticated = await device.device.approve({ userCode: code.data!.user_code });
      expect(unauthenticated.error?.status).toBe(401);
      expect(await sessions(ctx)).toEqual(before);

      const claim = await browser.device({ query: { user_code: code.data!.user_code } });
      expect(claim.error).toBeNull();

      const approval = await browser.device.approve({ userCode: code.data!.user_code });
      expect(approval.data).toEqual({ success: true });

      const approvedCode = await ctx.readDeviceState({ deviceCode: code.data!.device_code });
      const wrong = await device.device.token({
        grant_type: "urn:ietf:params:oauth:grant-type:device_code",
        client_id: "wrong-client",
        device_code: code.data!.device_code,
      });
      expect(wrong.error).toMatchObject({ status: 400, error: "invalid_grant" });
      expect(await ctx.readDeviceState({ deviceCode: code.data!.device_code })).toEqual(
        approvedCode,
      );
      expect(await sessions(ctx)).toEqual(before);

      const token = await device.device.token(
        {
          grant_type: "urn:ietf:params:oauth:grant-type:device_code",
          client_id: "ip-device-client",
          device_code: code.data!.device_code,
        },
        {
          headers: {
            "x-forwarded-for": "203.0.113.99, 198.51.100.218, 10.2.3.4",
            "user-agent": "device-poller",
          },
        },
      );
      expect(token.error).toBeNull();
      expect(token.data?.token_type).toBe("Bearer");

      const after = await sessions(ctx);
      expect(after).toHaveLength(3);

      for (const row of before) {
        expect(after.find((value) => value.id === row.id)).toEqual(row);
      }

      const issued = after.find((row) => row.token === token.data!.access_token)!;
      expect(issued).toMatchObject({
        userId: signup.data!.user.id,
        ipAddress: profile === "client-ip-disabled" ? "" : "198.51.100.218",
        userAgent: "device-poller",
      });
      expect(issued.token).not.toBe(signup.data!.token);
      expect(token.data!.expires_in).toBeGreaterThanOrEqual(604799);
      expect(token.data!.expires_in).toBeLessThanOrEqual(604800);
      expect(await ctx.readDeviceState({ deviceCode: code.data!.device_code })).toBeNull();

      const replay = await device.device.token({
        grant_type: "urn:ietf:params:oauth:grant-type:device_code",
        client_id: "ip-device-client",
        device_code: code.data!.device_code,
      });
      expect(replay.error).toMatchObject({ status: 400, error: "invalid_grant" });
      expect(await sessions(ctx)).toEqual(after);

      const revoke = await owner.client.revokeSession({ token: issued.token });
      expect(revoke.error).toBeNull();
      expect(await sessions(ctx)).toEqual(before);
      expect(await ctx.readUserState({ userId: other.data!.user.id })).toEqual(foreignBefore);

      return {
        other: ctx.snapshot(other),
        signup: ctx.snapshot(signup),
        before,
        originalCode,
        code: ctx.snapshot(code),
        unauthenticated: ctx.snapshot(unauthenticated),
        claim: ctx.snapshot(claim),
        approval: ctx.snapshot(approval),
        approvedCode,
        wrong: ctx.snapshot(wrong),
        token: ctx.snapshot(token),
        after,
        replay: ctx.snapshot(replay),
        revoke: ctx.snapshot(revoke),
        final: await sessions(ctx),
        foreignBefore,
        foreignAfter: await ctx.readUserState({ userId: other.data!.user.id }),
      };
    },
    [
      "POST /device/code",
      "GET /device",
      "POST /device/approve",
      "POST /device/token",
      "POST /revoke-session",
    ],
  );
}

compatScenario(
  "client IP concurrent equivalent addresses atomically share a bucket",
  async (ctx) => {
    const path = authProfilePath("client-ip-default") + "/client-ip-rate-check";
    const headers = { "x-forwarded-for": "2001:db8:ddd:1234::1" };
    const first = await ctx.rawRequest({ path, headers });
    expect(first.status).toBe(200);

    const responses = await Promise.all(
      Array.from({ length: 3 }, () => ctx.rawRequest({ path, headers })),
    );
    expect(responses.map((row) => row.status).sort()).toEqual([200, 429, 429]);
    expect(await sessions(ctx)).toEqual([]);

    const health = await ctx.rawRequest({
      path: authProfilePath("client-ip-default") + "/ok",
      headers,
    });
    expect(health.status).toBe(200);
    expect(health.body).toEqual({ ok: true });

    return {
      first,
      responses: responses.sort((left, right) => left.status - right.status),
      health,
      sessions: await sessions(ctx),
    };
  },
  ["GET /ok"],
);

// Actual TCP preserves duplicate fields that fetch/Headers would combine.
async function wireRequest(ctx: ScenarioContext, path: string, headers: Array<[string, string]>) {
  return new Promise<{
    status: number;
    body: unknown;
    headers: Record<string, string | undefined>;
  }>((resolve, reject) => {
    const url = new URL(ctx.baseURL);
    const chunks: Buffer[] = [];
    const socket = createConnection({ host: "127.0.0.1", port: Number(url.port) }, () => {
      socket.write(
        `GET ${path} HTTP/1.1\r\nHost: ${url.host}\r\n${headers.map(([name, value]) => `${name}: ${value}\r\n`).join("")}Connection: close\r\n\r\n`,
      );
    });
    socket.on("data", (chunk) => chunks.push(Buffer.from(chunk)));
    socket.on("error", reject);
    socket.on("end", () => {
      const wire = Buffer.concat(chunks).toString();
      const separator = wire.indexOf("\r\n\r\n");
      const [status, ...lines] = wire.slice(0, separator).split("\r\n");
      const fields = Object.fromEntries(
        lines.map((line) => {
          const colon = line.indexOf(":");
          return [line.slice(0, colon).toLowerCase(), line.slice(colon + 1).trim()];
        }),
      );
      const text = wire.slice(separator + 4);
      resolve({
        status: Number(status!.split(" ")[1]),
        body: text ? JSON.parse(text) : null,
        headers: {
          "content-type": fields["content-type"],
          "x-retry-after": fields["x-retry-after"],
        },
      });
    });
  });
}

compatScenario(
  "client IP forwarding fold retains genuine authority across repeated Cookie fields",
  async (ctx) => {
    const owner = ctx.actor("owner", "client-ip-default");
    const foreign = ctx.actor("foreign", "client-ip-full");
    const other = await foreign.client.signUp.email({
      email: ctx.uniqueEmail("cookie-foreign"),
      name: "Foreign",
      password: "Password123!",
    });
    expect(other.error).toBeNull();

    const foreignState = await ctx.readUserState({ userId: other.data!.user.id });
    let cookies: string[] = [];
    const signup = await owner.client.signUp.email(
      { email: ctx.uniqueEmail("cookie-owner"), name: "Owner", password: "Password123!" },
      {
        onSuccess({ response }) {
          cookies = response.headers.getSetCookie();
        },
      },
    );
    expect(signup.error).toBeNull();

    const signed = cookies
      .find((value) => value.startsWith("better-auth.session_token="))
      ?.split(";")[0];
    expect(signed).toBeDefined();

    const before = await sessions(ctx);
    const admitted = await wireRequest(ctx, authProfilePath("client-ip-default") + "/get-session", [
      ["Cookie", signed!],
      ["Cookie", "application.theme=dark"],
    ]);
    expect(admitted.status).toBe(200);
    expect(admitted.body).toMatchObject({
      user: { id: signup.data!.user.id },
      session: { userId: signup.data!.user.id, token: signup.data!.token },
    });
    expect(await sessions(ctx)).toEqual(before);
    expect(await ctx.readUserState({ userId: other.data!.user.id })).toEqual(foreignState);

    const signOut = await owner.client.signOut();
    expect(signOut.error).toBeNull();

    const after = await sessions(ctx);
    const replay = await wireRequest(ctx, authProfilePath("client-ip-default") + "/get-session", [
      ["Cookie", signed!],
      ["Cookie", "application.theme=dark"],
    ]);
    expect(replay.status).toBe(200);
    expect(replay.body).toBeNull();
    expect(await sessions(ctx)).toEqual(after);
    expect(await ctx.readUserState({ userId: other.data!.user.id })).toEqual(foreignState);

    return {
      other: ctx.snapshot(other),
      foreignState,
      signup: ctx.snapshot(signup),
      before,
      admitted,
      signOut: ctx.snapshot(signOut),
      after,
      replay,
      foreignAfter: await ctx.readUserState({ userId: other.data!.user.id }),
    };
  },
  ["GET /get-session", "POST /sign-out"],
);

for (const profile of ["client-ip-trusted", "client-ip-disabled"] as const) {
  compatScenario(
    `client IP ${profile} passkey login applies initialized policy after a genuine signature`,
    async (ctx) => {
      const owner = ctx.actor("owner", profile);
      const foreign = ctx.actor("foreign", "client-ip-full");
      const other = await foreign.client.signUp.email({
        email: ctx.uniqueEmail("passkey-ip-foreign"),
        name: "Foreign",
        password: "Password123!",
      });
      expect(other.error).toBeNull();

      const foreignState = await ctx.readUserState({ userId: other.data!.user.id });
      const signup = await owner.client.signUp.email({
        email: ctx.uniqueEmail("passkey-ip-owner"),
        name: "Owner",
        password: "Password123!",
      });
      expect(signup.error).toBeNull();

      const passkey = createAuthClient({
        baseURL: ctx.baseURL,
        plugins: [passkeyClient()],
        fetchOptions: { customFetchImpl: owner.fetch },
      });
      const authenticator = new Authenticator();
      const options = await passkey.$fetch("/passkey/generate-register-options", { method: "GET" });
      expect(options.error).toBeNull();

      const registration = await passkey.$fetch("/passkey/verify-registration", {
        method: "POST",
        body: { response: authenticator.register(options.data, ctx.baseURL), name: "IP Key" },
      });
      expect(registration.error).toBeNull();

      const signOut = await owner.client.signOut();
      expect(signOut.error).toBeNull();

      const before = await sessions(ctx);
      const beforeState = await ctx.readUserState({ userId: signup.data!.user.id });
      const authOptions = await passkey.$fetch("/passkey/generate-authenticate-options", {
        method: "GET",
      });
      expect(authOptions.error).toBeNull();

      const assertion = authenticator.authenticate(authOptions.data, ctx.baseURL);
      const headers = {
        "x-forwarded-for": "203.0.113.99, 198.51.100.222, 10.2.3.4",
        "user-agent": "passkey-browser",
      };
      const authenticated = await passkey.$fetch("/passkey/verify-authentication", {
        method: "POST",
        body: { response: assertion },
        headers,
      });
      expect(authenticated.error).toBeNull();

      const current = await owner.client.getSession();
      expect(current.data!.user.id).toBe(signup.data!.user.id);

      const after = await sessions(ctx);
      const issued = after.find((row) => row.id === current.data!.session.id)!;
      expect(after).toHaveLength(before.length + 1);

      for (const row of before) {
        expect(after.find((value) => value.id === row.id)).toEqual(row);
      }

      expect(issued).toMatchObject({
        userId: signup.data!.user.id,
        ipAddress: profile === "client-ip-disabled" ? "" : "198.51.100.222",
        userAgent: "passkey-browser",
      });

      const afterState = await ctx.readUserState({ userId: signup.data!.user.id });
      const replay = await passkey.$fetch("/passkey/verify-authentication", {
        method: "POST",
        body: { response: assertion },
        headers,
      });
      expect(replay.error?.status).toBe(400);
      expect(await sessions(ctx)).toEqual(after);
      expect(await ctx.readUserState({ userId: signup.data!.user.id })).toEqual(afterState);
      expect(await ctx.readUserState({ userId: other.data!.user.id })).toEqual(foreignState);

      return {
        other: ctx.snapshot(other),
        foreignState,
        signup: ctx.snapshot(signup),
        options: ctx.snapshot(options),
        registration: ctx.snapshot(registration),
        signOut: ctx.snapshot(signOut),
        before,
        beforeState,
        authOptions: ctx.snapshot(authOptions),
        authenticated: ctx.snapshot(authenticated),
        current: ctx.snapshot(current),
        after,
        afterState,
        replay: ctx.snapshot(replay),
        foreignAfter: await ctx.readUserState({ userId: other.data!.user.id }),
      };
    },
    [
      "GET /passkey/generate-register-options",
      "POST /passkey/verify-registration",
      "GET /passkey/generate-authenticate-options",
      "POST /passkey/verify-authentication",
    ],
  );
}

for (const profile of ["client-ip-trusted", "client-ip-disabled"] as const) {
  compatScenario(
    `client IP ${profile} verified email auto-signin applies initialized policy`,
    async (ctx) => {
      const owner = ctx.actor("owner", profile);
      const foreign = ctx.actor("foreign", "client-ip-full");
      const email = ctx.uniqueEmail("verification-ip-owner");
      const other = await foreign.client.signUp.email({
        email: ctx.uniqueEmail("verification-ip-foreign"),
        name: "Foreign",
        password: "Password123!",
      });
      expect(other.error).toBeNull();

      const foreignState = await ctx.readUserState({ userId: other.data!.user.id });
      const signup = await owner.client.signUp.email({
        email,
        name: "Owner",
        password: "Password123!",
      });
      expect(signup.error).toBeNull();

      const sent = await owner.client.sendVerificationEmail({ email });
      expect(sent.error).toBeNull();

      const delivery = (await ctx.readVerificationEmail({ email })) as {
        token: string;
        url: string;
      };
      expect(delivery.token).toBeString();

      const signOut = await owner.client.signOut();
      expect(signOut.error).toBeNull();

      const before = await sessions(ctx);
      const beforeState = await ctx.readUserState({ userId: signup.data!.user.id });
      const headers = {
        "x-forwarded-for": "203.0.113.99, 198.51.100.223, 10.2.3.4",
        "user-agent": "verification-browser",
      };
      const forged = await owner.client.verifyEmail(
        { query: { token: delivery.token.slice(0, -2) + "xx" } },
        { headers },
      );
      expect(forged.error?.status).toBe(401);
      expect(await sessions(ctx)).toEqual(before);
      expect(await ctx.readUserState({ userId: signup.data!.user.id })).toEqual(beforeState);

      const verified = await owner.client.verifyEmail(
        { query: { token: delivery.token } },
        { headers },
      );
      expect(verified.error).toBeNull();

      const current = await owner.client.getSession();
      expect(current.data!.user.id).toBe(signup.data!.user.id);

      const after = await sessions(ctx);
      const issued = after.find((row) => row.id === current.data!.session.id)!;
      expect(after).toHaveLength(before.length + 1);

      for (const row of before) {
        expect(after.find((value) => value.id === row.id)).toEqual(row);
      }

      expect(issued).toMatchObject({
        userId: signup.data!.user.id,
        ipAddress: profile === "client-ip-disabled" ? "" : "198.51.100.223",
        userAgent: "verification-browser",
      });
      expect(current.data!.user.emailVerified).toBe(true);
      expect(await ctx.readUserState({ userId: other.data!.user.id })).toEqual(foreignState);

      return {
        other: ctx.snapshot(other),
        foreignState,
        signup: ctx.snapshot(signup),
        sent: ctx.snapshot(sent),
        delivery,
        signOut: ctx.snapshot(signOut),
        before,
        beforeState,
        forged: ctx.snapshot(forged),
        verified: ctx.snapshot(verified),
        current: ctx.snapshot(current),
        after,
        foreignAfter: await ctx.readUserState({ userId: other.data!.user.id }),
      };
    },
    ["POST /send-verification-email", "GET /verify-email", "GET /get-session"],
  );
}

compatScenario(
  "client IP trusted admin impersonation retains operator and foreign authority with resolved metadata",
  async (ctx) => {
    const profile = "client-ip-trusted";
    const operator = ctx.actor("operator", profile);
    const target = ctx.actor("target", profile);
    const foreign = ctx.actor("foreign", "client-ip-full");
    const operatorEmail = ctx.uniqueEmail("ip-admin");
    const admin = await operator.client.signUp.email({
      email: operatorEmail,
      name: "Admin",
      password: "Password123!",
    });
    expect(admin.error).toBeNull();

    await ctx.promoteAdmin({ email: operatorEmail });
    const signup = await target.client.signUp.email({
      email: ctx.uniqueEmail("ip-target"),
      name: "Target",
      password: "Password123!",
    });
    expect(signup.error).toBeNull();

    const other = await foreign.client.signUp.email({
      email: ctx.uniqueEmail("ip-admin-foreign"),
      name: "Foreign",
      password: "Password123!",
    });
    expect(other.error).toBeNull();

    const before = await sessions(ctx);
    const foreignState = await ctx.readUserState({ userId: other.data!.user.id });
    const denied = await target.client.admin.impersonateUser({ userId: admin.data!.user.id });
    expect(denied.error?.status).toBe(403);
    expect(await sessions(ctx)).toEqual(before);

    const impersonated = await operator.client.admin.impersonateUser(
      { userId: signup.data!.user.id },
      {
        headers: {
          "x-forwarded-for": "203.0.113.99, 198.51.100.224, 10.2.3.4",
          "user-agent": "admin-browser",
        },
      },
    );
    expect(impersonated.error).toBeNull();

    const current = await operator.client.getSession();
    expect(current.data!.user.id).toBe(signup.data!.user.id);

    const after = await sessions(ctx);
    const issued = after.find((row) => row.id === current.data!.session.id)!;
    expect(after).toHaveLength(before.length + 1);

    for (const row of before) {
      expect(after.find((value) => value.id === row.id)).toEqual(row);
    }

    expect(issued).toMatchObject({
      userId: signup.data!.user.id,
      ipAddress: "198.51.100.224",
      userAgent: "admin-browser",
    });

    const stop = await operator.client.admin.stopImpersonating();
    expect(stop.error).toBeNull();
    expect((await operator.client.getSession()).data!.user.id).toBe(admin.data!.user.id);
    expect(await sessions(ctx)).toEqual(before);
    expect(await ctx.readUserState({ userId: other.data!.user.id })).toEqual(foreignState);

    return {
      admin: ctx.snapshot(admin),
      signup: ctx.snapshot(signup),
      other: ctx.snapshot(other),
      before,
      foreignState,
      denied: ctx.snapshot(denied),
      impersonated: ctx.snapshot(impersonated),
      current: ctx.snapshot(current),
      after,
      stop: ctx.snapshot(stop),
      final: await sessions(ctx),
      foreignAfter: await ctx.readUserState({ userId: other.data!.user.id }),
    };
  },
  ["POST /admin/impersonate-user", "POST /admin/stop-impersonating"],
);

for (const profile of ["client-ip-trusted", "client-ip-ordered", "client-ip-disabled"] as const) {
  compatScenario(
    `client IP ${profile} API-key virtual principals keep nullable metadata and override foreign cookies`,
    async (ctx) => {
      const owner = ctx.actor("owner", profile);
      const foreign = ctx.actor("foreign", "client-ip-full");
      const signup = await owner.client.signUp.email({
        email: ctx.uniqueEmail("virtual-ip-owner"),
        name: "Owner",
        password: "Password123!",
      });
      expect(signup.error).toBeNull();

      let cookies: string[] = [];
      const other = await foreign.client.signUp.email(
        { email: ctx.uniqueEmail("virtual-ip-foreign"), name: "Foreign", password: "Password123!" },
        {
          onSuccess({ response }) {
            cookies = response.headers.getSetCookie();
          },
        },
      );
      expect(other.error).toBeNull();

      const cookie = cookies
        .find((value) => value.startsWith("better-auth.session_token="))
        ?.split(";")[0];
      expect(cookie).toBeDefined();

      const client = createAuthClient({
        baseURL: ctx.baseURL,
        plugins: [apiKeyClient()],
        fetchOptions: { customFetchImpl: owner.fetch },
      });
      const created = await client.apiKey.create({ name: "Configured virtual principal" });
      expect(created.error).toBeNull();

      const key = created.data!;
      const before = await sessions(ctx);
      const ownerState = await ctx.readUserState({ userId: signup.data!.user.id });
      const foreignState = await ctx.readUserState({ userId: other.data!.user.id });
      const headers = {
        "x-api-key": key.key,
        cookie: cookie!,
        "x-forwarded-for": "203.0.113.99, 198.51.100.225, 10.2.3.4",
        "x-client-ip": "198.51.100.226",
        "user-agent": "virtual-browser",
      };
      const current = await ctx
        .actor("machine", profile)
        .client.getSession({ fetchOptions: { headers } });
      expect(current.error).toBeNull();
      expect(current.data!.user.id).toBe(signup.data!.user.id);
      expect(current.data!.session).toMatchObject({
        id: key.id,
        userId: signup.data!.user.id,
        token: key.key,
        userAgent: "virtual-browser",
        ipAddress:
          profile === "client-ip-disabled"
            ? null
            : profile === "client-ip-ordered"
              ? "198.51.100.226"
              : "198.51.100.225",
      });

      const nullable = await wireRequest(ctx, authProfilePath(profile) + "/get-session", [
        ["x-api-key", key.key],
        ["Cookie", cookie!],
      ]);
      expect(nullable.status).toBe(200);
      expect(nullable.body).toMatchObject({
        user: { id: signup.data!.user.id },
        session: {
          id: key.id,
          userId: signup.data!.user.id,
          token: key.key,
          ipAddress: null,
          userAgent: null,
        },
      });
      expect(await sessions(ctx)).toEqual(before);
      expect(await ctx.readUserState({ userId: signup.data!.user.id })).toEqual(ownerState);
      expect(await ctx.readUserState({ userId: other.data!.user.id })).toEqual(foreignState);

      const invalid = await ctx.actor("invalid-machine", profile).client.getSession({
        fetchOptions: { headers: { ...headers, "x-api-key": "invalid-short-key" } },
      });
      expect(invalid.error?.status).toBe(403);
      expect(await sessions(ctx)).toEqual(before);
      expect(await ctx.readUserState({ userId: other.data!.user.id })).toEqual(foreignState);

      return {
        signup: ctx.snapshot(signup),
        other: ctx.snapshot(other),
        created: ctx.snapshot(created),
        before,
        ownerState,
        foreignState,
        current: ctx.snapshot(current),
        nullable,
        invalid: ctx.snapshot(invalid),
        after: await sessions(ctx),
        ownerAfter: await ctx.readUserState({ userId: signup.data!.user.id }),
        foreignAfter: await ctx.readUserState({ userId: other.data!.user.id }),
      };
    },
    ["POST /api-key/create", "GET /get-session"],
  );
}
