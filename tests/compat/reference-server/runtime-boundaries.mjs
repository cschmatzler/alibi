// A fresh process per case isolates Better Auth's environment and project-ID caches.
// Every event comes from supported betterAuth initialization or ctx.publishTelemetry.
import { createServer } from "node:http";

const mode = process.argv[2];
const events = [];
const errors = [];
const logs = [];

const server = createServer(async (req, res) => {
  const chunks = [];

  for await (const chunk of req) {
    chunks.push(chunk);
  }

  events.push(JSON.parse(Buffer.concat(chunks).toString()));
  res.writeHead(mode === "failure" ? 500 : 200, { "content-type": "application/json" });
  res.end("{}");
});

await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));

const endpoint = `http://127.0.0.1:${server.address().port}`;

process.env.BETTER_AUTH_TELEMETRY_ENDPOINT = mode === "no-endpoint" ? "" : endpoint;
process.env.BETTER_AUTH_TELEMETRY = mode === "environment" ? "true" : "false";
process.env.BETTER_AUTH_TELEMETRY_DEBUG = "false";
process.env.NODE_ENV = mode === "test" ? "test" : "production";
process.env.BUN_ENV = process.env.NODE_ENV;

const { betterAuth } = await import("better-auth");
const { memoryAdapter } = await import("better-auth/adapters/memory");
const { emailOTP, organization, testUtils } = await import("better-auth/plugins");
const { createAccessControl } = await import("better-auth/plugins/access");

const rows = {
  user: [],
  session: [],
  account: [],
  verification: [],
  organization: [],
  member: [],
  invitation: [],
};

let providerCalls = 0;
const enabled = !["default", "disabled", "environment"].includes(mode);

const auth = betterAuth({
  baseURL: "http://runtime-boundaries.example.com",
  secret: "synthetic-boundaries-secret-at-least-32-characters",
  database: memoryAdapter(rows),
  emailAndPassword: { enabled: true },
  socialProviders: {
    github: async () => {
      providerCalls++;
      return { clientId: "synthetic-client", clientSecret: "synthetic-provider-secret" };
    },
  },
  telemetry: mode === "default" ? undefined : { enabled, debug: mode === "debug" },
  logger: {
    level: "debug",
    log: (level, message, ...args) => {
      (level === "error" ? errors : logs).push([message, ...args]);
    },
  },
  plugins: [
    organization(),
    emailOTP({ sendVerificationOTP: async () => {} }),
    testUtils({ captureOTP: true }),
    ...(mode === "init-failure"
      ? [
          {
            id: "reject-init",
            init() {
              throw new Error("synthetic initialization rejection");
            },
          },
        ]
      : []),
  ],
});

try {
  let ctx;
  try {
    ctx = await auth.$context;
  } catch (error) {
    if (mode !== "init-failure") {
      throw error;
    }

    const deadline = Date.now() + 2000;

    while (events.length < 1 && Date.now() < deadline) {
      await new Promise((resolve) => setTimeout(resolve, 5));
    }

    console.log(JSON.stringify({ mode, events, providerCalls, initError: error.message }));
    process.exitCode = 0;
  }
  if (ctx) {
    await ctx.publishTelemetry({ type: "application-ready", payload: { ready: true } });

    // Initialization's track is deliberately unawaited upstream. Wait for its real
    // local HTTP receipt rather than assuming $context means delivery completed.
    if (["enabled", "environment", "failure"].includes(mode)) {
      const deadline = Date.now() + 2000;
      while (events.length < 2 && Date.now() < deadline) {
        await new Promise((resolve) => setTimeout(resolve, 5));
      }
      if (events.length < 2) {
        throw new Error("Actual initialization telemetry did not reach local capture");
      }
    }

    const helpers = ctx.test;
    const draft = helpers.createUser({ email: "helper@example.com", name: "Helper" });
    const factoryWrites = (rows.user ?? []).length;
    const user = await helpers.saveUser(draft);
    const missingLogin = { before: structuredClone(rows) };

    try {
      await helpers.login({ userId: "nonexistent-user" });
    } catch (error) {
      missingLogin.error = error.message;
    }

    missingLogin.after = structuredClone(rows);
    const login = await helpers.login({ userId: user.id });
    const read = await auth.api.getSession({ headers: login.headers });
    await helpers.getAuthHeaders({ userId: user.id });
    await helpers.getCookies({ userId: user.id });
    const sessionRows = structuredClone(rows.session);
    const org = await helpers.saveOrganization(
      helpers.createOrganization({ name: "Helper Org", slug: "helper-org" }),
    );
    const member = await helpers.addMember({ userId: user.id, organizationId: org.id });
    await auth.api.sendVerificationOTP({ body: { email: user.email, type: "sign-in" } });
    const capturedOTP = helpers.getOTP(user.email);
    process.env.BETTER_AUTH_TELEMETRY_ENDPOINT = "";
    const second = betterAuth({
      baseURL: "http://isolated.example.com",
      secret: "second-boundaries-secret-at-least-32-characters",
      database: memoryAdapter({}),
      plugins: [testUtils({ captureOTP: true })],
    });
    const isolatedOTP = (await second.$context).test.getOTP(user.email);
    helpers.clearOTPs();
    await helpers.deleteOrganization(org.id);
    await helpers.deleteUser(user.id);
    const role = createAccessControl({ document: ["read", "write"] }).newRole({
      document: ["read"],
    });
    const permissions = [
      role.authorize({ document: ["read"] }),
      role.authorize({ document: ["write"] }),
      role.authorize({ missing: ["read"] }),
      role.authorize({ document: [] }),
      role.authorize({ document: { actions: ["write", "read"], connector: "OR" } }),
      role.authorize({ missing: ["read"], document: ["read"] }, "OR"),
    ];
    console.log(
      JSON.stringify({
        mode,
        events,
        errors,
        logs,
        providerCalls,
        helpers: {
          factoryWrites,
          user,
          missingLogin,
          login,
          read,
          sessionRows,
          org,
          member,
          capturedOTP,
          isolatedOTP: isolatedOTP ?? null,
          clearedOTP: helpers.getOTP(user.email) ?? null,
          rows,
          permissions,
        },
      }),
    );
  }
} finally {
  await new Promise((resolve) => server.close(resolve));
}
