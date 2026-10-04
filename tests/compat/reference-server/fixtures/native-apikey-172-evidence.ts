/** Published 1.7.6 handlers and genuine native memory rows. */
import { apiKey } from "@better-auth/api-key";
import { betterAuth } from "better-auth";
const origin = "http://localhost:43175";
const options = {
  secret: "native-apikey-172-secret-at-least-32-characters",
  baseURL: origin,
  emailAndPassword: { enabled: true },
  plugins: [
    apiKey([
      { configId: "default", enableMetadata: true },
      { configId: "billing", enableMetadata: true },
    ]),
  ],
};
const auth = betterAuth(options);
const context = await auth.$context;
const trace: unknown[] = [];
async function call(path: string, body?: unknown, cookie = "", query = "") {
  const response = await auth.handler(
    new Request(`${origin}/api/auth${path}${query}`, {
      method: body ? "POST" : "GET",
      headers: { origin, "content-type": "application/json", cookie },
      body: body ? JSON.stringify(body) : undefined,
    }),
  );
  const raw = await response.text();
  trace.push({
    path,
    status: response.status,
    body: raw,
    cookies: response.headers.getSetCookie(),
  });
  return { response, body: raw ? JSON.parse(raw) : null };
}
const cookies = (response: Response) =>
  response.headers
    .getSetCookie()
    .map((value) => value.split(";")[0])
    .join("; ");
const signup = await call("/sign-up/email", {
  name: "Owner",
  email: "apikey172@fixture.test",
  password: "Password123!",
});
const owner = signup.body.user.id;
const cookie = cookies(signup.response);
const other = await call("/sign-up/email", {
  name: "Other",
  email: "foreignkey172@fixture.test",
  password: "Password456!",
});
const foreignCookie = cookies(other.response);
const created = await call(
  "/api-key/create",
  { name: "Original", metadata: { purpose: "native" } },
  cookie,
);
const id = created.body.id;
const find = (id: string) =>
  context.adapter.findOne({ model: "apikey", where: [{ field: "id", value: id }] });
const before = structuredClone(await find(id));
const billing = await call("/api-key/create", { name: "Billing", configId: "billing" }, cookie);
const foreign = await call("/api-key/create", { name: "Foreign" }, foreignCookie);
const foreignBefore = structuredClone(await find(foreign.body.id));
await call("/api-key/get", undefined, foreignCookie, `?id=${id}`);
await call("/api-key/update", { keyId: id, name: "Stolen" }, foreignCookie);
await call("/api-key/delete", { keyId: id }, foreignCookie);
const unchanged = structuredClone(await find(id));
await call("/api-key/get", undefined, cookie, `?id=${id}&configId=billing`);
await call("/api-key/list", undefined, cookie, "?configId=billing&limit=1&offset=0");
await call("/api-key/update", { keyId: id, name: "Renamed" }, cookie);
const renamed = structuredClone(await find(id));
const limited = await auth.api.createApiKey({
  body: {
    userId: owner,
    name: "Quota",
    remaining: 3,
    rateLimitTimeWindow: 86400000,
    rateLimitMax: 1,
    permissions: { files: ["read"] },
  },
});
const permission = await auth.api.verifyApiKey({
  body: { key: limited.key, permissions: { files: ["write"] } },
});
const permissionRow = structuredClone(await find(limited.id));
for (let i = 0; i < 2; i++) {
  trace.push({
    operation: "verifyApiKey",
    body: await auth.api.verifyApiKey({ body: { key: limited.key } }),
  });
}
const limitedRow = structuredClone(await find(limited.id));
await context.adapter.update({
  model: "apikey",
  where: [{ field: "id", value: limited.id }],
  update: { expiresAt: new Date(Date.now() - 60000) },
});
const deletedExpired = await context.adapter.deleteMany({
  model: "apikey",
  where: [
    { field: "expiresAt", operator: "lt", value: new Date() },
    { field: "expiresAt", operator: "ne", value: null },
  ],
});
const foreignAfter = structuredClone(await find(foreign.body.id));
for (const [keyId, ownerCookie] of [
  [id, cookie],
  [billing.body.id, cookie],
  [foreign.body.id, foreignCookie],
]) {
  await call(
    "/api-key/delete",
    { keyId, configId: keyId === billing.body.id ? "billing" : "default" },
    ownerCookie,
  );
}
const retained = await auth.api.createApiKey({
  body: {
    userId: owner,
    name: "Retained",
    remaining: 0,
    refillAmount: 3,
    refillInterval: 60000,
    rateLimitEnabled: false,
  },
});
await context.adapter.update({
  model: "apikey",
  where: [{ field: "id", value: retained.id }],
  update: { lastRefillAt: new Date(0) },
});
const concurrent = await Promise.all(
  Array.from({ length: 8 }, () => auth.api.verifyApiKey({ body: { key: retained.key } })),
);
const afterConcurrent = structuredClone(await find(retained.id));
await context.adapter.update({
  model: "apikey",
  where: [{ field: "id", value: retained.id }],
  update: { requestCount: null, lastRequest: new Date() },
});
const nullCounter = await context.adapter.incrementOne({
  model: "apikey",
  where: [
    { field: "id", value: retained.id },
    { field: "requestCount", operator: "lt", value: 10 },
  ],
  increment: { requestCount: 1 },
});
const restarted = betterAuth(options);
const restartContext = await restarted.$context;
const lost = await restartContext.adapter.findOne({
  model: "apikey",
  where: [{ field: "id", value: retained.id }],
});
const restartVerify = await restarted.api.verifyApiKey({ body: { key: retained.key } });
console.log(
  JSON.stringify(
    {
      trace,
      before,
      unchanged,
      renamed,
      foreignBefore,
      foreignAfter,
      permission,
      permissionRow,
      limitedRow,
      deletedExpired,
      retained,
      concurrent,
      afterConcurrent,
      nullCounter,
      lost,
      restartVerify,
    },
    null,
    2,
  ),
);
