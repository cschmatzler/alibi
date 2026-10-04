/** Published BetterAuth 1.7.6, without a database or patched package modules. */
import assert from "node:assert/strict";

import { betterAuth } from "better-auth";
import { deviceAuthorization } from "better-auth/plugins";
const origin = "http://localhost:43176";
const options = {
  secret: "native-device-172-secret-at-least-32-characters",
  baseURL: origin,
  emailAndPassword: { enabled: true },
  plugins: [deviceAuthorization({ interval: "0s" })],
};
const auth = betterAuth(options);
const { adapter, internalAdapter } = await auth.$context;
const trace: unknown[] = [];
const effects: unknown[] = [];
async function call(path: string, input?: unknown, cookie = "", code?: string, instance = auth) {
  const response = await instance.handler(
    new Request(
      `${origin}/api/auth${path}${code ? "?user_code=" + encodeURIComponent(code) : ""}`,
      {
        method: input ? "POST" : "GET",
        headers: { origin, "content-type": "application/json", cookie },
        body: input ? JSON.stringify(input) : undefined,
      },
    ),
  );
  const raw = await response.text();
  trace.push({ path, status: response.status, body: raw });
  return { response, body: raw ? JSON.parse(raw) : null };
}
const row = (code: string) =>
  adapter.findOne<any>({ model: "deviceCode", where: [{ field: "deviceCode", value: code }] });
const token = (code: string, client = "console") => ({
  grant_type: "urn:ietf:params:oauth:grant-type:device_code",
  device_code: code,
  client_id: client,
});
const cookies: string[] = [];
for (const name of ["owner", "other"]) {
  const result = await call("/sign-up/email", {
    email: `${name}@example.com`,
    name,
    password: "Password123!",
  });
  assert.equal(result.response.status, 200);
  cookies.push(
    result.response.headers
      .getSetCookie()
      .map((v) => v.split(";")[0])
      .join("; "),
  );
}
for (const decision of ["approve", "deny"]) {
  const issued = await call("/device/code", { client_id: "console", scope: "profile raw" });
  assert.equal(issued.response.status, 200);
  const { device_code: device, user_code: user } = issued.body;
  const initial = await row(device);
  assert.equal(initial.scope, "profile raw");
  assert.equal(initial.clientId, "console");
  assert.ok(!initial.userId);
  assert.equal((await call("/device/token", token(device, "other"))).body.error, "invalid_grant");
  assert.ok(!(await row(device)).lastPolledAt);
  assert.equal((await call("/device/token", token(device))).body.error, "authorization_pending");
  assert.ok(!(await call("/device", undefined, "", user)).body.scope);
  assert.equal(
    (await call("/device/approve", { userCode: user }, cookies[0])).body.error,
    "invalid_request",
  );
  assert.equal((await call("/device", undefined, cookies[0], user)).body.scope, "profile raw");
  const owner = (await row(device)).userId;
  assert.ok(!(await call("/device", undefined, cookies[1], user)).body.scope);
  assert.equal(
    (await call(`/device/${decision}`, { userCode: user }, cookies[1])).response.status,
    403,
  );
  assert.equal((await row(device)).userId, owner);
  assert.equal(
    (await call(`/device/${decision}`, { userCode: user }, cookies[0])).response.status,
    200,
  );
  assert.equal(
    (await call("/device/deny", { userCode: user }, cookies[0])).body.error,
    "invalid_request",
  );
  const redeemed = await call("/device/token", token(device));
  if (decision === "approve") {
    assert.equal(redeemed.response.status, 200);
    assert.equal(redeemed.body.scope, "profile raw");
    const session = await internalAdapter.findSession(redeemed.body.access_token);
    assert.equal(session?.session.userId, owner);
  } else assert.equal(redeemed.body.error, "access_denied");
  assert.equal(await row(device), null);
  assert.equal((await call("/device/token", token(device))).body.error, "invalid_grant");
  effects.push({ decision, consumed: await row(device) });
}
await adapter.create({
  model: "deviceCode",
  data: {
    deviceCode: "expired-device",
    userCode: "EXPIRED",
    userId: null,
    expiresAt: new Date(Date.now() - 1000),
    status: "pending",
    lastPolledAt: null,
    pollingInterval: 5000,
    clientId: "console",
    scope: null,
  },
});
assert.equal((await call("/device", undefined, cookies[0], "EXPIRED")).body.error, "expired_token");
assert.equal((await call("/device/token", token("expired-device"))).body.error, "expired_token");
assert.equal(await row("expired-device"), null);
await Bun.write("evidence/source-workflow.json", JSON.stringify(trace, null, 2));
const retained = await call("/device/code", { client_id: "restart" });
const restarted = betterAuth(options);
assert.equal(
  (
    await call(
      "/device/token",
      token(retained.body.device_code, "restart"),
      "",
      undefined,
      restarted,
    )
  ).body.error,
  "invalid_grant",
);
assert.ok(await row(retained.body.device_code));
const old = await row(retained.body.device_code);
assert.equal(
  (await call("/device", undefined, cookies[0], old.userCode, restarted)).body.error,
  "invalid_request",
);
const fresh = (await restarted.$context).adapter;
const missingUpdate = await fresh.update({
  model: "deviceCode",
  where: [{ field: "id", value: old.id }],
  update: { status: "approved", userId: old.userId },
});
const missingClaim = await fresh.updateMany({
  model: "deviceCode",
  where: [
    { field: "id", value: old.id },
    { field: "status", value: "pending" },
    { field: "userId", value: null },
  ],
  update: { userId: "absent-owner" },
});
const missingDecision = await fresh.updateMany({
  model: "deviceCode",
  where: [
    { field: "id", value: old.id },
    { field: "status", value: "pending" },
  ],
  update: { status: "approved" },
});
const missingConsume = await fresh.consumeOne({
  model: "deviceCode",
  where: [
    { field: "id", value: old.id },
    { field: "status", value: "approved" },
  ],
});
assert.equal(missingUpdate, null);
assert.equal(missingClaim, 0);
assert.equal(missingDecision, 0);
assert.equal(missingConsume, null);
assert.equal(
  await fresh.findOne({
    model: "deviceCode",
    where: [{ field: "deviceCode", value: old.deviceCode }],
  }),
  null,
);
effects.push({ missingUpdate, missingClaim, missingDecision, missingConsume, freshRecord: null });
await Bun.write("evidence/source-restart-workflow.json", JSON.stringify(trace.slice(28), null, 2));

effects.push({ restartLost: true, originalRetained: true });
await Bun.write("evidence/source-record-effects.json", JSON.stringify(effects, null, 2));
console.log("Published 1.7.6 device workflow, consumption, expiry and restart loss passed");
