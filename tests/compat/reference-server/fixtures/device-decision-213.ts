/** Controlled custom-adapter delay around unmodified published 1.7.6 handlers. */
import assert from "node:assert/strict";

import { memoryAdapter } from "@better-auth/memory-adapter";
import { betterAuth } from "better-auth";
import { deviceAuthorization } from "better-auth/plugins";

const origin = "http://localhost:43213";
const observations: unknown[] = [];
for (const last of ["approved", "denied"]) {
  const physical: Record<string, any[]> = {
    user: [],
    account: [],
    session: [],
    verification: [],
    deviceCode: [],
  };
  const gates = new Map<string, () => void>();
  let ready!: () => void;
  const bothReady = new Promise<void>((resolve) => {
    ready = resolve;
  });
  let enabled = false;
  const writes: unknown[] = [];
  const auth = betterAuth({
    secret: "device-decision-213-secret-at-least-32-characters",
    baseURL: origin,
    emailAndPassword: { enabled: true },
    database: (options) => {
      const adapter = memoryAdapter(physical)(options);
      return {
        ...adapter,
        update: async (input) => {
          if (enabled && input.model === "deviceCode") {
            writes.push({ phase: "validated", input });
            await new Promise<void>((resolve) => {
              gates.set(input.update.status, resolve);
              if (gates.size === 2) ready();
            });
            const result = await adapter.update(input);
            writes.push({ phase: "written", row: structuredClone(result) });
            return result;
          }
          return adapter.update(input);
        },
      };
    },
    plugins: [deviceAuthorization({ interval: "0s" })],
  });
  const trace: unknown[] = [];
  async function call(path: string, body?: unknown, cookie = "") {
    const response = await auth.handler(
      new Request(origin + "/api/auth" + path, {
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
      headers: Object.fromEntries(response.headers),
    });
    return { response, body: JSON.parse(raw) };
  }
  const owner = await call("/sign-up/email", {
    email: "owner@example.com",
    name: "Owner",
    password: "Password123!",
  });
  const cookie = owner.response.headers
    .getSetCookie()
    .map((value) => value.split(";")[0])
    .join("; ");
  const { body: issued } = await call("/device/code", {
    client_id: "console",
    scope: "profile raw",
  });
  await call("/device?user_code=" + encodeURIComponent(issued.user_code), undefined, cookie);
  const before = structuredClone(physical);
  enabled = true;
  const approve = call("/device/approve", { userCode: issued.user_code }, cookie);
  const deny = call("/device/deny", { userCode: issued.user_code }, cookie);
  let watchdog: ReturnType<typeof setTimeout>;
  try {
    await Promise.race([
      bothReady,
      new Promise((_, reject) => {
        watchdog = setTimeout(() => reject(new Error("both decisions did not reach update")), 3000);
      }),
    ]);
  } finally {
    clearTimeout(watchdog!);
  }
  assert.equal(physical.deviceCode[0].status, "pending");
  const first = last === "approved" ? "denied" : "approved";
  gates.get(first)!();
  assert.equal((await (first === "approved" ? approve : deny)).response.status, 200);
  assert.equal(physical.deviceCode[0].status, first);
  gates.get(last)!();
  assert.equal((await (last === "approved" ? approve : deny)).response.status, 200);
  assert.equal(physical.deviceCode[0].status, last);
  assert.equal(physical.deviceCode[0].userId, owner.body.user.id);
  enabled = false;
  const decided = structuredClone(physical);
  assert.equal(
    (await call("/device/approve", { userCode: issued.user_code }, cookie)).response.status,
    400,
  );
  const tokenBody = {
    grant_type: "urn:ietf:params:oauth:grant-type:device_code",
    device_code: issued.device_code,
    client_id: "console",
  };
  const redeemed = await call("/device/token", tokenBody);
  assert.equal(redeemed.response.status, last === "approved" ? 200 : 400);
  if (last === "approved") {
    assert.equal(redeemed.body.scope, "profile raw");
    assert.equal(
      physical.session.find((row) => row.token === redeemed.body.access_token)?.userId,
      owner.body.user.id,
    );
  } else assert.equal(redeemed.body.error, "access_denied");
  assert.equal(physical.deviceCode.length, 0);
  assert.equal(physical.session.length, before.session.length + (last === "approved" ? 1 : 0));
  assert.deepEqual(physical.user, before.user);
  assert.deepEqual(physical.account, before.account);
  assert.equal((await call("/device/token", tokenBody)).body.error, "invalid_grant");
  observations.push({ last, before, writes, decided, after: physical, trace });
}
await Bun.write(
  process.env.DEVICE_213_OUTPUT ?? "evidence/device-decision-213-source.json",
  JSON.stringify(observations, null, 2),
);
console.log(
  "Both controlled orders: two successes, last completed write wins; owner, consumption and session effects passed.",
);
