import assert from "node:assert/strict";
import { writeFile } from "node:fs/promises";
import { passkey } from "../reference-server/node_modules/@better-auth/passkey/dist/index.mjs";
import { createPasskeyAdapters } from "./support/passkey-adapters.mjs";

const { adapters, close } = await createPasskeyAdapters();
const cases = [];
for (const [backend, adapter] of Object.entries(adapters)) {
  for (const operation of ["registration", "authentication"]) {
    const userId = `${backend}-${operation}`;
    let count = 0;
    const events = [];
    const plugin = passkey({ rpID: "localhost", rpName: "Names", origin: "http://localhost", [operation]: {
      requireSession: false, resolveUser: async () => ({ id: userId, name: "Owner" }),
      extensions: async () => {
        events.push("extensions");
        count += 1;
        await adapter.create({ model: "passkey", forceAllowId: true, data: {
          id: `${userId}-${count}`, userId, credentialID: Buffer.from(`extension-${count}`).toString("base64url"), publicKey: "public",
          counter: 0, deviceType: "singleDevice", backedUp: false, transports: "usb",
        } });
        return {};
      },
    } });
    const context = {
      options: {}, session: operation === "authentication" ? { user: { id: userId }, session: { token: "session" } } : null,
      adapter: { ...adapter, findMany: async (...args) => { events.push("read"); return adapter.findMany(...args); } },
      internalAdapter: { createVerificationValue: async () => { events.push("publish"); } },
      createAuthCookie: () => ({ name: "challenge", attributes: {} }),
      secret: "read-order-oracle-secret-at-least-32-characters", appName: "Names",
    };
    for (let call = 1; call <= 2; call++) {
      events.length = 0;
      const endpoint = operation === "registration" ? "generatePasskeyRegistrationOptions" : "generatePasskeyAuthenticationOptions";
      const output = await plugin.endpoints[endpoint]({ context });
      assert.deepEqual(events, ["read", "extensions", "publish"]);
      const descriptors = output.excludeCredentials ?? output.allowCredentials;
      assert.equal(descriptors?.length ?? 0, call - 1);
      cases.push({ backend, operation, call, descriptors, absent: descriptors === undefined, events: [...events] });
    }
  }
}
await close();
assert.equal(cases.length, 8);
await writeFile(new URL("../../../crates/plugins/src/passkey/generation_read_order_cases.json", import.meta.url), JSON.stringify({ better_auth: "1.7.18", cases }) + "\n");
console.log(`${cases.length} actual generation callback mutation/read-order cases`);
