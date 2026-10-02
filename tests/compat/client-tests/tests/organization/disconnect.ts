/** Real socket transport. The server abort/drop observer acknowledges closure. */

import { expect } from "bun:test";
import { connect } from "node:net";
import type { FixtureProfile } from "../../support/profiles";
import type { ScenarioContext } from "../../support/scenario";
export async function disconnectedRequest(
  ctx: ScenarioContext,
  actor: string,
  profile: FixtureProfile,
  email: string,
  path: string,
  body: unknown,
  marker: string,
  beforeSend?: () => Promise<void>,
) {
  const reset = await ctx.rawRequest({
    path: "/__test/organization-transport-reset",
    method: "POST",
  });
  expect(reset.status).toBe(200);
  const signin = await ctx
    .actor(actor, profile)
    .fetch(`/__test/profiles/${profile}/api/auth/sign-in/email`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email, password: "password123" }),
    });
  expect(signin.status).toBe(200);
  const signinBody: unknown = await signin.json();
  const cookie = signin.headers
    .getSetCookie()
    .map((raw) => raw.split(";")[0])
    .join("; ");
  expect(cookie).toContain("session_token=");
  if (beforeSend) await beforeSend();
  const origin = new URL(ctx.baseURL);
  const wirePath = `/__test/profiles/${profile}/api/auth${path}`;
  const payload = JSON.stringify(body);
  const socket = connect(Number(origin.port), origin.hostname);
  await new Promise<void>((resolve, reject) => {
    socket.once("connect", resolve);
    socket.once("error", reject);
  });
  let responseBytes = 0;
  socket.on("data", (bytes) => {
    responseBytes += bytes.length;
  });
  const closed = new Promise<void>((resolve) => socket.once("close", () => resolve()));
  socket.write(
    `POST ${wirePath} HTTP/1.1\r\nHost: ${origin.host}\r\nOrigin: ${origin.origin}\r\nCookie: ${cookie}\r\nX-Continuation-Marker: ${marker}\r\nContent-Type: application/json\r\nContent-Length: ${Buffer.byteLength(payload)}\r\n\r\n${payload}`,
  );
  return {
    signin: { status: signin.status, body: signinBody },
    request: {
      method: "POST",
      path: wirePath,
      body,
      marker,
      signedCookieSupplied: cookie.includes("session_token="),
    },
    dispose() {
      socket.destroy();
    },
    async close() {
      socket.destroy();
      await closed;
      expect(responseBytes).toBe(0);
      const receipt = await ctx.rawRequest({
        path: `/__test/organization-transport-state?marker=${encodeURIComponent(marker)}`,
      });
      expect(receipt.status).toBe(200);
      expect(receipt.body).toEqual({ marker, aborted: true });
      return { clientClosed: socket.destroyed, responseBytes, receipt };
    },
  };
}
