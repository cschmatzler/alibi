import { expect, test } from "bun:test";
import { createHash, createHmac } from "node:crypto";

import { compareValues, type ComparisonContext } from "../support/compare";
import { authPath, secret, captureSessionIssuer } from "./support/server-session-issuer";

test("logical credential sign-in needs actual owner, issuer, signature, clock and browser read", async () => {
  const left = await captureSessionIssuer("signInEmail");
  const right = await captureSessionIssuer("signInEmail");
  const context: ComparisonContext = {
    leftBaseURL: left.baseURL,
    rightBaseURL: right.baseURL,
    leftStartedAt: left.startedAt,
    rightStartedAt: right.startedAt,
    leftFinishedAt: left.finishedAt,
    rightFinishedAt: right.finishedAt,
    leftRequestWindows: left.windows,
    rightRequestWindows: right.windows,
    sessionCookieSecret: secret,
    compactSessionCacheSecret: secret,
    sessionCookieSecretsByAuthPath: { [authPath]: secret },
  };
  expect(compareValues(left.value, right.value, context)).toEqual([]);
  for (const mutate of [
    (windows: typeof right.windows) => {
      delete windows[0]!.issuedSessionCookie;
    },
    (windows: typeof right.windows) => {
      const receipt = windows[1]!.logicalEndpoint!;
      const response = receipt.response as any;
      response.result.value.response.user.id = "foreign-owner";
      receipt.digest = createHash("sha256").update(JSON.stringify(response)).digest("hex");
    },
    (windows: typeof right.windows) => {
      const receipt = windows[1]!.logicalEndpoint!;
      const response = receipt.response as any;
      const token = "unissued-token";
      const signature = createHmac("sha256", secret).update(token).digest("base64");
      response.result.value.response.token = token;
      response.result.value.headers["set-cookie"] =
        `better-auth.session_token=${encodeURIComponent(`${token}.${signature}`)}; Path=/; HttpOnly`;
      receipt.digest = createHash("sha256").update(JSON.stringify(response)).digest("hex");
    },
    (windows: typeof right.windows) => {
      delete windows[1]!.logicalEndpoint;
    },
    (windows: typeof right.windows) => {
      windows[1]!.logicalEndpoint!.digest = "altered";
    },
    (windows: typeof right.windows) => {
      (windows[1]!.logicalEndpoint!.input as any).body.email = "foreign@fixture.test";
    },
    (windows: typeof right.windows) => {
      (windows[1]!.logicalEndpoint!.input as any).operation = "changePassword";
    },
    (windows: typeof right.windows) => {
      windows[1]!.finishedAt = windows[1]!.startedAt - 1000;
    },
    (windows: typeof right.windows) => {
      delete windows[2]!.sessionCookie;
    },
  ]) {
    const windows = structuredClone(right.windows);
    mutate(windows);
    expect(
      compareValues(left.value, right.value, { ...context, rightRequestWindows: windows }).some(
        (difference) => difference.reason.includes("corresponding observed issuance"),
      ),
    ).toBe(true);
  }
  const damaged = structuredClone(right.value) as any;
  damaged.observation.output.result.value.headers["set-cookie"] =
    "better-auth.session_token=forged; Path=/; HttpOnly";
  expect(compareValues(left.value, damaged, context)).not.toEqual([]);
});
