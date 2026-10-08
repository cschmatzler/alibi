import { expect } from "bun:test";
import { createHash } from "node:crypto";

import { authProfilePath } from "../../../support/profiles";
import { compatScenario } from "../../../support/scenario";
const cases = [
  { mode: "http", host: "exact.fixture.test", expected: "http://exact.fixture.test" },
  { mode: "https", host: "exact.fixture.test", expected: "https://exact.fixture.test" },
  {
    mode: "auto",
    host: "tenant.preview.fixture.test",
    expected: "http://tenant.preview.fixture.test",
  },
  {
    mode: "auto",
    host: "deep.tenant.preview.fixture.test",
    expected: "http://deep.tenant.preview.fixture.test",
  },
  { mode: "auto", host: "preview.fixture.test", expected: "http://fallback.fixture.test" },
  { mode: "auto", host: "evil.fixture.test", expected: "http://fallback.fixture.test" },
  { mode: "no-fallback", host: "evil.fixture.test", expected: null },
  {
    mode: "auto",
    host: "evil.fixture.test",
    forwarded: "exact.fixture.test",
    proto: "https",
    expected: "https://exact.fixture.test",
  },
  {
    mode: "http",
    host: "evil.fixture.test",
    forwarded: "exact.fixture.test",
    proto: "https",
    expected: "http://exact.fixture.test",
  },
  {
    mode: "untrusted",
    host: "exact.fixture.test",
    forwarded: "tenant.preview.fixture.test",
    proto: "https",
    expected: "http://exact.fixture.test",
  },
] as const;
for (const [index, c] of cases.entries()) {
  compatScenario(
    `dynamic baseURL case ${index} ${c.mode} selects allowed host protocol or fallback before OAuth state issuance`,
    async (ctx) => {
      const profile = `generic-token-base-${c.mode}` as const;
      const actor = ctx.actor("owner", profile);
      const state = async () =>
        (
          await ctx.rawRequest({
            path: "/__test/user-lifecycle/control",
            method: "POST",
            json: { profile: "default", action: "state" },
          })
        ).body as any;
      const before = await state();
      const headers: Record<string, string> = { host: c.host };
      if ("forwarded" in c) headers["x-forwarded-host"] = c.forwarded;
      if ("proto" in c) headers["x-forwarded-proto"] = c.proto;
      const start = await actor.client.signIn.social(
        { provider: "generic", callbackURL: "/dynamic-done", disableRedirect: true },
        { headers },
      );
      if (!c.expected) {
        expect(start.error?.status).toBe(500);
        expect(await state()).toEqual(before);
        return ctx.snapshot({ start, before });
      }
      expect(start.error).toBeNull();
      const authorization = new URL(start.data!.url!);
      expect(authorization.searchParams.get("redirect_uri")).toBe(
        c.expected + authProfilePath(profile) + "/callback/generic",
      );
      expect(authorization.searchParams.get("state")).toBeTruthy();
      expect(authorization.searchParams.get("code_challenge")).toBeTruthy();
      const after = await state();
      expect(after.verifications).toHaveLength(1);
      expect(before.verifications).toEqual([]);
      const row = after.verifications[0];
      expect(row.identifier).toBe("auth-state:" + authorization.searchParams.get("state")!);
      const payload = JSON.parse(row.value);
      expect(payload.callbackURL).toBe("/dynamic-done");
      expect(payload.oauthState).toBe(authorization.searchParams.get("state")!);
      expect(createHash("sha256").update(payload.codeVerifier).digest("base64url")).toBe(
        authorization.searchParams.get("code_challenge")!,
      );
      return ctx.snapshot({
        start,
        before,
        after: {
          ...after,
          verifications: [
            {
              ...row,
              identifier: {
                namespace: "auth-state:",
                state: row.identifier.slice("auth-state:".length),
              },
              value: {
                token: row.value,
                payload: {
                  ...payload,
                  codeVerifier: { token: payload.codeVerifier },
                  oauthState: { state: payload.oauthState },
                  expiresAt: new Date(payload.expiresAt).toISOString(),
                },
              },
            },
          ],
        },
      });
    },
    ["POST /sign-in/social"],
  );
}
