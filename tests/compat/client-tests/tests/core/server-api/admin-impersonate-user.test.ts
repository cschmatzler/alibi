import { expect } from "bun:test";
import { createHmac } from "node:crypto";

import { Cookie } from "tough-cookie";

import { compatScenario } from "../../../support/scenario";
import { readUserState } from "../../../support/verification";

const secret = "compat-test-only-key-not-real-minimum-32chars";
function emittedCookies(raws: string[], adminToken: string, newToken: string) {
  const live = new Map<string, Cookie>();
  const receipt: Record<string, unknown> = {};
  const verified = new Map<string, string>();
  for (const raw of raws) {
    const cookie = Cookie.parse(raw)!;
    expect(cookie).toBeDefined();
    let payload = cookie.value;
    if (cookie.key.startsWith("better-auth.") && cookie.value && cookie.maxAge !== 0) {
      const signed = decodeURIComponent(cookie.value);
      const separator = signed.lastIndexOf(".");
      expect(separator).toBeGreaterThan(0);
      payload = signed.slice(0, separator);
      const signature = createHmac("sha256", secret).update(payload).digest("base64");
      expect(signed.slice(separator + 1)).toBe(signature);
      expect(cookie.value).toBe(encodeURIComponent(payload + "." + signature));
    }
    verified.set(cookie.key, payload);
    receipt[cookie.key] = {
      ...(cookie.key === "better-auth.admin_session" && cookie.value
        ? { token: payload.split(":")[0], rememberFlag: payload.split(":")[1] }
        : cookie.key === "better-auth.session_token" && cookie.value
          ? { token: payload }
          : { payload }),
      path: cookie.path,
      httpOnly: cookie.httpOnly,
      secure: cookie.secure,
      sameSite: cookie.sameSite,
      maxAge: cookie.maxAge ?? null,
    };
    if (cookie.maxAge === 0) {
      live.delete(cookie.key);
    } else {
      live.set(cookie.key, cookie);
    }
  }
  expect(live.get("better-auth.admin_session")).toBeDefined();
  expect(verified.get("better-auth.admin_session")).toBe(adminToken + ":");
  expect(verified.get("better-auth.session_token")).toBe(newToken);
  expect(verified.get("better-auth.dont_remember")).toBe("true");
  expect(live.has("application_a")).toBe(true);
  expect(live.has("application_b")).toBe(true);
  return {
    receipt,
    headers: {
      cookie: [...live.values()].map((cookie) => cookie.key + "=" + cookie.value).join("; "),
    },
  };
}
compatScenario(
  "server admin impersonateUser publishes signed usable sessions and preserves original authority",
  async (ctx) => {
    async function signup(name: string, profile?: "admin-standard") {
      let cookie = "";
      const result = await ctx.actor(name, profile).client.signUp.email({
        email: ctx.uniqueEmail(name),
        name,
        password: "Password123!",
        fetchOptions: {
          onSuccess({ response }) {
            cookie = response.headers
              .getSetCookie()
              .map((raw) => raw.split(";")[0])
              .join("; ");
          },
        },
      });
      expect(result.error).toBeNull();
      return { result, headers: { cookie } };
    }
    const admin = await signup("impersonate-server-admin", "admin-standard");
    const target = await signup("impersonate-server-target");
    const foreign = await signup("impersonate-server-foreign");
    const id = target.result.data!.user.id;
    const before = {
      admin: await readUserState(ctx, admin.result.data!.user.id),
      target: await readUserState(ctx, id),
      foreign: await readUserState(ctx, foreign.result.data!.user.id),
    };
    async function invoke(input: Record<string, unknown>) {
      const response = await ctx
        .actor("impersonate-server-control")
        .fetch(ctx.baseURL + "/__test/admin/server-api", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ operation: "impersonateUser", ...input }),
        });
      const text = await response.text();
      return {
        status: response.status,
        body: text ? JSON.parse(text) : null,
        principal: response.headers.get("x-admin-principal"),
        cookies: response.headers.getSetCookie(),
      };
    }
    const rejected = [];
    for (const [input, status, code] of [
      [{}, 400, "VALIDATION_ERROR"],
      [{ body: null }, 400, "VALIDATION_ERROR"],
      [{ body: { userId: { toString: "bad" } } }, 400, "VALIDATION_ERROR"],
      [{ body: { userId: id } }, 401, undefined],
      [{ body: { userId: id }, headers: {} }, 401, undefined],
      [
        { body: { userId: id }, headers: foreign.headers },
        403,
        "YOU_ARE_NOT_ALLOWED_TO_IMPERSONATE_USERS",
      ],
      [
        { body: { userId: id }, headers: admin.headers, profile: "admin-role-manager" },
        403,
        "YOU_ARE_NOT_ALLOWED_TO_IMPERSONATE_USERS",
      ],
      [
        { body: { userId: admin.result.data!.user.id }, headers: admin.headers },
        403,
        "YOU_CANNOT_IMPERSONATE_ADMINS",
      ],
      [{ body: { userId: null }, headers: admin.headers }, 404, "USER_NOT_FOUND"],
      [{ body: { userId: "missing-user" }, headers: admin.headers }, 404, "USER_NOT_FOUND"],
    ] as const) {
      const raw = await invoke(input);
      expect(raw.status).toBe(status);
      if (code) {
        expect(raw.body.code).toBe(code);
      } else {
        expect(raw.body).toBeNull();
      }
      rejected.push(raw);
    }
    expect(await readUserState(ctx, id)).toEqual(before.target);
    const results = [];
    for (const [profile, duration] of [
      ["admin-standard", 3600],
      ["admin-duration-fractional", 120.75],
    ] as const) {
      const raw = await invoke({
        profile,
        body: { userId: id, impersonatedBy: foreign.result.data!.user.id },
        query: { userId: foreign.result.data!.user.id },
        headers: {
          ...admin.headers,
          "x-forwarded-for": "203.0.113.46",
          "user-agent": "logical-admin-sdk",
        },
      });
      expect(raw.status).toBe(200);
      expect(raw.body.user.id).toBe(id);
      expect(raw.body.session).toMatchObject({
        userId: id,
        impersonatedBy: admin.result.data!.user.id,
        ipAddress: "203.0.113.46",
        userAgent: "logical-admin-sdk",
      });
      expect(raw.body.session.token).not.toBe(admin.result.data!.token);
      expect(
        Math.abs(
          Date.parse(raw.body.session.expiresAt) -
            Date.parse(raw.body.session.createdAt) -
            duration * 1000,
        ),
      ).toBeLessThan(2000);
      expect(raw.principal).toBe(admin.result.data!.user.email);
      const cookies = emittedCookies(
        raw.cookies,
        admin.result.data!.token!,
        raw.body.session.token,
      );
      const during = await readUserState(ctx, id);
      expect(during.user).toEqual(before.target.user);
      expect(during.accounts).toEqual(before.target.accounts);
      expect(during.sessions).toHaveLength(before.target.sessions.length + 1);
      expect(
        during.sessions.find((session) => session.token === raw.body.session.token),
      ).toMatchObject({ id: raw.body.session.id, userId: id });
      expect(await readUserState(ctx, admin.result.data!.user.id)).toEqual(before.admin);
      expect(await readUserState(ctx, foreign.result.data!.user.id)).toEqual(before.foreign);
      const current = await ctx.rawRequest({
        path: "/api/auth/get-session",
        headers: cookies.headers,
      });
      expect((current.body as { user: { id: string }; session: { token: string } }).user.id).toBe(
        id,
      );
      expect((current.body as { session: { token: string } }).session.token).toBe(
        raw.body.session.token,
      );
      const restored = await ctx.rawRequest({
        path: "/api/auth/admin/stop-impersonating",
        method: "POST",
        json: {},
        headers: cookies.headers,
      });
      expect(restored.status).toBe(200);
      expect((restored.body as { user: { id: string }; session: { token: string } }).user.id).toBe(
        admin.result.data!.user.id,
      );
      expect((restored.body as { session: { token: string } }).session.token).toBe(
        admin.result.data!.token!,
      );
      expect(await readUserState(ctx, id)).toEqual(before.target);
      results.push({
        status: raw.status,
        body: raw.body,
        principal: raw.principal,
        cookies: cookies.receipt,
        during,
        current,
        restored,
      });
    }
    return ctx.snapshot({
      admin: admin.result,
      target: target.result,
      foreign: foreign.result,
      before,
      rejected,
      results,
    });
  },
);
