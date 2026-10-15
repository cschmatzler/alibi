import { createHmac } from "node:crypto";

import { Cookie } from "tough-cookie";
import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";
import { readUserState } from "../../../support/verification";
const secret = "compat-test-only-key-not-real-minimum-32chars";
function header(raws: string[]) {
  const values = new Map<string, string>();
  for (const raw of raws) {
    const cookie = Cookie.parse(raw)!;
    if (cookie.maxAge === 0) {
      values.delete(cookie.key);
    } else {
      values.set(cookie.key, cookie.value);
    }
  }
  return { cookie: [...values].map(([key, value]) => key + "=" + value).join("; ") };
}
function signed(payload: string) {
  return encodeURIComponent(
    payload + "." + createHmac("sha256", secret).update(payload).digest("base64"),
  );
}
function restoration(raws: string[], token: string, remember: boolean) {
  const receipt: Record<string, unknown> = {};
  for (const raw of raws) {
    const cookie = Cookie.parse(raw)!;
    let value = cookie.value;
    if (cookie.key.startsWith("better-auth.") && value) {
      const decoded = decodeURIComponent(value);
      const separator = decoded.lastIndexOf(".");
      value = decoded.slice(0, separator);
      expect(cookie.value).toBe(signed(value));
    }
    receipt[cookie.key] = {
      ...(cookie.key === "better-auth.session_token" ? { token: value } : { value }),
      path: cookie.path,
      domain: cookie.domain ?? null,
      httpOnly: cookie.httpOnly,
      secure: cookie.secure,
      sameSite: cookie.sameSite,
      maxAge: cookie.maxAge ?? null,
    };
  }
  const session = Cookie.parse(raws.find((raw) => raw.startsWith("better-auth.session_token="))!)!;
  expect(session.value).toBe(signed(token));
  expect((session.maxAge ?? null) === null).toBe(remember);
  const cleared = Cookie.parse(raws.find((raw) => raw.startsWith("better-auth.admin_session="))!)!;
  expect(cleared.value).toBe("");
  expect(cleared.maxAge).toBe(0);
  expect(raws).toContain("application_a=first; Path=/; HttpOnly");
  expect(raws).toContain("application_b=second; Path=/; HttpOnly");
  return receipt;
}
compatScenario(
  "server admin stopImpersonating restores only the signed owner session and its remember policy",
  async (ctx) => {
    async function signup(name: string, profile?: "admin-standard") {
      let cookie = "";
      const result = await ctx.actor(name, profile).client.signUp.email({
        email: ctx.uniqueEmail(name),
        name,
        password: "Password123!",
        fetchOptions: {
          onSuccess({ response }) {
            cookie = header(response.headers.getSetCookie()).cookie;
          },
        },
      });
      expect(result.error).toBeNull();
      return { result, headers: { cookie } };
    }
    const admin = await signup("stop-server-admin", "admin-standard");
    const target = await signup("stop-server-target");
    const foreign = await signup("stop-server-foreign");
    async function invoke(operation: string, input: Record<string, unknown>) {
      const response = await ctx
        .actor("stop-server-control")
        .fetch(ctx.baseURL + "/__test/admin/server-api", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ operation, ...input }),
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
    for (const [input, status, message] of [
      [{ body: 7 }, 400, "Headers is required"],
      [{ headers: {} }, 401, undefined],
      [{ headers: admin.headers, body: 7 }, 400, "You are not impersonating anyone"],
      [
        { headers: foreign.headers, body: { userId: admin.result.data!.user.id } },
        400,
        "You are not impersonating anyone",
      ],
    ] as const) {
      const raw = await invoke("stopImpersonating", input);
      expect(raw.status).toBe(status);
      if (message) {
        expect(raw.body.message).toBe(message);
      } else {
        expect(raw.body).toBeNull();
      }
      rejected.push(raw);
    }
    const results = [];
    for (const remember of [false, true]) {
      let originalToken = admin.result.data!.token!;
      let originalHeaders = admin.headers;
      if (remember) {
        let cookie = "";
        const login = await ctx.actor("stop-short-admin").client.signIn.email({
          email: admin.result.data!.user.email,
          password: "Password123!",
          rememberMe: false,
          fetchOptions: {
            onSuccess({ response }) {
              cookie = header(response.headers.getSetCookie()).cookie;
            },
          },
        });
        expect(login.error).toBeNull();
        originalToken = login.data!.token!;
        originalHeaders = { cookie };
      }
      const before = {
        admin: await readUserState(ctx, admin.result.data!.user.id),
        target: await readUserState(ctx, target.result.data!.user.id),
        foreign: await readUserState(ctx, foreign.result.data!.user.id),
      };
      const impersonated = await invoke("impersonateUser", {
        body: { userId: target.result.data!.user.id },
        headers: originalHeaders,
      });
      expect(impersonated.status).toBe(200);
      const active = header(impersonated.cookies);
      const onlySession = {
        cookie: active.cookie
          .split("; ")
          .filter((pair) => !pair.startsWith("better-auth.admin_session="))
          .join("; "),
      };
      const failures = [];
      for (const proof of [undefined, "invalid", signed(foreign.result.data!.token! + ":")]) {
        const headers = {
          cookie:
            onlySession.cookie +
            (proof === undefined ? "" : "; better-auth.admin_session=" + proof),
        };
        const raw = await invoke("stopImpersonating", { headers });
        expect(raw.status).toBe(500);
        expect(raw.body.message).toBe("Failed to find admin session");
        failures.push(raw);
      }
      const during = await readUserState(ctx, target.result.data!.user.id);
      expect(during.sessions).toHaveLength(before.target.sessions.length + 1);
      const stopped = await invoke("stopImpersonating", {
        headers: active,
        body: 7,
        query: { userId: foreign.result.data!.user.id, sessionToken: foreign.result.data!.token },
      });
      expect(stopped.status).toBe(200);
      expect(stopped.body.user.id).toBe(admin.result.data!.user.id);
      expect(stopped.body.session.token).toBe(originalToken);
      expect(stopped.principal).toBe(target.result.data!.user.email);
      const cookies = restoration(stopped.cookies, originalToken, remember);
      expect(await readUserState(ctx, target.result.data!.user.id)).toEqual(before.target);
      expect(await readUserState(ctx, admin.result.data!.user.id)).toEqual(before.admin);
      expect(await readUserState(ctx, foreign.result.data!.user.id)).toEqual(before.foreign);
      const current = await ctx.rawRequest({
        path: "/api/auth/get-session",
        headers: header(stopped.cookies),
      });
      expect((current.body as { user: { id: string } }).user.id).toBe(admin.result.data!.user.id);
      const replay = await invoke("stopImpersonating", { headers: active });
      expect(replay.status).toBe(401);
      expect(replay.body).toBeNull();
      results.push({
        remember,
        before,
        impersonated: { status: impersonated.status, body: impersonated.body },
        failures,
        during,
        stopped: {
          status: stopped.status,
          body: stopped.body,
          principal: stopped.principal,
          cookies,
        },
        current,
        replay,
      });
    }
    return ctx.snapshot({
      admin: admin.result,
      target: target.result,
      foreign: foreign.result,
      rejected,
      results,
    });
  },
);
