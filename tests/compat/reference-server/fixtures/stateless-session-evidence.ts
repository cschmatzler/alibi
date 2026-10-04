/** Focused pinned 1.7.6 HTTP evidence; private controls stay inside this fixture. */
import { betterAuth } from "better-auth";
import { createAuthMiddleware, setShouldSkipSessionRefresh } from "better-auth/api";
import { symmetricDecodeJWT, symmetricEncodeJWT } from "better-auth/crypto";
const secret = "stateless-172-secret-minimum-32-characters";
const origin = "http://localhost:43172";
const auth = betterAuth({
  secret,
  baseURL: origin,
  emailAndPassword: { enabled: true },
  session: {
    disableSessionRefresh: true,
    deferSessionRefresh: true,
    cookieCache: { refreshCache: { updateAge: 700000 } },
  },
  hooks: {
    before: createAuthMiddleware(async (ctx) => {
      if (ctx.headers?.get("x-fixture-skip-refresh") === "1") {
        await setShouldSkipSessionRefresh(true);
      }
    }),
  },
});
let cookie = "";
const trace: unknown[] = [];
async function call(path: string, body?: unknown, skip = false) {
  const response = await auth.handler(
    new Request(`${origin}/api/auth${path}`, {
      method: body ? "POST" : "GET",
      headers: {
        origin,
        "content-type": "application/json",
        cookie,
        ...(skip ? { "x-fixture-skip-refresh": "1" } : {}),
      },
      body: body ? JSON.stringify(body) : undefined,
    }),
  );
  const raw = await response.text();
  trace.push({
    path,
    skip,
    status: response.status,
    body: raw,
    cookies: response.headers.getSetCookie(),
  });
  return { response, body: JSON.parse(raw) };
}
const signup = await call("/sign-up/email", {
  email: "native172@fixture.test",
  password: "Password123!",
  name: "Stateless",
});
cookie = signup.response.headers
  .getSetCookie()
  .map((value) => value.split(";")[0])
  .join("; ");
await call("/get-session?disableRefresh=true");
await call("/get-session?disableCookieCache=true");
await call("/get-session", undefined, true);
await call("/sign-out", {});
await call("/get-session");
await call("/get-session?disableCookieCache=true");
console.log(JSON.stringify({ version: "1.7.6", trace }, null, 2));

const provisioned = betterAuth({
  secret,
  baseURL: origin,
  emailAndPassword: { enabled: true },
  user: { additionalFields: { tier: { type: "string", defaultValue: "starter" } } },
  session: {
    deferSessionRefresh: true,
    additionalFields: {
      label: { type: "string", defaultValue: "browser", input: false },
      private: { type: "string", defaultValue: "private-value", input: false, returned: false },
    },
  },
});
const provisionedTrace: unknown[] = [];
let provisionedCookie = "";
async function provisionedCall(path: string, body?: unknown) {
  const response = await provisioned.handler(
    new Request(`${origin}/api/auth${path}`, {
      method: body ? "POST" : "GET",
      headers: { origin, "content-type": "application/json", cookie: provisionedCookie },
      body: body ? JSON.stringify(body) : undefined,
    }),
  );
  const raw = await response.text();
  provisionedTrace.push({
    path,
    status: response.status,
    body: raw,
    cookies: response.headers.getSetCookie(),
  });
  return { response, body: JSON.parse(raw) };
}
const provisionedSignup = await provisionedCall("/sign-up/email", {
  email: "no-db172@fixture.test",
  password: "Password123!",
  name: "No database",
});
provisionedCookie = provisionedSignup.response.headers
  .getSetCookie()
  .map((value) => value.split(";")[0])
  .join("; ");
await provisionedCall("/get-session");
const originalCookie = provisionedCookie;
const cacheValue = provisionedCookie
  .split("; ")
  .find((value) => value.startsWith("better-auth.session_data="))!
  .split("=")[1];
const claims = await symmetricDecodeJWT(cacheValue, secret, "better-auth-session");
const shortCache = await symmetricEncodeJWT(claims!, secret, "better-auth-session", 30);
provisionedCookie = provisionedCookie.replace(cacheValue, shortCache);
await provisionedCall("/get-session");
provisionedCookie = originalCookie;
const context = await provisioned.$context;
await context.internalAdapter.updateSession(provisionedSignup.body.token, {
  expiresAt: new Date(Date.now() + 3600000),
});
await provisionedCall("/get-session?disableCookieCache=true");
await provisionedCall("/get-session?disableCookieCache=true", {});
const secondLogin = await provisionedCall("/sign-in/email", {
  email: "no-db172@fixture.test",
  password: "Password123!",
});
await provisionedCall("/list-sessions");
await provisionedCall("/revoke-other-sessions", {});
provisionedCookie = secondLogin.response.headers
  .getSetCookie()
  .map((value) => value.split(";")[0])
  .join("; ");
await provisionedCall("/get-session");
await provisionedCall("/get-session?disableCookieCache=true");
provisionedCookie = originalCookie;
await provisionedCall("/revoke-sessions", {});
console.log(
  JSON.stringify(
    {
      version: "1.7.6",
      profile: "additional-fields-and-deferred-renewal",
      trace: provisionedTrace,
    },
    null,
    2,
  ),
);
