/** Focused pinned 1.7.6 HTTP evidence; private controls stay inside this fixture. */
import { betterAuth } from "better-auth";
import { createAuthMiddleware, setShouldSkipSessionRefresh } from "better-auth/api";
const secret = "stateless-172-secret-minimum-32-characters";
const origin = "http://localhost:43172";
const auth = betterAuth({
  secret, baseURL: origin, emailAndPassword: { enabled: true },
  session: { disableSessionRefresh: true, deferSessionRefresh: true,
    cookieCache: { refreshCache: { updateAge: 700000 } } },
  hooks: { before: createAuthMiddleware(async ctx => {
    if (ctx.headers?.get("x-fixture-skip-refresh") === "1") await setShouldSkipSessionRefresh(true);
  }) },
});
let cookie = "";
const trace: unknown[] = [];
async function call(path: string, body?: unknown, skip = false) {
  const response = await auth.handler(new Request(`${origin}/api/auth${path}`, {
    method: body ? "POST" : "GET",
    headers: { origin, "content-type": "application/json", cookie,
      ...(skip ? {"x-fixture-skip-refresh":"1"} : {}) },
    body: body ? JSON.stringify(body) : undefined,
  }));
  const raw = await response.text();
  trace.push({ path, skip, status: response.status, body: raw, cookies: response.headers.getSetCookie() });
  return { response, body: JSON.parse(raw) };
}
const signup = await call("/sign-up/email", { email: "native172@fixture.test", password: "Password123!", name: "Stateless" });
cookie = signup.response.headers.getSetCookie().map(value => value.split(";")[0]).join("; ");
await call("/get-session?disableRefresh=true");
await call("/get-session?disableCookieCache=true");
await call("/get-session", undefined, true);
await call("/sign-out", {});
await call("/get-session");
await call("/get-session?disableCookieCache=true");
console.log(JSON.stringify({ version:"1.7.6", trace }, null, 2));
