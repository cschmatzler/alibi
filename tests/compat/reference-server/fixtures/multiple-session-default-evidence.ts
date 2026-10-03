/** Bounded public-handler evidence for the noDB OAuth-state configuration. */
import { betterAuth } from "better-auth";

const origin = "http://localhost:43132";
const secret = "oauth-state-fixture-secret-at-least-32-characters";
const observations = [];
for (const strategy of [undefined, "cookie", "database"] as const) {
  const auth = betterAuth({
    secret,
    baseURL: origin,
    emailAndPassword: { enabled: true },
    account: strategy ? { storeStateStrategy: strategy } : undefined,
    socialProviders: { google: { clientId: "local-client", clientSecret: "local-secret" } },
  });
  const call = async (path: string, cookie = "", body?: unknown) => {
    const response = await auth.handler(
      new Request(`${origin}/api/auth${path}`, {
        method: body ? "POST" : "GET",
        headers: { origin, cookie, "content-type": "application/json" },
        body: body ? JSON.stringify(body) : undefined,
      }),
    );
    return {
      status: response.status,
      body: await response.text(),
      cookies: response.headers.getSetCookie(),
      location: response.headers.get("location"),
    };
  };
  const issued = await call("/sign-in/social", "", {
    provider: "google",
    callbackURL: "/completed",
    disableRedirect: true,
    errorCallbackURL: "/saved-error?flow=original",
  });
  if (issued.status !== 200) throw new Error(JSON.stringify(issued));
  const state = new URL(JSON.parse(issued.body).url).searchParams.get("state")!;
  const cookie = issued.cookies[0]!.split(";")[0]!;
  const context = await auth.$context;
  const before = await context.internalAdapter.findVerificationValue(state);
  if (Boolean(before) !== (strategy === "database")) {
    throw new Error("wrong physical OAuth state mode");
  }
  const callback = await call(`/callback/google?state=${state}`, cookie);
  if (callback.location !== "/saved-error?flow=original&error=no_code") {
    throw new Error(JSON.stringify(callback));
  }
  const after = await context.internalAdapter.findVerificationValue(state);
  if (after !== null) throw new Error("state not consumed");
  const signup = await call("/sign-up/email", "", {
    email: `${strategy ?? "automatic"}@fixture.test`,
    password: "password123",
    name: "Configuration owner",
  });
  if (signup.status !== 200) throw new Error(JSON.stringify(signup));
  const logout = await call(
    "/sign-out",
    signup.cookies.map((value) => value.split(";")[0]).join("; "),
    {},
  );
  const expiresState = logout.cookies.some((value) => value.startsWith("better-auth.oauth_state="));
  if (expiresState !== (strategy !== "database")) throw new Error("wrong logout cleanup mode");
  observations.push({
    configured: strategy ?? "automatic",
    resolved: context.oauthConfig.storeStateStrategy,
    issued,
    before,
    callback,
    after,
    signup,
    logout,
  });
}
console.log(JSON.stringify({ version: "1.7.6", observations }, null, 2));
