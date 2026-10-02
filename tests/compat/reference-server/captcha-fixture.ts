import { betterAuth, type BetterAuthOptions } from "better-auth";
import { captcha, type CaptchaOptions } from "better-auth/plugins";
import { createAuthMiddleware } from "better-auth/api";

export const CAPTCHA_PROFILES = [
  "captcha-turnstile", "captcha-turnstile-configured", "captcha-turnstile-custom", "captcha-turnstile-wildcard", "captcha-turnstile-globstar", "captcha-turnstile-empty", "captcha-turnstile-disabled", "captcha-turnstile-no-secret", "captcha-turnstile-ip-disabled", "captcha-turnstile-ip-custom",
  "captcha-google", "captcha-google-configured", "captcha-google-zero", "captcha-hcaptcha", "captcha-hcaptcha-sitekey", "captcha-captchafox", "captcha-captchafox-sitekey",
  "captcha-botid", "captcha-botid-denied", "captcha-botid-custom", "captcha-botid-throw", "captcha-botid-validator-throw", "captcha-botid-timeout",
] as const;

/** Actual configured middleware, provider HTTP responses and application callbacks. */
export function createCaptchaFixture(base: BetterAuthOptions, port: number) {
  const events: unknown[] = [];
  const profiles = new Map<string, ReturnType<typeof betterAuth>>();
  for (const name of CAPTCHA_PROFILES) {
    const provider = name.includes("turnstile") ? "cloudflare-turnstile" : name.includes("google") ? "google-recaptcha" : name.includes("hcaptcha") ? "hcaptcha" : name.includes("captchafox") ? "captchafox" : "vercel-botid";
    const endpoints = name === "captcha-turnstile-custom" ? ["/ok"] : name.endsWith("-wildcard") ? ["/sign-in/*"] : name.endsWith("-globstar") ? ["/sign-in/**"] : name.endsWith("-empty") ? [] : undefined;
    const options: CaptchaOptions = provider === "vercel-botid" ? {
      provider, checkBotId: async () => {
        events.push({ profile: name, kind: "bot-check" });
        if (name === "captcha-botid-timeout") { await Bun.sleep(11_000); events.push({ profile:name,kind:"bot-finished" }); }
        if (name.endsWith("-throw") && !name.endsWith("validator-throw")) throw new Error("application bot check failed");
        return { isBot: name !== "captcha-botid", isVerifiedBot: name.includes("custom"), verifiedBotName: "fixture-bot" };
      },
      ...(name.includes("custom") || name.endsWith("validator-throw") ? { validateRequest: async ({ request, verification }) => {
        events.push({ profile: name, kind: "bot-validator", path: new URL(request.url).pathname, verification });
        if (name.endsWith("validator-throw")) throw new Error("application bot validator failed");
        return verification.isVerifiedBot === true && request.headers.get("x-allow-verified") === "yes";
      } } : {}),
    } : {
      provider, secretKey: name.endsWith("-no-secret") ? "" : "fixture-captcha-secret", endpoints,
      siteVerifyURLOverride: `http://localhost:${port}/__test/captcha-verify/${provider}`,
      ...(provider === "google-recaptcha" || provider === "cloudflare-turnstile" ? name.endsWith("-configured") ? { expectedAction: "login", allowedHostnames: ["app.fixture.test"] } : {} : name.endsWith("-sitekey") ? { siteKey: "fixture-site-key" } : {}),
      ...(provider === "google-recaptcha" && name.endsWith("-zero") ? { minScore: 0 } : {}),
    };
    const basePath = `/__test/profiles/${name}/api/auth`;
    const observe = (kind: string) => ({ id: `captcha-${kind}`, onRequest: async (request: Request) => { events.push({ profile: name, kind, path: new URL(request.url).pathname, method: request.method }); } });
    profiles.set(basePath, betterAuth({
      ...base, basePath, disabledPaths: name === "captcha-turnstile-disabled" ? ["/sign-in/email"] : [],
      advanced: { ipAddress: { disableIpTracking: name.endsWith("-ip-disabled"), ...(name.endsWith("-ip-custom") ? { ipAddressHeaders: ["x-fixture-ip"] } : {}) } },
      plugins: [observe("early-a"), captcha(options), observe("early-b"), { id: "captcha-endpoint-observer", hooks: { before: [{ matcher: () => true, handler: createAuthMiddleware(async ctx => { events.push({ profile: name, kind: "before", path: ctx.path }); }) }] } }],
    }));
  }
  return { profiles, async handle(request: Request) {
    const path = new URL(request.url).pathname;
    if (path === "/__test/captcha-events") return Response.json(events.splice(0));
    if (!path.startsWith("/__test/captcha-verify/")) return null;
    const rawBody = await request.text(), contentType = request.headers.get("content-type");
    const body = contentType?.includes("application/json") ? JSON.parse(rawBody) : Object.fromEntries(new URLSearchParams(rawBody));
    events.push({ kind: "provider", provider: path.split("/").at(-1), method: request.method, contentType, rawBody, body });
    const token = body.response;
    if (token === "http-failure") return Response.json({ error: "fixture service failure" }, { status: 502 });
    if (token === "invalid-json") return new Response("invalid", { headers: { "content-type": "application/json" } });
    if (token === "null") return Response.json(null);
    if (token === "blob-json") return new Response(JSON.stringify({ success:true }),{headers:{"content-type":"application/octet-stream"}});
    if (token === "empty-text") return new Response("",{headers:{"content-type":"text/plain"}});
    if (token === "timeout") await Bun.sleep(11_000);
    return Response.json({ success: token === "truthy-success" ? "false" : token !== "denied", ...(token === "missing-action" ? {} : {action: token === "wrong-action" ? "logout" : "login"}), ...(token === "missing-host" ? {} : {hostname: token === "wrong-host" ? "foreign.fixture.test" : "app.fixture.test"}), ...(token === "v2" ? {} : { score: token === "score-text" ? "0.1" : token === "score-null" ? null : token === "low-score" ? .1 : .9 }) });
  } };
}
