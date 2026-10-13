import { createHash, randomUUID } from "node:crypto";
export function ssoOidcFixture() {
  let email = "sso-employee@example.test";
  const codes = new Map<string, { challenge: string; email: string }>();
  const tokens = new Map<string, string>();
  const exchanges: any[] = [];
  const server = Bun.serve({
    port: 0,
    hostname: "127.0.0.1",
    async fetch(request) {
      const url = new URL(request.url);
      if (url.pathname === "/authorize") {
        if (
          url.searchParams.get("client_id") !== "enterprise-client" ||
          url.searchParams.get("code_challenge_method") !== "S256"
        ) {
          return new Response(null, { status: 400 });
        }
        const challenge = url.searchParams.get("code_challenge");
        const redirect = url.searchParams.get("redirect_uri");
        if (!challenge || !redirect) return new Response(null, { status: 400 });
        const code = randomUUID();
        codes.set(code, { challenge, email });
        const callback = new URL(redirect);
        callback.searchParams.set("code", code);
        callback.searchParams.set("state", url.searchParams.get("state") ?? "");
        return new Response(null, { status: 302, headers: { location: callback.toString() } });
      }
      if (url.pathname === "/token") {
        const form = Object.fromEntries(new URLSearchParams(await request.text()));
        exchanges.push({ authorization: request.headers.get("authorization"), form });
        const stored = codes.get(form.code);
        codes.delete(form.code);
        if (
          request.headers.get("authorization") !==
            "Basic ZW50ZXJwcmlzZS1jbGllbnQ6c3RvcmVkLXNlY3JldA==" ||
          !stored ||
          createHash("sha256")
            .update(form.code_verifier ?? "")
            .digest("base64url") !== stored.challenge
        ) {
          return Response.json({ error: "invalid_grant" }, { status: 400 });
        }
        const token = randomUUID();
        tokens.set(token, stored.email);
        return Response.json({
          access_token: token,
          token_type: "Bearer",
          expires_in: 3600,
          scope: "openid email",
        });
      }
      if (url.pathname === "/userinfo") {
        const token = request.headers.get("authorization")?.replace(/^Bearer /, "");
        const user = token ? tokens.get(token) : undefined;
        return user
          ? Response.json({
              sub: "employee-subject",
              email: user,
              email_verified: true,
              name: "SSO employee",
            })
          : new Response(null, { status: 401 });
      }
      return new Response(null, { status: 404 });
    },
  });
  server.unref();
  return {
    base: `http://127.0.0.1:${server.port}`,
    setEmail(value: string) {
      email = value;
    },
    exchanges() {
      return [...exchanges];
    },
  };
}
