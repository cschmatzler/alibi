import { createHash, randomUUID, sign } from "node:crypto";
export function ssoOidcFixture() {
  let email = "sso-employee@example.test";
  let idTokenCase = "none";
  let discoveryCase = "valid";
  const codes = new Map<string, { challenge: string; email: string; tokenCase: string }>();
  const tokens = new Map<string, string>();
  const exchanges: any[] = [];
  const server = Bun.serve({
    port: 0,
    hostname: "127.0.0.1",
    async fetch(request) {
      const url = new URL(request.url);
      if (url.pathname === "/.well-known/openid-configuration") {
        const document: any = {
          issuer: url.origin,
          authorization_endpoint: "/authorize",
          token_endpoint: "/token",
          jwks_uri: "/jwks",
          userinfo_endpoint: "/userinfo",
          token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post"],
        };
        if (discoveryCase === "missing") delete document.jwks_uri;
        if (discoveryCase === "issuer") document.issuer = "https://wrong-issuer.example.test";
        return Response.json(document);
      }
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
        codes.set(code, { challenge, email, tokenCase: idTokenCase });
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
        const output: any = {
          access_token: token,
          token_type: "Bearer",
          expires_in: 3600,
          scope: "openid email",
        };
        if (stored.tokenCase !== "none") {
          output.id_token = await signedIdToken(url.origin, stored.email, stored.tokenCase);
        }
        return Response.json(output);
      }
      if (url.pathname === "/jwks") {
        return Response.json(
          await Bun.file(new URL("../../../fixtures/one-tap/jwks.json", import.meta.url)).json(),
        );
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
    setDiscoveryCase(value: string) {
      discoveryCase = value;
    },
    setIdTokenCase(value: string) {
      idTokenCase = value;
    },
    setEmail(value: string) {
      email = value;
      exchanges.length = 0;
    },
    exchanges() {
      return [...exchanges];
    },
  };
}

async function signedIdToken(issuer: string, email: string, tokenCase: string) {
  const now = Math.floor(Date.now() / 1000);
  const claims: any = {
    iss: issuer,
    aud: "enterprise-client",
    sub: "employee-subject",
    email,
    email_verified: true,
    name: "SSO employee",
    iat: now,
    exp: now + 3600,
  };
  if (tokenCase === "issuer") claims.iss = "https://wrong-issuer.example.test";
  if (tokenCase === "audience") claims.aud = "other-client";
  if (tokenCase === "expired") claims.exp = now - 3600;
  if (tokenCase === "authorized-party") claims.azp = "other-client";
  if (tokenCase === "multi-audience" || tokenCase === "valid-multi-audience") {
    claims.aud = ["enterprise-client", "other-client"];
    if (tokenCase === "valid-multi-audience") claims.azp = "enterprise-client";
  }
  if (tokenCase === "subject") delete claims.sub;
  if (tokenCase === "userinfo-mismatch") claims.sub = "other-subject";
  const privateKey = await Bun.file(
    new URL(
      tokenCase === "signature"
        ? "../../../fixtures/one-tap/wrong-private-key.pem"
        : "../../../fixtures/one-tap/private-key.pem",
      import.meta.url,
    ),
  ).text();
  const header = Buffer.from(
    JSON.stringify({ alg: "RS256", typ: "JWT", kid: "one-tap-local-rs256" }),
  ).toString("base64url");
  const payload = Buffer.from(JSON.stringify(claims)).toString("base64url");
  const data = `${header}.${payload}`;
  return `${data}.${sign("RSA-SHA256", Buffer.from(data), privateKey).toString("base64url")}`;
}
