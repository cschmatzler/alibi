import { createHash, randomUUID, sign, verify } from "node:crypto";
import { readFile as readFixtureFile } from "node:fs/promises";

import { serveFixture } from "../http.ts";
export async function ssoOidcFixture() {
  let email = "sso-employee@example.test";
  let idTokenCase = "none";
  let discoveryCase = "valid";
  let profile: Record<string, unknown> | null = null;
  const codes = new Map<
    string,
    { challenge: string; email: string; tokenCase: string; profile: Record<string, unknown> | null }
  >();
  const tokens = new Map<string, Record<string, unknown>>();
  const exchanges: any[] = [];
  const server = await serveFixture({
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
      if (url.pathname === "/authorize" || url.pathname === "/oauth/authorize") {
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
        codes.set(code, { challenge, email, tokenCase: idTokenCase, profile });
        const callback = new URL(redirect);
        callback.searchParams.set("code", code);
        callback.searchParams.set("state", url.searchParams.get("state") ?? "");
        return new Response(null, { status: 302, headers: { location: callback.toString() } });
      }
      if (
        url.pathname === "/token" ||
        url.pathname === "/token-jwt" ||
        url.pathname === "/oauth/token"
      ) {
        const form = Object.fromEntries(new URLSearchParams(await request.text()));
        exchanges.push({ authorization: request.headers.get("authorization"), form });
        const stored = codes.get(form.code);
        codes.delete(form.code);
        const authenticated =
          url.pathname === "/token-jwt"
            ? request.headers.get("authorization") === null &&
              !Object.hasOwn(form, "client_secret") &&
              form.client_id === "enterprise-client" &&
              form.client_assertion_type ===
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" &&
              (await verifyClientAssertion(form.client_assertion!, url.toString()))
            : request.headers.get("authorization") ===
                "Basic ZW50ZXJwcmlzZS1jbGllbnQ6c3RvcmVkLXNlY3JldA==" ||
              (url.pathname === "/oauth/token" &&
                form.client_id === "enterprise-client" &&
                form.client_secret === "stored-secret");
        if (
          !authenticated ||
          !stored ||
          createHash("sha256")
            .update(form.code_verifier ?? "")
            .digest("base64url") !== stored.challenge
        ) {
          return Response.json({ error: "invalid_grant" }, { status: 400 });
        }
        const token = randomUUID();
        const grantedProfile = stored.profile ?? {
          sub: "employee-subject",
          email: stored.email,
          email_verified: true,
          name: "SSO employee",
        };
        tokens.set(token, grantedProfile);
        const output: any = {
          access_token: token,
          token_type: "Bearer",
          expires_in: 3600,
          scope: "openid email",
        };
        if (stored.tokenCase !== "none") {
          output.id_token = await signedIdToken(
            url.origin,
            stored.email,
            stored.tokenCase,
            grantedProfile,
          );
        }
        return Response.json(output);
      }
      if (url.pathname === "/jwks") {
        return Response.json(
          JSON.parse(
            await readFixtureFile(
              new URL("../../../fixtures/one-tap/jwks.json", import.meta.url),
              "utf8",
            ),
          ),
        );
      }
      if (url.pathname === "/userinfo" || url.pathname === "/api/v4/user") {
        const token = request.headers.get("authorization")?.replace(/^Bearer /, "");
        const user = token ? tokens.get(token) : undefined;
        return user ? Response.json(user) : new Response(null, { status: 401 });
      }
      return new Response(null, { status: 404 });
    },
  });
  server.unref();
  return {
    base: `http://127.0.0.1:${server.port}`,
    setProfile(value: Record<string, unknown> | null) {
      profile = value;
    },
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

async function signedIdToken(
  issuer: string,
  email: string,
  tokenCase: string,
  profile: Record<string, unknown>,
) {
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
  Object.assign(claims, profile);
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
  const privateKey = await readFixtureFile(
    new URL(
      tokenCase === "signature"
        ? "../../../fixtures/one-tap/wrong-private-key.pem"
        : "../../../fixtures/one-tap/private-key.pem",
      import.meta.url,
    ),
    "utf8",
  );
  const header = Buffer.from(
    JSON.stringify({ alg: "RS256", typ: "JWT", kid: "one-tap-local-rs256" }),
  ).toString("base64url");
  const payload = Buffer.from(JSON.stringify(claims)).toString("base64url");
  const data = `${header}.${payload}`;
  return `${data}.${sign("RSA-SHA256", Buffer.from(data), privateKey).toString("base64url")}`;
}

async function verifyClientAssertion(token: string, audience: string) {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return false;
    const header = JSON.parse(Buffer.from(parts[0]!, "base64url").toString());
    const claims = JSON.parse(Buffer.from(parts[1]!, "base64url").toString());
    const now = Math.floor(Date.now() / 1000);
    if (
      header.alg !== "RS256" ||
      header.typ !== "JWT" ||
      header.kid !== "sso-key" ||
      claims.iss !== "enterprise-client" ||
      claims.sub !== "enterprise-client" ||
      claims.aud !== audience ||
      claims.iat > now + 2 ||
      claims.iat < now - 5 ||
      claims.exp !== claims.iat + 120 ||
      !/^[-0-9a-f]{36}$/.test(claims.jti)
    ) {
      return false;
    }
    const cert = await readFixtureFile(
      new URL("../../fixtures/salesforce-transport/leaf.pem", import.meta.url),
      "utf8",
    );
    return verify(
      "RSA-SHA256",
      Buffer.from(`${parts[0]}.${parts[1]}`),
      cert,
      Buffer.from(parts[2]!, "base64url"),
    );
  } catch {
    return false;
  }
}
