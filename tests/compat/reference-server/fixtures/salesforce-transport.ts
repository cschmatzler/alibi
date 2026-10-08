import { readFileSync } from "node:fs";
import { createServer as createHTTPServer } from "node:http";
import { createServer as createTLSServer } from "node:tls";

// Capture the real transport before other deterministic provider mappings install.
const networkFetch = globalThis.fetch.bind(globalThis);
const certificate = readFileSync(
  new URL("../../fixtures/salesforce-transport/cert.pem", import.meta.url),
  "utf8",
);
const key = readFileSync(
  new URL("../../fixtures/salesforce-transport/key.pem", import.meta.url),
  "utf8",
);
const hosts = new Set(["login.salesforce.com", "test.salesforce.com", "login.fixture.test"]);

/** A trusted local HTTPS CONNECT transport. The provider keeps its original URLs. */
export function salesforceTransport() {
  let input = { subject: "salesforce-subject", email: "salesforce@example.invalid" };
  const receipts: unknown[] = [];
  const http = createHTTPServer(async (request, response) => {
    const chunks: Buffer[] = [];
    for await (const chunk of request) chunks.push(Buffer.from(chunk));
    const body =
      request.method === "POST"
        ? Object.fromEntries(new URLSearchParams(Buffer.concat(chunks).toString()))
        : null;
    const destination = `https://${request.headers.host}${request.url}`;
    receipts.push({
      destination,
      method: request.method,
      body,
      authorization: request.headers.authorization ?? null,
      contentType: request.headers["content-type"] ?? null,
    });
    const path = new URL(destination).pathname;
    let value: unknown;
    if (path === "/services/oauth2/token") {
      const refresh = body?.grant_type === "refresh_token";
      value = {
        access_token: refresh ? "family-refreshed-access" : "family-access",
        refresh_token: refresh ? "family-rotated-refresh" : "family-refresh",
        token_type: "Bearer",
        expires_in: 3600,
        scope: "openid email profile",
      };
    } else if (path === "/services/oauth2/userinfo") {
      value = {
        user_id: input.subject,
        name: "Salesforce Family Owner",
        email: input.email,
        email_verified: true,
        photos: { picture: "https://images.example.invalid/family.png" },
      };
    } else {
      response.writeHead(404);
      response.end();
      return;
    }
    response.writeHead(200, { "content-type": "application/json", connection: "close" });
    response.end(JSON.stringify(value));
  });
  const secure = createTLSServer(
    {
      key,
      cert: readFileSync(
        new URL("../../fixtures/salesforce-transport/leaf.pem", import.meta.url),
        "utf8",
      ),
      ALPNProtocols: ["http/1.1"],
    },
    (socket) => {
      http.emit("connection", socket);
    },
  );
  secure.on("tlsClientError", () => {});
  const proxy = createHTTPServer((_request, response) => {
    response.writeHead(405);
    response.end();
  });
  proxy.on("connect", (request, socket, head) => {
    if (!hosts.has(request.url!.replace(/:443$/, ""))) {
      socket.end("HTTP/1.1 403 Forbidden\r\n\r\n");
      return;
    }
    socket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
    if (head.length) socket.unshift(head);
    secure.emit("connection", socket);
  });
  proxy.listen(0, "127.0.0.1");
  function proxyURL() {
    const address = proxy.address();
    if (!address || typeof address === "string") {
      throw new Error("Salesforce proxy is not listening");
    }
    return `http://127.0.0.1:${address.port}`;
  }
  return {
    async fetch(request: Request) {
      return networkFetch(request, { proxy: proxyURL(), tls: { ca: certificate } });
    },
    async handle(request: Request) {
      const path = new URL(request.url).pathname;
      if (path === "/__test/salesforce-transport/config") {
        return Response.json({ proxyURL: proxyURL() });
      }
      if (path === "/__test/salesforce-transport/receipts") return Response.json(receipts);
      if (path === "/__test/salesforce-transport/control" && request.method === "POST") {
        input = await request.json();
        receipts.length = 0;
        return Response.json({ status: true });
      }
      return null;
    },
  };
}
