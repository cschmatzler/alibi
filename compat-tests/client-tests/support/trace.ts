import { Cookie, CookieJar } from "tough-cookie";
import { jsonShape } from "./normalize";

/** Request/response transport observations with secrets omitted. */
export type TraceEntry = {
  actor: string;
  method: string;
  path: string;
  requestBodyShape: unknown;
  responseStatus: number;
  responseHeaders: Record<string, string>;
  responseCookies: Record<string, unknown>;
  responseBodyShape: unknown;
};

function bodyShape(text: string) {
  if (!text) return null;
  try { return jsonShape(JSON.parse(text)); }
  catch { return "string"; }
}

function responseCookies(response: Response) {
  const result: Record<string, unknown> = {};
  for (const raw of response.headers.getSetCookie()) {
    const cookie = Cookie.parse(raw);
    if (!cookie) throw new Error("Unparseable Set-Cookie header");
    // Last Set-Cookie for an identical scope wins, just as it does in the jar.
    result[`${cookie.key};${cookie.domain ?? ""};${cookie.path ?? "/"}`] = {
      path: cookie.path ?? null,
      domain: cookie.domain ?? null,
      httpOnly: cookie.httpOnly,
      secure: cookie.secure,
      sameSite: cookie.sameSite ?? null,
      maxAge: cookie.maxAge ?? null,
      // RFC 6265: Max-Age takes precedence over Expires.
      expiresAt: cookie.maxAge === undefined && cookie.expires instanceof Date ? cookie.expires.toISOString() : null,
    };
  }
  return result;
}

/** Fetch with an isolated standards-aware cookie jar and complete redirect traces. */
export function createTracingFetch(baseURL: string, actor: string, traces: TraceEntry[], authPath = "/api/auth") {
  const jar = new CookieJar();
  const origin = new URL(baseURL);
  return async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const target = new URL(input instanceof Request ? input.url : input, baseURL);
    if (authPath !== "/api/auth" && target.origin === origin.origin && target.pathname.startsWith("/api/auth/")) {
      target.pathname = `${authPath}${target.pathname.slice("/api/auth".length)}`;
    }
    const supplied = input instanceof Request ? new Request(input, init) : undefined;
    let request = supplied ? new Request(target, supplied) : new Request(target, init);
    const redirectMode = init?.redirect ?? request.redirect;
    const requestCredentials = init?.credentials ?? (input instanceof Request ? input.credentials : undefined) ?? "same-origin";
    for (let redirects = 0; redirects <= 10; redirects++) {
      const url = new URL(request.url);
      const headers = new Headers(request.headers);
      const credentials = requestCredentials !== "omit"
        && (requestCredentials === "include" || url.origin === origin.origin);
      if (credentials && !headers.has("cookie")) {
        const cookies = await jar.getCookieString(url.href, {
          sameSiteContext: url.hostname === origin.hostname ? "strict" : "none",
        });
        if (cookies) headers.set("cookie", cookies);
      }
      if (!headers.has("origin")) headers.set("origin", origin.origin);
      const response = await fetch(new Request(request, { headers, redirect: "manual" }));
      if (credentials) {
        for (const cookie of response.headers.getSetCookie()) {
          await jar.setCookie(cookie, url.href, { ignoreError: true });
        }
      }
      const selectedHeaders: Record<string, string> = {};
      for (const header of ["content-type", "location"]) {
        const value = response.headers.get(header);
        if (value) selectedHeaders[header] = header === "content-type" ? value.split(";").at(0)?.trim() ?? value : value;
      }
      traces.push({
        actor,
        method: request.method,
        path: `${url.pathname}${url.search}`,
        requestBodyShape: bodyShape(await request.clone().text()),
        responseStatus: response.status,
        responseHeaders: selectedHeaders,
        responseCookies: responseCookies(response),
        responseBodyShape: bodyShape(await response.clone().text()),
      });
      const location = response.headers.get("location");
      if (![301, 302, 303, 307, 308].includes(response.status) || !location || redirectMode === "manual") return response;
      if (redirectMode === "error") throw new Error("Unexpected redirect");
      const next = new URL(location, url);
      const nextHeaders = new Headers(request.headers);
      nextHeaders.delete("cookie");
      if (next.origin !== url.origin) nextHeaders.delete("authorization");
      const becomesGet = response.status === 303 || ([301, 302].includes(response.status) && request.method === "POST");
      if (becomesGet) nextHeaders.delete("content-type");
      request = new Request(next, {
        method: becomesGet ? "GET" : request.method,
        headers: nextHeaders,
        body: becomesGet || ["GET", "HEAD"].includes(request.method) ? null : await request.clone().arrayBuffer(),
        credentials: requestCredentials,
      });
    }
    throw new Error("Too many redirects");
  };
}
