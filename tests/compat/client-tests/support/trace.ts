import { Cookie, CookieJar } from "tough-cookie";
import { jsonShape } from "./normalize";
import { mutateTransport } from "./assurance/wire";
export const requestWindow = Symbol("compat-request-window");
export type RequestWindow = {
  startedAt: number;
  finishedAt: number;
  inputDates: Record<string, string>;
  inputOwner?: { field: "id" | "token"; value: string };
  sessionCookie?: string;
  issuedSessionCookie?: string;
  /** Exact input of the three default verification-publication owners. */
  verificationInput?: unknown;
};

/** Complete response observations, kept in memory; reports contain paths rather than secrets. */
export type TraceEntry = {
  [requestWindow]?: RequestWindow;
  actor: string;
  method: string;
  path: string;
  requestBodyShape: unknown;
  responseStatus: number;
  responseHeaders: Record<string, string>;
  responseCookies: Record<string, unknown>;
  responseBodyShape: unknown;
  /** Complete auth and observed application creation responses; other controls retain shapes. */
  responseBody?: unknown;
  /** Complete rejection payload, compared by value: error wire text carries no runtime entropy. */
  responseErrorBody?: unknown;
};

function bodyShape(text: string) {
  if (!text) return null;
  try {
    return jsonShape(JSON.parse(text));
  } catch {
    return "string";
  }
}

/** Every 4xx/5xx body is compared literally through the identity bijection, not as a shape. */
function errorBody(status: number, text: string): unknown {
  if (status < 400) return undefined;
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
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
      expiresAt:
        cookie.maxAge === undefined && cookie.expires instanceof Date
          ? cookie.expires.toISOString()
          : null,
    };
  }
  return result;
}

function sessionReceipt(request: Headers, response: Headers) {
  const select = (values: string[]) => {
    const cookies = values
      .map((value) => Cookie.parse(value))
      .filter(
        (cookie) =>
          cookie &&
          /^(?:__Secure-)?better-auth\.session_token$/.test(cookie.key) &&
          cookie.value &&
          cookie.maxAge !== 0,
      );
    return cookies.length === 1
      ? `${cookies[0]!.key}=${cookies[0]!.value}`
      : undefined;
  };
  const sessionCookie = select((request.get("cookie") ?? "").split(";")),
    issuedSessionCookie = select(response.getSetCookie());
  return {
    ...(sessionCookie ? { sessionCookie } : {}),
    ...(issuedSessionCookie ? { issuedSessionCookie } : {}),
  };
}

/** Fetch with an isolated standards-aware cookie jar and complete redirect traces. */
export function createTracingFetch(
  baseURL: string,
  actor: string,
  traces: TraceEntry[],
  authPath = "/api/auth",
) {
  const jar = new CookieJar();
  const origin = new URL(baseURL);
  return async (
    input: string | URL | Request,
    init?: RequestInit,
  ): Promise<Response> => {
    const target = new URL(
      input instanceof Request ? input.url : input,
      baseURL,
    );
    if (
      authPath !== "/api/auth" &&
      target.origin === origin.origin &&
      target.pathname.startsWith("/api/auth/")
    ) {
      target.pathname = `${authPath}${target.pathname.slice("/api/auth".length)}`;
    }
    const supplied =
      input instanceof Request ? new Request(input, init) : undefined;
    let request = supplied
      ? new Request(target, supplied)
      : new Request(target, init);
    const redirectMode = init?.redirect ?? request.redirect;
    const requestCredentials =
      init?.credentials ??
      (input instanceof Request ? input.credentials : undefined) ??
      "same-origin";
    for (let redirects = 0; redirects <= 10; redirects++) {
      const url = new URL(request.url);
      const headers = new Headers(request.headers);
      const credentials =
        requestCredentials !== "omit" &&
        (requestCredentials === "include" || url.origin === origin.origin);
      if (credentials && !headers.has("cookie")) {
        const cookies = await jar.getCookieString(url.href, {
          sameSiteContext: url.hostname === origin.hostname ? "strict" : "none",
        });
        if (cookies) headers.set("cookie", cookies);
      }
      if (!headers.has("origin")) headers.set("origin", origin.origin);
      const outbound = new Request(request, { headers, redirect: "manual" });
      const requestText = await request.clone().text(),
        startedAt = Date.now();
      const response = await mutateTransport(outbound, await fetch(outbound));
      if (credentials) {
        for (const cookie of response.headers.getSetCookie()) {
          await jar.setCookie(cookie, url.href, { ignoreError: true });
        }
      }
      const selectedHeaders: Record<string, string> = {};
      for (const [header, value] of response.headers) {
        // Transport framing, server identity and wall-clock Date are supplied by
        // different HTTP engines. Cookies have their own structured observation.
        if (
          [
            "date",
            "server",
            "connection",
            "keep-alive",
            "content-length",
            "transfer-encoding",
            "set-cookie",
          ].includes(header)
        )
          continue;
        selectedHeaders[header] = value;
      }
      const responseText = await response.clone().text();
      const inputDates: Record<string, string> = {};
      let inputOwner: RequestWindow["inputOwner"];
      let verificationInput: unknown;
      function dates(value: unknown, path = "") {
        if (!value || typeof value !== "object") return;
        for (const [key, child] of Object.entries(value)) {
          if (
            [
              "metadata",
              "custom",
              "additionalFields",
              "applicationData",
            ].includes(key)
          )
            continue;
          const next = `${path}.${key}`;
          if (
            key.endsWith("At") &&
            typeof child === "string" &&
            /^\d{4}-\d\d-\d\dT/.test(child) &&
            Number.isFinite(Date.parse(child))
          )
            inputDates[next] = child;
          else dates(child, next);
        }
      }
      try {
        const input = JSON.parse(requestText);
        verificationInput = input;
        dates(input);
        // Only this fixture operation explicitly supplies a session deadline.
        if (
          url.pathname === "/__test/expire-session" &&
          typeof input?.token === "string"
        )
          inputOwner = { field: "token", value: input.token };
      } catch {
        /* A non-JSON body has no declared clock inputs. */
      }
      const entry: TraceEntry = {
        [requestWindow]: {
          startedAt,
          finishedAt: Date.now(),
          inputDates,
          ...(/\/(?:email-otp\/send-verification-otp|sign-in\/magic-link|one-time-token\/generate)$/.test(url.pathname)
            ? { verificationInput: requestText ? verificationInput : null } : {}),
          ...(inputOwner ? { inputOwner } : {}),
          ...sessionReceipt(headers, response.headers),
        },
        actor,
        method: request.method,
        path: `${url.pathname}${url.search}`,
        requestBodyShape: bodyShape(requestText),
        responseStatus: response.status,
        responseHeaders: selectedHeaders,
        responseCookies: responseCookies(response),
        responseBodyShape: bodyShape(responseText),
        ...(url.pathname === "/__test/api-key/create" ||
        (request.method === "GET" && url.pathname === "/__test/verification-publications") ||
        (request.method === "POST" &&
          ["/__test/organization-membership-policy/server", "/__test/organization-member-addition/server"].includes(url.pathname)) ||
        /^\/(?:__test\/profiles\/[^/]+\/)?api\/auth(?:\/|$)/.test(url.pathname)
          ? {
              responseBody: (() => {
                if (!responseText) return null;
                try {
                  return JSON.parse(responseText);
                } catch {
                  return responseText;
                }
              })(),
            }
          : {}),
      };
      const rejected = errorBody(response.status, responseText);
      if (rejected !== undefined) entry.responseErrorBody = rejected;
      traces.push(entry);
      const location = response.headers.get("location");
      if (
        ![301, 302, 303, 307, 308].includes(response.status) ||
        !location ||
        redirectMode === "manual"
      )
        return response;
      if (redirectMode === "error") throw new Error("Unexpected redirect");
      const next = new URL(location, url);
      const nextHeaders = new Headers(request.headers);
      nextHeaders.delete("cookie");
      if (next.origin !== url.origin) nextHeaders.delete("authorization");
      const becomesGet =
        response.status === 303 ||
        ([301, 302].includes(response.status) && request.method === "POST");
      if (becomesGet) nextHeaders.delete("content-type");
      request = new Request(next, {
        method: becomesGet ? "GET" : request.method,
        headers: nextHeaders,
        body:
          becomesGet || ["GET", "HEAD"].includes(request.method)
            ? null
            : await request.clone().arrayBuffer(),
        credentials: requestCredentials,
      });
    }
    throw new Error("Too many redirects");
  };
}
