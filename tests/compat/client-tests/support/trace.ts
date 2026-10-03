import { createHash } from "node:crypto";

import { Cookie, CookieJar } from "tough-cookie";

import { mutateTransport } from "./assurance/wire";
import { jsonShape } from "./normalize";

export const requestWindow = Symbol("compat-request-window");

export type RequestWindow = {
  startedAt: number;
  finishedAt: number;
  inputDates: Record<string, string>;
  inputOwner?: { field: "id" | "token"; value: string };
  sessionCookie?: string;
  issuedSessionCookie?: string;
  /** Exact account JWE observed from the real issuing response. */
  issuedAccountCookie?: string;
  /** Complete multi-session Set-Cookie headers observed from the real response. */
  issuedMultiSessionCookies?: string[];
  /** Exact email and signed challenge returned by the real password sign-in. */
  signInEmail?: string;
  issuedTwoFactorCookie?: string;
  /** Actual outer-signed, user-bound trust proof returned by factor verification. */
  issuedTrustCookie?: string;
  /** Actual signed database-state cookie from the default OAuth issuing response. */
  issuedVerificationStateCookie?: string;
  /** Exact input of verification producers, provider profile and explicit expiry controls. */
  verificationInput?: unknown;
  /** Integrity of the original complete parsed observer response, separate from compared output. */
  verificationObserverDigest?: string;
  /** Original remote signer input and signed response, before any client projection. */
  remoteJwtSigning?: { input: unknown; response: unknown; digest: string };
  /** Complete callback receipt from the real signer observer. */
  remoteJwtObserver?: { body: unknown; digest: string };
  /** Original narrow physical controls; their values are not transport output. */
  controlObservation?: {
    kind:
      | "member-addition"
      | "social-provider"
      | "user-validation"
      | "managed-secrets"
      | "jwt-keyring";
    body: unknown;
    digest: string;
  };
  memberAdditionOwner?: { organizationId: string; userId: string };
  jwtKeyringInput?: { profile: string; operation: string };
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
  if (!text) {
    return null;
  }
  try {
    return jsonShape(JSON.parse(text));
  } catch {
    return "string";
  }
}

/** Every 4xx/5xx body is compared literally through the identity bijection, not as a shape. */
function errorBody(status: number, text: string): unknown {
  if (status < 400) {
    return undefined;
  }
  if (!text) {
    return null;
  }
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
    if (!cookie) {
      throw new Error("Unparseable Set-Cookie header");
    }
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
    return cookies.length === 1 ? `${cookies[0]!.key}=${cookies[0]!.value}` : undefined;
  };
  const sessionCookie = select((request.get("cookie") ?? "").split(";"));
  const issuedSessionCookie = select(response.getSetCookie());
  const account = response
    .getSetCookie()
    .map((raw) => Cookie.parse(raw))
    .filter(
      (cookie) =>
        cookie &&
        /^(?:__Secure-)?better-auth\.account_data$/.test(cookie.key) &&
        cookie.value &&
        cookie.maxAge !== 0,
    );
  const trust = response
    .getSetCookie()
    .map((raw) => Cookie.parse(raw))
    .filter(
      (cookie) =>
        cookie && /^(?:__Secure-)?better-auth\.trust_device$/.test(cookie.key) && cookie.value,
    );
  return {
    ...(sessionCookie ? { sessionCookie } : {}),
    ...(issuedSessionCookie ? { issuedSessionCookie } : {}),
    ...(account.length === 1 ? { issuedAccountCookie: account[0]!.value } : {}),
    ...(trust.length === 1 ? { issuedTrustCookie: `${trust[0]!.key}=${trust[0]!.value}` } : {}),
    issuedMultiSessionCookies: response
      .getSetCookie()
      .filter((raw) => /^(?:__Secure-)?better-auth\.session_token_multi-/.test(raw)),
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
  return async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const target = new URL(input instanceof Request ? input.url : input, baseURL);

    if (
      authPath !== "/api/auth" &&
      target.origin === origin.origin &&
      target.pathname.startsWith("/api/auth/")
    ) {
      target.pathname = `${authPath}${target.pathname.slice("/api/auth".length)}`;
    }

    const supplied = input instanceof Request ? new Request(input, init) : undefined;
    let request = supplied ? new Request(target, supplied) : new Request(target, init);
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
        if (cookies) {
          headers.set("cookie", cookies);
        }
      }

      if (!headers.has("origin")) {
        headers.set("origin", origin.origin);
      }

      const outbound = new Request(request, { headers, redirect: "manual" });
      const requestText = await request.clone().text();
      const startedAt = Date.now();
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
        ) {
          continue;
        }
        selectedHeaders[header] = value;
      }

      const responseText = await response.clone().text();
      const inputDates: Record<string, string> = {};
      let inputOwner: RequestWindow["inputOwner"];
      let verificationInput: unknown;

      function dates(value: unknown, path = "") {
        if (!value || typeof value !== "object") {
          return;
        }
        for (const [key, child] of Object.entries(value)) {
          if (["metadata", "custom", "additionalFields", "applicationData"].includes(key)) {
            continue;
          }
          const next = `${path}.${key}`;
          if (
            key.endsWith("At") &&
            typeof child === "string" &&
            /^\d{4}-\d\d-\d\dT/.test(child) &&
            Number.isFinite(Date.parse(child))
          ) {
            inputDates[next] = child;
          } else {
            dates(child, next);
          }
        }
      }

      try {
        const input = JSON.parse(requestText);
        verificationInput = input;
        dates(input);

        // Only this fixture operation explicitly supplies a session deadline.
        if (url.pathname === "/__test/expire-session" && typeof input?.token === "string") {
          inputOwner = { field: "token", value: input.token };
        }
      } catch {
        /* A non-JSON body has no declared clock inputs. */
      }

      let verificationObserverDigest: string | undefined;

      if (request.method === "GET" && url.pathname === "/__test/verification-publications") {
        try {
          verificationObserverDigest = createHash("sha256")
            .update(JSON.stringify(JSON.parse(responseText)))
            .digest("hex");
        } catch {
          /* A non-JSON response remains literal and has no publication admission. */
        }
      }

      let controlObservation: RequestWindow["controlObservation"];
      let remoteJwtSigning: RequestWindow["remoteJwtSigning"];
      let remoteJwtObserver: RequestWindow["remoteJwtObserver"];
      if (url.pathname === "/__test/jwt-remote" && response.status === 200) {
        try {
          const body: unknown = JSON.parse(responseText);
          if (request.method === "POST") {
            remoteJwtSigning = {
              input: verificationInput,
              response: body,
              digest: createHash("sha256")
                .update(JSON.stringify([verificationInput, body]))
                .digest("hex"),
            };
          } else if (request.method === "GET") {
            remoteJwtObserver = {
              body,
              digest: createHash("sha256").update(JSON.stringify(body)).digest("hex"),
            };
          }
        } catch {
          /* Invalid JSON cannot establish a signing publication. */
        }
      }

      if (
        (request.method === "POST" && url.pathname === "/__test/jwt-keyring") ||
        (request.method === "GET" &&
          [
            "/__test/organization-member-addition/state",
            "/__test/social-provider/state",
            "/__test/user-validation/state",
            "/__test/managed-secrets/state",
          ].includes(url.pathname))
      ) {
        try {
          const body: unknown = JSON.parse(responseText);
          controlObservation = {
            kind:
              url.pathname === "/__test/jwt-keyring"
                ? "jwt-keyring"
                : url.pathname.includes("organization-member-addition")
                  ? "member-addition"
                  : url.pathname.includes("managed-secrets")
                    ? "managed-secrets"
                    : url.pathname.includes("user-validation")
                      ? "user-validation"
                      : "social-provider",
            body,
            digest: createHash("sha256").update(JSON.stringify(body)).digest("hex"),
          };
        } catch {
          /* Non-JSON control responses cannot authorize dates. */
        }
      }

      const memberInput = verificationInput as
        | { body?: { organizationId?: unknown; userId?: unknown } }
        | undefined;
      const keyringInput = verificationInput as
        | { profile?: unknown; operation?: unknown }
        | undefined;
      const entry: TraceEntry = {
        [requestWindow]: {
          startedAt,
          finishedAt: Date.now(),
          inputDates,
          ...(remoteJwtSigning ? { remoteJwtSigning } : {}),
          ...(remoteJwtObserver ? { remoteJwtObserver } : {}),
          ...(controlObservation ? { controlObservation } : {}),
          ...(request.method === "POST" &&
          url.pathname === "/__test/jwt-keyring" &&
          typeof keyringInput?.profile === "string" &&
          typeof keyringInput.operation === "string"
            ? {
                jwtKeyringInput: {
                  profile: keyringInput.profile,
                  operation: keyringInput.operation,
                },
              }
            : {}),
          ...(request.method === "POST" &&
          url.pathname === "/__test/organization-member-addition/server" &&
          typeof memberInput?.body?.organizationId === "string" &&
          typeof memberInput.body.userId === "string"
            ? {
                memberAdditionOwner: {
                  organizationId: memberInput.body.organizationId,
                  userId: memberInput.body.userId,
                },
              }
            : {}),
          ...(url.pathname === "/__test/verification-state" ||
          url.pathname === "/__test/social-provider/profile" ||
          /\/(?:email-otp\/send-verification-otp|sign-in\/(?:magic-link|social)|one-time-token\/generate)$/.test(
            url.pathname,
          )
            ? { verificationInput: requestText ? verificationInput : null }
            : {}),
          ...(url.pathname.endsWith("/sign-in/social")
            ? (() => {
                const cookies = response.headers
                  .getSetCookie()
                  .map((value) => Cookie.parse(value))
                  .filter(
                    (value) =>
                      value &&
                      /^(?:__Secure-)?better-auth\.state$/.test(value.key) &&
                      value.maxAge === 300,
                  );
                return cookies.length === 1
                  ? { issuedVerificationStateCookie: `${cookies[0]!.key}=${cookies[0]!.value}` }
                  : {};
              })()
            : {}),
          ...(verificationObserverDigest ? { verificationObserverDigest } : {}),
          ...(inputOwner ? { inputOwner } : {}),
          ...(url.pathname.endsWith("/sign-in/email")
            ? (() => {
                const cookies = response.headers
                  .getSetCookie()
                  .map((value) => Cookie.parse(value))
                  .filter(
                    (cookie) =>
                      cookie && /^(?:__Secure-)?better-auth\.two_factor$/.test(cookie.key),
                  );
                return {
                  ...(typeof (verificationInput as { email?: unknown })?.email === "string"
                    ? { signInEmail: (verificationInput as { email: string }).email }
                    : {}),
                  ...(cookies.length === 1
                    ? { issuedTwoFactorCookie: `${cookies[0]!.key}=${cookies[0]!.value}` }
                    : {}),
                };
              })()
            : {}),
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
          [
            "/__test/organization-membership-policy/server",
            "/__test/organization-member-addition/server",
          ].includes(url.pathname)) ||
        /^\/(?:__test\/profiles\/[^/]+\/)?api\/auth(?:\/|$)/.test(url.pathname)
          ? {
              responseBody: (() => {
                if (!responseText) {
                  return null;
                }
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

      if (rejected !== undefined) {
        entry.responseErrorBody = rejected;
      }

      traces.push(entry);
      const location = response.headers.get("location");

      if (
        ![301, 302, 303, 307, 308].includes(response.status) ||
        !location ||
        redirectMode === "manual"
      ) {
        return response;
      }

      if (redirectMode === "error") {
        throw new Error("Unexpected redirect");
      }

      const next = new URL(location, url);
      const nextHeaders = new Headers(request.headers);
      nextHeaders.delete("cookie");

      if (next.origin !== url.origin) {
        nextHeaders.delete("authorization");
      }

      const becomesGet =
        (response.status === 303 && !["GET", "HEAD"].includes(request.method)) ||
        ([301, 302].includes(response.status) && request.method === "POST");

      if (becomesGet) {
        nextHeaders.delete("content-type");
      }

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
