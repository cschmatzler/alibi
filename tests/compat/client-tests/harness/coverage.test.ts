import { expect, test } from "bun:test";

import { collectCoverage } from "../support/coverage";
import type { TraceEntry } from "../support/trace";
import { requestWindow } from "../support/trace";

function trace(path: string, status: number): TraceEntry {
  return {
    actor: "reader",
    method: "GET",
    path,
    requestBodyShape: null,
    responseStatus: status,
    responseHeaders: {},
    responseCookies: {},
    responseBodyShape: null,
  };
}

test("numbered algorithm profiles retain success and authorization evidence", () => {
  const output = collectCoverage(
    "managed key transitions",
    [
      trace("/__test/profiles/jwt-es256/api/auth/jwks", 200),
      trace("/__test/profiles/jwt-es512/api/auth/jwks", 200),
      trace("/__test/profiles/jwt-rs256/api/auth/token", 401),
      trace("/__test/profiles/jwt-ps256/api/auth/token", 401),
    ],
    ["GET /jwks"],
  );
  expect(output).toEqual({
    "GET /jwks": { success: ["managed key transitions"], state: ["managed key transitions"] },
    "GET /token": {
      rejection: ["managed key transitions"],
      authorization: ["managed key transitions"],
    },
  });
});

test("fixture control paths cannot manufacture authentication evidence", () => {
  expect(
    collectCoverage(
      "control call",
      [
        trace("/__test/jwt", 200),
        trace("/__test/profiles/jwt-es256/jwks", 200),
        trace("/arbitrary/api/auth/jwks", 200),
      ],
      ["GET /jwks"],
    ),
  ).toEqual({});
});

test("Source default OAuth error redirects record admission denial without counting them as successful callbacks", () => {
  const baseURL = "http://fixture.local:42921";
  const scenario = "actual OAuth admission";
  const rejected = ["email_does_not_match", "unable_to_get_user_info", "state_mismatch"].map(
    (error) => ({
      ...trace(
        "/__test/profiles/social-gitlab-issuer/api/auth/callback/gitlab?code=issued&state=issued",
        302,
      ),
      responseHeaders: {
        location: `${baseURL}/__test/profiles/social-gitlab-issuer/api/auth/error?error=${error}`,
      },
    }),
  );
  expect(collectCoverage(scenario, rejected, ["GET /callback/{}"], baseURL)).toEqual({
    "GET /callback/{}": { rejection: [scenario], authorization: [scenario], state: [scenario] },
  });

  const proxyDenied = {
    ...trace("/__test/profiles/oauth-proxy-cookie/api/auth/callback/gitlab/oauth-proxy", 302),
    responseHeaders: {
      location: `${baseURL}/__test/profiles/oauth-proxy-cookie/api/auth/error?error=state_mismatch`,
    },
  };
  expect(collectCoverage(scenario, [proxyDenied], [], baseURL)).toEqual({
    "GET /callback/{}/oauth-proxy": { rejection: [scenario], authorization: [scenario] },
  });

  const issued = {
    ...trace("/__test/profiles/oauth-proxy-cookie/api/auth/link-social", 200),
    method: "POST",
    responseBody: { url: "https://provider.example/authorize?state=issued" },
    [requestWindow]: {
      startedAt: 100,
      finishedAt: 110,
      inputDates: {},
      oauthErrorCallbackURL: `${baseURL}/proxy-error?application=kept`,
    },
  };
  const configuredDenial = {
    ...proxyDenied,
    responseHeaders: { location: `${baseURL}/proxy-error?application=kept&error=state_mismatch` },
  };
  expect(
    collectCoverage(scenario, [issued, configuredDenial], [], baseURL)[
      "GET /callback/{}/oauth-proxy"
    ],
  ).toEqual({ rejection: [scenario], authorization: [scenario] });
  for (const unbound of [
    [],
    [{ ...issued, responseStatus: 403 }],
    [{ ...issued, path: "/__test/profiles/foreign/api/auth/link-social" }],
    [{ ...issued, responseBody: {} }],
    [{ ...issued, [requestWindow]: undefined }],
  ]) {
    expect(
      collectCoverage(scenario, [...unbound, configuredDenial], [], baseURL)[
        "GET /callback/{}/oauth-proxy"
      ],
    ).toEqual({ success: [scenario] });
  }

  const defaultCallback = {
    ...trace("/api/auth/callback/google", 302),
    responseHeaders: { location: "/api/auth/error?error=email_does_not_match" },
  };
  expect(collectCoverage(scenario, [defaultCallback], [], baseURL)).toEqual({
    "GET /callback/{}": { rejection: [scenario], authorization: [scenario] },
  });
  // Location alone cannot provide origin ownership without actual request context.
  expect(collectCoverage(scenario, rejected, [])).toEqual({
    "GET /callback/{}": { success: [scenario] },
  });

  const nonDenials: Partial<TraceEntry>[] = [
    { responseStatus: 200 },
    { responseStatus: 301 },
    { method: "POST" },
    { path: "/api/auth/sign-in/social" },
    { path: "/api/auth/callback/gitlab/extra" },
    { responseHeaders: {} },
    { responseHeaders: { location: "http://[broken" } },
    {
      responseHeaders: {
        location: `${baseURL}/__test/profiles/social-gitlab-issuer/api/auth/callback/gitlab?error=state_mismatch`,
      },
    },
    { responseHeaders: { location: `${baseURL}/api/auth/error?error=state_mismatch` } },
    {
      responseHeaders: {
        location:
          "http://foreign.local:42921/__test/profiles/social-gitlab-issuer/api/auth/error?error=state_mismatch",
      },
    },
    {
      responseHeaders: {
        location:
          "http://user:secret@fixture.local:42921/__test/profiles/social-gitlab-issuer/api/auth/error?error=state_mismatch",
      },
    },
    {
      responseHeaders: {
        location: `${baseURL}/__test/profiles/social-gitlab-issuer/api/auth/error?error=state_mismatch#fragment`,
      },
    },
    {
      responseHeaders: {
        location: `${baseURL}/__test/profiles/social-gitlab-issuer/api/auth/error?error=state_mismatch#`,
      },
    },
    {
      responseHeaders: {
        location: `${baseURL}/__test/profiles/social-gitlab-issuer/api/auth/error?error=state_mismatch&error=state_mismatch`,
      },
    },
    {
      responseHeaders: {
        location: `${baseURL}/__test/profiles/social-gitlab-issuer/api/auth/error?error=unknown`,
      },
    },
    { responseHeaders: { location: `${baseURL}/gitlab-done` } },
  ];

  for (const changed of nonDenials) {
    const output = collectCoverage(scenario, [{ ...rejected[0]!, ...changed }], [], baseURL);
    for (const record of Object.values(output)) {
      expect(record.authorization).toBeUndefined();
      expect(record.rejection).toBeUndefined();
      expect(record.success).toEqual([scenario]);
    }
  }

  expect(
    collectCoverage(scenario, [defaultCallback], ["state"], baseURL)["GET /callback/{}"]?.state,
  ).toBeUndefined();
});

test("real account ownership errors and request-bound reset denials retain evidence without promoting unknown failures", () => {
  const scenario = "measured denial";
  const baseURL = "http://fixture.local:42921";
  const account = {
    ...trace("/api/auth/refresh-token", 400),
    method: "POST",
    responseErrorBody: { code: "ACCOUNT_NOT_FOUND", message: "Account not found" },
  };
  const unlink = {
    ...account,
    path: "/__test/profiles/social-gitlab-issuer/api/auth/unlink-account",
  };
  const credential = {
    ...account,
    path: "/api/auth/delete-user",
    responseErrorBody: {
      code: "CREDENTIAL_ACCOUNT_NOT_FOUND",
      message: "Credential account not found",
    },
  };
  expect(collectCoverage(scenario, [account, unlink, credential], [], baseURL)).toEqual({
    "POST /delete-user": { rejection: [scenario], authorization: [scenario] },
    "POST /refresh-token": { rejection: [scenario], authorization: [scenario] },
    "POST /unlink-account": { rejection: [scenario], authorization: [scenario] },
  });

  for (const changed of [
    { responseStatus: 200 },
    { responseStatus: 500 },
    { method: "GET" },
    { path: "/api/auth/sign-up/email" },
    { path: "/__test/refresh-token" },
    { responseErrorBody: { code: "FAILED_TO_UNLINK_LAST_ACCOUNT" } },
    { responseErrorBody: { code: "APPLICATION_ERROR" } },
    { responseErrorBody: null },
  ]) {
    for (const record of Object.values(
      collectCoverage(scenario, [{ ...account, ...changed }], [], baseURL),
    )) {
      expect(record.authorization).toBeUndefined();
    }
  }

  expect(collectCoverage(scenario, [{ ...account, responseStatus: 500 }], [], baseURL)).toEqual({
    "POST /refresh-token": {},
  });

  const reset = {
    ...trace(
      "/api/auth/reset-password/invalid-reset-token?callbackURL=%2Fcallback%3Ffoo%3Dbar%26baz%3Dqux",
      302,
    ),
    responseHeaders: { location: `${baseURL}/callback?foo=bar&baz=qux&error=INVALID_TOKEN` },
  };
  expect(collectCoverage(scenario, [reset], [], baseURL)).toEqual({
    "GET /reset-password/{}": { rejection: [scenario] },
  });

  const profile = {
    ...reset,
    path: reset.path.replace("/api/auth/", "/__test/profiles/dispatch-default/api/auth/"),
  };
  expect(collectCoverage(scenario, [profile], [], baseURL)).toEqual({
    "GET /reset-password/{}": { rejection: [scenario] },
  });

  for (const changed of [
    { responseStatus: 200 },
    { responseStatus: 301 },
    { method: "POST" },
    { path: "/api/auth/reset-password/invalid-reset-token" },
    { path: reset.path + "&callbackURL=%2Fcallback" },
    {
      path: "/api/auth/reset-password/invalid-reset-token?callbackURL=%2Fcallback%3Ffoo%3Dbar%26baz%3Dqux%26error%3DINVALID_TOKEN",
    },
    {
      path: "/api/auth/reset-password/invalid-reset-token?callbackURL=http%3A%2F%2Fforeign.local%2Fcallback",
    },
    {
      responseHeaders: {
        location: `${baseURL}/callback?foo=bar&baz=qux&error=INVALID_TOKEN&error=INVALID_TOKEN`,
      },
    },
    { responseHeaders: { location: `${baseURL}/callback?foo=bar&baz=qux&error=UNKNOWN` } },
    {
      responseHeaders: { location: `${baseURL}/callback?foo=changed&baz=qux&error=INVALID_TOKEN` },
    },
    { responseHeaders: { location: `${baseURL}/unowned?foo=bar&baz=qux&error=INVALID_TOKEN` } },
    {
      responseHeaders: {
        location: "http://foreign.local/callback?foo=bar&baz=qux&error=INVALID_TOKEN",
      },
    },
    {
      responseHeaders: {
        location: `${baseURL}/callback?foo=bar&baz=qux&error=INVALID_TOKEN#fragment`,
      },
    },
  ]) {
    for (const record of Object.values(
      collectCoverage(scenario, [{ ...reset, ...changed }], [], baseURL),
    )) {
      expect(record.rejection).toBeUndefined();
    }
  }
});
