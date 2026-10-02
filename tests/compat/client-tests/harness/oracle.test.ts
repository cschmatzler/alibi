import { expect, test } from "bun:test";

import { oracleFindings } from "../support/oracle";
import type { TraceEntry } from "../support/trace";

function trace(method: string, path: string, status: number, errorBody?: unknown): TraceEntry {
  return {
    actor: "primary",
    method,
    path,
    requestBodyShape: null,
    responseStatus: status,
    responseHeaders: {},
    responseCookies: {},
    responseBodyShape: null,
    ...(status >= 400 ? { responseErrorBody: errorBody } : {}),
  };
}

const signIn = trace("POST", "/api/auth/sign-in/email", 200);

test("a reference that served the scenario supports a parity claim", () => {
  expect(
    oracleFindings([
      signIn,
      trace("POST", "/api/auth/sign-in/email", 401, { code: "INVALID_EMAIL_OR_PASSWORD" }),
      trace("GET", "/__test/profiles/jwt/api/auth/token", 404, { code: "USER_NOT_FOUND" }),
      // Upstream's own 5xx responses are behavior both runtimes must reproduce.
      trace("POST", "/api/auth/update-user", 500, null),
      trace("POST", "/api/auth/update-user", 500, { code: "UNKNOWN_ERROR", message: "x" }),
      // Fixture controls outside the auth router may legitimately 404.
      trace("GET", "/__test/user-state", 404, null),
    ]),
  ).toEqual([]);
});

// A mistyped path is an empty 404 on both runtimes and compares equal.
test("an unrouted auth request fails even when both runtimes agree", () => {
  expect(oracleFindings([signIn, trace("POST", "/api/auth/sign-in/emial", 404, null)])).toEqual([
    "POST /api/auth/sign-in/emial: the reference server has no such route (empty 404)",
  ]);
  expect(
    oracleFindings([signIn, trace("GET", "/__test/profiles/jwt/api/auth/jwkz", 404, null)]),
  ).toHaveLength(1);
  expect(
    oracleFindings([signIn, trace("POST", "/api/auth/sign-in/emial", 404, null)], {
      unroutedRequests: "asserts the path is not exposed",
    }),
  ).toEqual([]);
});

// Any thrown error becomes the same body, so agreement says nothing about which.
test("a fixture that collapses a thrown error fails even when both runtimes agree", () => {
  const collapsed = trace("POST", "/__test/server-api/set-password", 500, {
    message: "Internal server error",
  });
  expect(oracleFindings([signIn, collapsed])).toEqual([
    "POST /__test/server-api/set-password: the fixture reported a thrown error as a generic 500",
  ]);
  expect(
    oracleFindings([signIn, collapsed], { collapsedFixtureErrors: "status-only contract" }),
  ).toEqual([]);
});

test("a scenario that makes no request proves nothing", () => {
  expect(oracleFindings([])).toEqual(["the scenario made no request to the reference server"]);
});
